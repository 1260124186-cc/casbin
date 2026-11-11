// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package casbin

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// TenantSpec declares the desired state of one tenant enforcer in a
// reconciliation manifest.
type TenantSpec struct {
	// TenantID uniquely identifies the tenant and is used as the pool key.
	TenantID string
	// PolicyGeneration is the policy generation (version) the tenant should
	// run. A value different from the active generation triggers a rebuild;
	// the same value is a no-op, so re-applying an unchanged manifest never
	// rebuilds the tenant.
	PolicyGeneration uint64
	// Filter is passed unchanged to the pool's EnforcerFactory when the
	// tenant enforcer has to be (re)built.
	Filter interface{}
	// Resident pins the tenant: reconciliation never removes a resident
	// tenant, even when it is absent from a later manifest.
	Resident bool
}

// TenantPoolState is the persisted active state of one tenant enforcer. It is
// the unit stored by a PoolStateStore.
type TenantPoolState struct {
	TenantID         string
	PolicyGeneration uint64
	// Tracked is false for entries created lazily through Get whose
	// generation has never been attested by reconciliation.
	Tracked bool
	// Resident mirrors the pool pin so a restart keeps debug tenants.
	Resident bool
}

// PoolStateStore persists the active per-tenant generation map so that a
// process restart can converge to a complete generation instead of a
// partially switched one.
//
// Implementations must make SaveTenantPoolState atomic with respect to
// crashes: a crash during a save must leave either the previous complete
// state or the new complete state, never a mix of both (for example write a
// temporary object and rename it, or use a single transaction).
type PoolStateStore interface {
	// LoadTenantPoolState returns the last successfully saved state map.
	LoadTenantPoolState() (map[string]TenantPoolState, error)
	// SaveTenantPoolState atomically replaces the stored state map.
	SaveTenantPoolState(states map[string]TenantPoolState) error
}

// InMemoryPoolStateStore is a PoolStateStore backed by a mutex-protected map.
// It is intended for tests and for single-process deployments; processes that
// need crash recovery across restarts must provide a durable implementation.
type InMemoryPoolStateStore struct {
	mu     sync.Mutex
	states map[string]TenantPoolState
}

// NewInMemoryPoolStateStore creates an empty in-memory pool state store.
func NewInMemoryPoolStateStore() *InMemoryPoolStateStore {
	return &InMemoryPoolStateStore{states: make(map[string]TenantPoolState)}
}

// LoadTenantPoolState returns a copy of the stored state map.
func (s *InMemoryPoolStateStore) LoadTenantPoolState() (map[string]TenantPoolState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]TenantPoolState, len(s.states))
	for id, state := range s.states {
		out[id] = state
	}
	return out, nil
}

// SaveTenantPoolState atomically replaces the stored state map.
func (s *InMemoryPoolStateStore) SaveTenantPoolState(states map[string]TenantPoolState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]TenantPoolState, len(states))
	for id, state := range states {
		next[id] = state
	}
	s.states = next
	return nil
}

// TenantConflict describes a tenant that could not be moved to its requested
// generation and was left serving its previous active generation.
type TenantConflict struct {
	TenantID string
	// WantedGeneration is the generation requested by the manifest.
	WantedGeneration uint64
	// ActiveGeneration is the generation still served after the failed pass.
	// It is zero when the tenant had no active enforcer.
	ActiveGeneration uint64
	// Err is the underlying failure (filtered load, role link validation or
	// pool state write).
	Err error
}

// ReconcileReport is the outcome of one ReconcileTenantEnforcerPool pass.
// Every slice is sorted by tenant id and every tenant appears in at most one
// of Added/Updated/Removed/Unchanged/Retained, while Conflicts may
// additionally reference tenants from those groups.
type ReconcileReport struct {
	// Added lists tenants that had no enforcer and were built and activated.
	Added []string
	// Updated lists tenants rebuilt because their generation changed.
	Updated []string
	// Removed lists tenants dropped because they were no longer declared and
	// were not resident.
	Removed []string
	// Unchanged lists declared tenants already serving the requested
	// generation, so no rebuild happened.
	Unchanged []string
	// Retained lists resident tenants that are absent from the manifest but
	// kept because of their pin.
	Retained []string
	// Conflicts lists tenants that kept their previous generation because a
	// build, validation or state write failed.
	Conflicts []TenantConflict
}

// HasConflicts reports whether the pass left any tenant conflict.
func (r *ReconcileReport) HasConflicts() bool {
	return len(r.Conflicts) > 0
}

// RoleLinkValidator verifies that the role manager of a freshly built tenant
// enforcer is consistent with its loaded grouping policy. A non-nil error
// fails the tenant activation and leaves the tenant on its old generation.
type RoleLinkValidator func(tenantID string, e *SyncedEnforcer) error

// ReconcileOption customizes a reconciliation pass.
type ReconcileOption func(*reconcileConfig)

type reconcileConfig struct {
	store     PoolStateStore
	validator RoleLinkValidator
}

// WithPoolStateStore persists the active generation map after every
// successful pass and restores resident pins from it at the start of a pass.
// A failed state write rolls the whole pass back to the previous state.
func WithPoolStateStore(store PoolStateStore) ReconcileOption {
	return func(cfg *reconcileConfig) {
		cfg.store = store
	}
}

// WithRoleLinkValidator overrides the default grouping-policy/role-link
// consistency check.
func WithRoleLinkValidator(validator RoleLinkValidator) ReconcileOption {
	return func(cfg *reconcileConfig) {
		cfg.validator = validator
	}
}

// Errors returned by reconciliation.
var (
	errPoolEpochChanged = errors.New("casbin: pool generation changed while reconciling tenant enforcers")
)

// PinResident marks a tenant as resident. The pin survives cache
// invalidations and reconciliations: a resident tenant is never removed just
// because it is absent from a manifest. Pinning a tenant that has no enforcer
// yet records the pin so that later entries inherit it.
func (p *EnforcerPool) PinResident(tenantID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	p.residents[tenantID] = struct{}{}
	if entry, ok := p.enforcers[tenantID]; ok {
		entry.resident = true
	}
}

// UnpinResident removes a resident pin. It does not remove the enforcer; a
// later reconciliation may still keep the tenant while the manifest declares
// it as resident.
func (p *EnforcerPool) UnpinResident(tenantID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	delete(p.residents, tenantID)
	if entry, ok := p.enforcers[tenantID]; ok {
		entry.resident = false
	}
}

// IsResident reports whether the tenant currently carries a resident pin.
func (p *EnforcerPool) IsResident(tenantID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	if _, ok := p.residents[tenantID]; ok {
		return true
	}
	if entry, ok := p.enforcers[tenantID]; ok {
		return entry.resident
	}
	return false
}

// ActiveGeneration returns the policy generation served by the tenant's
// active enforcer. The boolean is false when the tenant is absent or its
// enforcer was created lazily through Get and has never been reconciled.
func (p *EnforcerPool) ActiveGeneration(tenantID string) (uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	entry, ok := p.enforcers[tenantID]
	if !ok || !entry.tracked {
		return 0, false
	}
	return entry.generation, true
}

// ReconcileTenantEnforcerPool drives the pool toward the manifest.
//
// It builds enforcers for tenants that are new or whose PolicyGeneration
// changed, leaves tenants already at the requested generation untouched,
// removes tenants that are neither declared nor resident, and keeps resident
// tenants that are absent from the manifest.
//
// New enforcers are fully built and validated before any pool state changes,
// then the whole pass is applied in a single critical section, so pool
// lookups (Get) and tenant enforcement always observe one consistent active
// generation per tenant: either the complete old generation or the complete
// new generation, never a partially built one.
//
// A per-tenant filtered-load failure or role-link validation inconsistency
// only fails that tenant: it keeps its previous enforcer and generation and
// is reported in ReconcileReport.Conflicts. A pool state write failure rolls
// back every tenant touched by the pass. If the pool generation was changed
// concurrently (for example by InvalidateAll), the pass is aborted without
// touching the pool and the conflict is returned for a retry.
func ReconcileTenantEnforcerPool(pool *EnforcerPool, manifest []TenantSpec, opts ...ReconcileOption) (*ReconcileReport, error) {
	if pool == nil {
		return nil, errNilEnforcerPool
	}
	cfg := reconcileConfig{validator: defaultTenantRoleLinkValidator}
	for _, opt := range opts {
		opt(&cfg)
	}

	declared := make(map[string]TenantSpec, len(manifest))
	for _, spec := range manifest {
		if _, dup := declared[spec.TenantID]; dup {
			return nil, fmt.Errorf("casbin: duplicate tenant id %q in reconcile manifest", spec.TenantID)
		}
		declared[spec.TenantID] = spec
	}

	// Reconciliation passes are serialized so each pass swaps a state it
	// planned itself.
	pool.reconcileMu.Lock()
	defer pool.reconcileMu.Unlock()

	if pool.factory == nil {
		return nil, errNilEnforcerFactory
	}

	pool.mu.Lock()
	pool.initLocked()
	if cfg.store != nil {
		stored, err := cfg.store.LoadTenantPoolState()
		if err != nil {
			pool.mu.Unlock()
			return nil, fmt.Errorf("casbin: load tenant pool state: %w", err)
		}
		// Resident pins must survive a restart even before the tenant shows
		// up in a manifest.
		for id, state := range stored {
			if state.Resident {
				pool.residents[id] = struct{}{}
			}
		}
	}
	snap := pool.snapshotLocked()
	pool.mu.Unlock()

	report := &ReconcileReport{}

	// Plan: every declared tenant that is missing, untracked or behind the
	// requested generation has to be built. Tracked tenants at the same
	// generation are never rebuilt, which makes the pass idempotent.
	type planned struct {
		spec TenantSpec
		old  *enforcerPoolEntry
	}
	var toBuild []planned
	for _, spec := range manifest {
		old := snap.entries[spec.TenantID]
		if old != nil && old.tracked && old.generation == spec.PolicyGeneration {
			report.Unchanged = append(report.Unchanged, spec.TenantID)
			continue
		}
		toBuild = append(toBuild, planned{spec: spec, old: old})
	}

	// Build phase: no pool state is mutated, so concurrent lookups keep
	// serving the old generation while new enforcers are loading.
	type stagedEnforcer struct {
		spec TenantSpec
		e    *SyncedEnforcer
	}
	staged := make(map[string]*stagedEnforcer)
	conflicts := make(map[string]TenantConflict)
	for _, plan := range toBuild {
		activeGen := uint64(0)
		if plan.old != nil {
			activeGen = plan.old.generation
		}

		e, err := pool.factory(plan.spec.TenantID, plan.spec.Filter)
		if err != nil {
			conflicts[plan.spec.TenantID] = TenantConflict{
				TenantID:         plan.spec.TenantID,
				WantedGeneration: plan.spec.PolicyGeneration,
				ActiveGeneration: activeGen,
				Err:              fmt.Errorf("casbin: tenant %s filtered policy load failed: %w", plan.spec.TenantID, err),
			}
			continue
		}
		if e == nil {
			conflicts[plan.spec.TenantID] = TenantConflict{
				TenantID:         plan.spec.TenantID,
				WantedGeneration: plan.spec.PolicyGeneration,
				ActiveGeneration: activeGen,
				Err:              errNilEnforcer,
			}
			continue
		}
		if cfg.validator != nil {
			if err := cfg.validator(plan.spec.TenantID, e); err != nil {
				conflicts[plan.spec.TenantID] = TenantConflict{
					TenantID:         plan.spec.TenantID,
					WantedGeneration: plan.spec.PolicyGeneration,
					ActiveGeneration: activeGen,
					Err:              err,
				}
				continue
			}
		}
		staged[plan.spec.TenantID] = &stagedEnforcer{spec: plan.spec, e: e}
	}

	// Swap phase: one critical section moves the pool from the old
	// generation to the new generation atomically.
	pool.mu.Lock()
	if pool.generation != snap.generation {
		pool.mu.Unlock()
		for _, plan := range toBuild {
			activeGen := uint64(0)
			if plan.old != nil {
				activeGen = plan.old.generation
			}
			conflicts[plan.spec.TenantID] = TenantConflict{
				TenantID:         plan.spec.TenantID,
				WantedGeneration: plan.spec.PolicyGeneration,
				ActiveGeneration: activeGen,
				Err:              errPoolEpochChanged,
			}
		}
		report.Conflicts = conflictList(conflicts)
		sort.Strings(report.Unchanged)
		return report, errPoolEpochChanged
	}

	changed := false
	touched := make(map[string]struct{})

	for id, candidate := range staged {
		entry := &enforcerPoolEntry{
			enforcer:   candidate.e,
			generation: candidate.spec.PolicyGeneration,
			tracked:    true,
		}
		if old, ok := pool.enforcers[id]; ok {
			entry.elem = old.elem
			entry.resident = old.resident
			pool.lru.MoveToFront(old.elem)
			report.Updated = append(report.Updated, id)
		} else {
			entry.elem = pool.lru.PushFront(id)
			report.Added = append(report.Added, id)
		}
		pool.enforcers[id] = entry
		touched[id] = struct{}{}
		changed = true
	}

	// Reconcile resident flags for every declared tenant, including
	// unchanged ones and tenants whose build failed and kept their old
	// enforcer. A manifest pin or a manual pin wins; an absent pin clears a
	// manifest-driven pin from a previous pass.
	for id, spec := range declared {
		_, pinned := pool.residents[id]
		wantResident := spec.Resident || pinned
		if spec.Resident {
			pool.residents[id] = struct{}{}
			wantResident = true
		}
		entry, ok := pool.enforcers[id]
		if !ok {
			continue
		}
		if entry.resident != wantResident {
			updated := *entry
			updated.resident = wantResident
			pool.enforcers[id] = &updated
			touched[id] = struct{}{}
			changed = true
		}
	}

	// Sweep entries that the manifest no longer declares. Resident tenants,
	// including manually pinned debug tenants, stay in the pool.
	for id, entry := range pool.enforcers {
		if _, ok := declared[id]; ok {
			continue
		}
		if entry.resident {
			report.Retained = append(report.Retained, id)
			continue
		}
		if _, pinned := pool.residents[id]; pinned {
			report.Retained = append(report.Retained, id)
			continue
		}
		pool.lru.Remove(entry.elem)
		delete(pool.enforcers, id)
		report.Removed = append(report.Removed, id)
		touched[id] = struct{}{}
		changed = true
	}

	if changed {
		pool.generation++
	}

	pool.mu.Unlock()

	// Persist the new active generation map. A failed write cannot leave
	// tenants on an unpersisted generation: roll the whole pass back so all
	// touched tenants keep their previous state.
	if cfg.store != nil {
		pool.mu.Lock()
		states := pool.poolStateLocked()
		pool.mu.Unlock()
		if err := cfg.store.SaveTenantPoolState(states); err != nil {
			pool.mu.Lock()
			pool.restoreLocked(snap)
			pool.mu.Unlock()

			saveErr := fmt.Errorf("casbin: save tenant pool state failed: %w", err)
			for id := range touched {
				var activeGen, wantedGen uint64
				if old, ok := snap.entries[id]; ok {
					activeGen = old.generation
				}
				if spec, ok := declared[id]; ok {
					wantedGen = spec.PolicyGeneration
				}
				conflicts[id] = TenantConflict{
					TenantID:         id,
					WantedGeneration: wantedGen,
					ActiveGeneration: activeGen,
					Err:              saveErr,
				}
			}
			// The swap was rolled back: structural results must not claim
			// changes that no longer exist in the pool.
			report.Added = nil
			report.Updated = nil
			report.Removed = nil
			report.Retained = nil
			report.Conflicts = conflictList(conflicts)
			sortReport(report)
			return report, saveErr
		}
	}

	report.Conflicts = conflictList(conflicts)
	sortReport(report)
	return report, nil
}

// defaultTenantRoleLinkValidator checks that every grouping policy rule of a
// freshly built enforcer is resolvable as a link in its role manager. Models
// without a role_definition section have nothing to validate.
func defaultTenantRoleLinkValidator(tenantID string, e *SyncedEnforcer) error {
	grouping, ok := e.model["g"]
	if !ok || len(grouping) == 0 {
		return nil
	}
	for ptype := range grouping {
		rm := e.GetNamedRoleManager(ptype)
		if rm == nil {
			return fmt.Errorf("casbin: tenant %s role link inconsistent: no role manager for %s", tenantID, ptype)
		}
		rules, err := e.GetNamedGroupingPolicy(ptype)
		if err != nil {
			return fmt.Errorf("casbin: tenant %s role link validation failed: %w", tenantID, err)
		}
		for _, rule := range rules {
			if len(rule) < 2 {
				return fmt.Errorf("casbin: tenant %s role link inconsistent: malformed grouping rule %v", tenantID, rule)
			}
			hasLink, err := rm.HasLink(rule[0], rule[1], rule[2:]...)
			if err != nil {
				return fmt.Errorf("casbin: tenant %s role link validation failed: %w", tenantID, err)
			}
			if !hasLink {
				return fmt.Errorf("casbin: tenant %s role link inconsistent: %s rule %v has no role-manager link", tenantID, ptype, rule)
			}
		}
	}
	return nil
}

func (p *EnforcerPool) snapshotLocked() *poolSnapshot {
	snap := &poolSnapshot{
		entries:    make(map[string]*enforcerPoolEntry, len(p.enforcers)),
		residents:  make(map[string]struct{}, len(p.residents)),
		generation: p.generation,
	}
	for id, entry := range p.enforcers {
		snap.entries[id] = entry
	}
	for el := p.lru.Front(); el != nil; el = el.Next() {
		snap.order = append(snap.order, el.Value.(string))
	}
	for id := range p.residents {
		snap.residents[id] = struct{}{}
	}
	return snap
}

// restoreLocked rebuilds the exact pool state captured by snap. Published
// entry structs are never mutated in place by a swap, so sharing the entry
// pointers restores the old enforcers unchanged; only LRU elements are
// recreated for the restored list.
func (p *EnforcerPool) restoreLocked(snap *poolSnapshot) {
	p.enforcers = make(map[string]*enforcerPoolEntry, len(snap.entries))
	for id, entry := range snap.entries {
		p.enforcers[id] = entry
	}
	p.lru.Init()
	for _, id := range snap.order {
		if entry, ok := p.enforcers[id]; ok {
			entry.elem = p.lru.PushBack(id)
		}
	}
	p.residents = make(map[string]struct{}, len(snap.residents))
	for id := range snap.residents {
		p.residents[id] = struct{}{}
	}
	p.generation = snap.generation
}

func (p *EnforcerPool) poolStateLocked() map[string]TenantPoolState {
	states := make(map[string]TenantPoolState, len(p.enforcers)+len(p.residents))
	for id, entry := range p.enforcers {
		states[id] = TenantPoolState{
			TenantID:         id,
			PolicyGeneration: entry.generation,
			Tracked:          entry.tracked,
			Resident:         entry.resident,
		}
	}
	// Keep pins for tenants that have no enforcer yet.
	for id := range p.residents {
		state, ok := states[id]
		if !ok {
			state = TenantPoolState{TenantID: id}
		}
		state.Resident = true
		states[id] = state
	}
	return states
}

type poolSnapshot struct {
	entries    map[string]*enforcerPoolEntry
	order      []string
	residents  map[string]struct{}
	generation uint64
}

func conflictList(conflicts map[string]TenantConflict) []TenantConflict {
	if len(conflicts) == 0 {
		return nil
	}
	ids := make([]string, 0, len(conflicts))
	for id := range conflicts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]TenantConflict, 0, len(ids))
	for _, id := range ids {
		out = append(out, conflicts[id])
	}
	return out
}

func sortReport(report *ReconcileReport) {
	sort.Strings(report.Added)
	sort.Strings(report.Updated)
	sort.Strings(report.Removed)
	sort.Strings(report.Unchanged)
	sort.Strings(report.Retained)
}
