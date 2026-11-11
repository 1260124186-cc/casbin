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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/casbin/casbin/v3/model"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
)

// tenantFilter is the filter the test factory passes to the filtered file
// adapter.
type tenantFilter struct {
	domain     string
	generation uint64
}

// reconcileTestFactory builds one filtered rbac_with_domains enforcer per
// tenant and generation. It counts calls, can fail or block selected builds,
// and can tamper with the role manager to exercise validation.
type reconcileTestFactory struct {
	mu        sync.Mutex
	calls     map[string]int
	fail      map[string]error
	clearRM   map[string]bool
	block     map[string]chan struct{}
	seen      map[string]chan struct{}
	seenOnce  map[string]*sync.Once
	dir       string
	idCounter uint64
	content   func(tenant string, generation uint64) string
}

func newReconcileTestFactory(t *testing.T) *reconcileTestFactory {
	t.Helper()
	return &reconcileTestFactory{
		calls:    make(map[string]int),
		fail:     make(map[string]error),
		clearRM:  make(map[string]bool),
		block:    make(map[string]chan struct{}),
		seen:     make(map[string]chan struct{}),
		seenOnce: make(map[string]*sync.Once),
		dir:      t.TempDir(),
		content:  defaultTenantPolicy,
	}
}

func defaultTenantPolicy(tenant string, generation uint64) string {
	lines := []string{
		fmt.Sprintf("p, admin, %s, data1, read", tenant),
		fmt.Sprintf("p, admin, %s, data1, write", tenant),
	}
	if generation >= 2 {
		lines = append(lines, fmt.Sprintf("p, admin, %s, data9, read", tenant))
	}
	lines = append(lines, fmt.Sprintf("g, alice, admin, %s", tenant))
	return strings.Join(lines, "\n")
}

func (f *reconcileTestFactory) failKey(tenant string, generation uint64) string {
	return fmt.Sprintf("%s@%d", tenant, generation)
}

func (f *reconcileTestFactory) gate(tenant string) (seen, release chan struct{}) {
	seen = make(chan struct{})
	release = make(chan struct{})
	f.mu.Lock()
	f.block[tenant] = release
	f.seen[tenant] = seen
	f.seenOnce[tenant] = &sync.Once{}
	f.mu.Unlock()
	return seen, release
}

func (f *reconcileTestFactory) build(key string, filter interface{}) (*SyncedEnforcer, error) {
	tf, ok := filter.(tenantFilter)
	if !ok {
		return nil, fmt.Errorf("unexpected filter type %T", filter)
	}

	f.mu.Lock()
	f.calls[key]++
	if release, blocked := f.block[key]; blocked {
		if seen, ok := f.seen[key]; ok {
			f.seenOnce[key].Do(func() { close(seen) })
		}
		f.mu.Unlock()
		<-release
		f.mu.Lock()
	}
	clearRM := f.clearRM[key]
	failErr := f.fail[f.failKey(key, tf.generation)]
	content := f.content(key, tf.generation)
	f.idCounter++
	id := f.idCounter
	f.mu.Unlock()

	if failErr != nil {
		return nil, failErr
	}
	path := filepath.Join(f.dir, fmt.Sprintf("%s-gen%d-%d.csv", key, tf.generation, id))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return nil, err
	}

	m, err := model.NewModelFromFile("examples/rbac_with_domains_model.conf")
	if err != nil {
		return nil, err
	}
	e, err := NewSyncedEnforcer(m)
	if err != nil {
		return nil, err
	}
	e.SetAdapter(fileadapter.NewFilteredAdapter(path))
	if err := e.LoadFilteredPolicy(&fileadapter.Filter{
		P: []string{"", tf.domain},
		G: []string{"", "", tf.domain},
	}); err != nil {
		return nil, err
	}
	if clearRM {
		if rm := e.GetRoleManager(); rm != nil {
			if err := rm.Clear(); err != nil {
				return nil, err
			}
		}
	}
	return e, nil
}

func tenantSpec(id string, generation uint64) TenantSpec {
	return TenantSpec{
		TenantID:         id,
		PolicyGeneration: generation,
		Filter:           tenantFilter{domain: id, generation: generation},
	}
}

func residentSpec(id string, generation uint64) TenantSpec {
	spec := tenantSpec(id, generation)
	spec.Resident = true
	return spec
}

func assertStrings(t *testing.T, got, want []string, label string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", label, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v", label, got, want)
		}
	}
}

func findConflict(t *testing.T, report *ReconcileReport, tenant string) TenantConflict {
	t.Helper()
	for _, conflict := range report.Conflicts {
		if conflict.TenantID == tenant {
			return conflict
		}
	}
	t.Fatalf("conflict for tenant %q not found in %+v", tenant, report.Conflicts)
	return TenantConflict{}
}

func TestReconcileAddUpdateRemoveAndIdempotent(t *testing.T) {
	factory := newReconcileTestFactory(t)
	pool := NewEnforcerPool(factory.build, 10)

	report, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
		tenantSpec("tenant2", 1),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertStrings(t, report.Added, []string{"tenant1", "tenant2"}, "Added")
	if pool.Len() != 2 {
		t.Fatalf("Len = %d, want 2", pool.Len())
	}
	if factory.calls["tenant1"] != 1 || factory.calls["tenant2"] != 1 {
		t.Fatalf("factory calls = %+v, want one build per tenant", factory.calls)
	}
	if gen, ok := pool.ActiveGeneration("tenant1"); !ok || gen != 1 {
		t.Fatalf("tenant1 active generation = %d/%v, want 1/true", gen, ok)
	}

	oldEnforcer, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Re-applying the same manifest must not rebuild anything.
	report, err = ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
		tenantSpec("tenant2", 1),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertStrings(t, report.Unchanged, []string{"tenant1", "tenant2"}, "Unchanged")
	if factory.calls["tenant1"] != 1 || factory.calls["tenant2"] != 1 {
		t.Fatalf("factory calls = %+v, unchanged tenants were rebuilt", factory.calls)
	}
	if got, _ := pool.Get("tenant1", nil); got != oldEnforcer {
		t.Fatal("unchanged tenant enforcer was replaced")
	}

	// Move only tenant2 to generation 2.
	report, err = ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
		tenantSpec("tenant2", 2),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertStrings(t, report.Updated, []string{"tenant2"}, "Updated")
	assertStrings(t, report.Unchanged, []string{"tenant1"}, "Unchanged")
	if factory.calls["tenant2"] != 2 {
		t.Fatalf("tenant2 factory calls = %d, want 2", factory.calls["tenant2"])
	}
	if gen, ok := pool.ActiveGeneration("tenant2"); !ok || gen != 2 {
		t.Fatalf("tenant2 active generation = %d/%v, want 2/true", gen, ok)
	}
	if gen, ok := pool.ActiveGeneration("tenant1"); !ok || gen != 1 {
		t.Fatalf("tenant1 active generation = %d/%v, want 1/true", gen, ok)
	}

	newEnforcer, err := pool.Get("tenant2", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// The new generation carries an authorization-visible policy change.
	allowed, err := oldEnforcer.Enforce("alice", "tenant2", "data9", "read")
	if err != nil {
		t.Fatalf("Enforce old: %v", err)
	}
	if allowed {
		t.Fatal("generation 1 unexpectedly contains data9 policy")
	}
	allowed, err = newEnforcer.Enforce("alice", "tenant2", "data9", "read")
	if err != nil {
		t.Fatalf("Enforce new: %v", err)
	}
	if !allowed {
		t.Fatal("generation 2 data9 policy was not loaded")
	}
	allowed, err = newEnforcer.Enforce("alice", "tenant2", "data1", "read")
	if err != nil || !allowed {
		t.Fatalf("generation 2 lost existing policy, allowed=%v err=%v", allowed, err)
	}

	// Dropping tenant2 from the manifest removes it because it is not resident.
	report, err = ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertStrings(t, report.Removed, []string{"tenant2"}, "Removed")
	if pool.Len() != 1 {
		t.Fatalf("Len = %d, want 1", pool.Len())
	}
	if _, ok := pool.ActiveGeneration("tenant2"); ok {
		t.Fatal("removed tenant still reports an active generation")
	}
}

func TestReconcileResidentRetention(t *testing.T) {
	factory := newReconcileTestFactory(t)
	pool := NewEnforcerPool(factory.build, 10)

	// A manually pinned debug tenant, created lazily through Get.
	debugEnforcer, err := pool.Get("debug", tenantFilter{domain: "debug", generation: 1})
	if err != nil {
		t.Fatalf("Get debug: %v", err)
	}
	pool.PinResident("debug")
	if !pool.IsResident("debug") {
		t.Fatal("debug tenant is not resident after PinResident")
	}

	// A normal lazy tenant without a pin.
	if _, err := pool.Get("scratch", tenantFilter{domain: "scratch", generation: 1}); err != nil {
		t.Fatalf("Get scratch: %v", err)
	}

	report, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertStrings(t, report.Removed, []string{"scratch"}, "Removed")
	assertStrings(t, report.Retained, []string{"debug"}, "Retained")
	if pool.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (tenant1 + debug)", pool.Len())
	}
	if got, _ := pool.Get("debug", nil); got != debugEnforcer {
		t.Fatal("resident debug enforcer was replaced")
	}

	// A manifest-declared resident stays after it disappears from the manifest.
	report, err = ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
		residentSpec("debug2", 1),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !pool.IsResident("debug2") {
		t.Fatal("manifest resident flag was not recorded")
	}
	report, err = ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertStrings(t, report.Retained, []string{"debug", "debug2"}, "Retained")

	// Unpinning makes the tenant removable on the next reconciliation.
	pool.UnpinResident("debug2")
	if pool.IsResident("debug2") {
		t.Fatal("debug2 still resident after UnpinResident")
	}
	report, err = ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertStrings(t, report.Removed, []string{"debug2"}, "Removed")
	assertStrings(t, report.Retained, []string{"debug"}, "Retained")
}

func TestReconcileLoadFailureKeepsOldGeneration(t *testing.T) {
	factory := newReconcileTestFactory(t)
	pool := NewEnforcerPool(factory.build, 10)
	boom := errors.New("adapter boom")

	if _, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
		tenantSpec("tenant2", 1),
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	oldTenant2, _ := pool.Get("tenant2", nil)

	factory.fail[factory.failKey("tenant2", 2)] = boom

	report, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 2),
		tenantSpec("tenant2", 2),
	})
	if err != nil {
		t.Fatalf("reconcile returned pass-level error: %v", err)
	}
	if !report.HasConflicts() {
		t.Fatal("expected conflicts, got none")
	}
	assertStrings(t, report.Updated, []string{"tenant1"}, "Updated")
	conflict := findConflict(t, report, "tenant2")
	if conflict.WantedGeneration != 2 || conflict.ActiveGeneration != 1 {
		t.Fatalf("conflict generations = wanted %d active %d, want 2/1", conflict.WantedGeneration, conflict.ActiveGeneration)
	}
	if !errors.Is(conflict.Err, boom) {
		t.Fatalf("conflict error = %v, want wrapper of %v", conflict.Err, boom)
	}

	// The failed tenant keeps serving its old enforcer and generation.
	if gen, ok := pool.ActiveGeneration("tenant2"); !ok || gen != 1 {
		t.Fatalf("tenant2 generation after failure = %d/%v, want 1/true", gen, ok)
	}
	if got, _ := pool.Get("tenant2", nil); got != oldTenant2 {
		t.Fatal("failed tenant enforcer was replaced")
	}
	if gen, ok := pool.ActiveGeneration("tenant1"); !ok || gen != 2 {
		t.Fatalf("tenant1 generation = %d/%v, want 2/true", gen, ok)
	}

	// Once the adapter recovers, the next pass converges the failed tenant.
	delete(factory.fail, factory.failKey("tenant2", 2))
	report, err = ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 2),
		tenantSpec("tenant2", 2),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertStrings(t, report.Updated, []string{"tenant2"}, "Updated")
	if gen, ok := pool.ActiveGeneration("tenant2"); !ok || gen != 2 {
		t.Fatalf("tenant2 generation = %d/%v, want 2/true", gen, ok)
	}
}

func TestReconcileRoleLinkValidation(t *testing.T) {
	t.Run("default validator passes", func(t *testing.T) {
		factory := newReconcileTestFactory(t)
		pool := NewEnforcerPool(factory.build, 10)
		report, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
			tenantSpec("tenant1", 1),
		})
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if report.HasConflicts() {
			t.Fatalf("unexpected conflicts: %+v", report.Conflicts)
		}
	})

	t.Run("default validator detects missing links", func(t *testing.T) {
		factory := newReconcileTestFactory(t)
		factory.clearRM["tenant1"] = true
		pool := NewEnforcerPool(factory.build, 10)

		report, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
			tenantSpec("tenant1", 1),
		})
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if !report.HasConflicts() || pool.Len() != 0 {
			t.Fatalf("expected conflict and empty pool, got conflicts=%v len=%d", report.Conflicts, pool.Len())
		}
		conflict := findConflict(t, report, "tenant1")
		if !strings.Contains(conflict.Err.Error(), "role link inconsistent") {
			t.Fatalf("conflict error = %q, want role link inconsistency", conflict.Err.Error())
		}
	})

	t.Run("custom validator failure keeps old generation", func(t *testing.T) {
		factory := newReconcileTestFactory(t)
		pool := NewEnforcerPool(factory.build, 10)
		validationErr := errors.New("link check boom")

		if _, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
			tenantSpec("tenant1", 1),
		}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		oldEnforcer, _ := pool.Get("tenant1", nil)

		report, err := ReconcileTenantEnforcerPool(pool,
			[]TenantSpec{tenantSpec("tenant1", 2)},
			WithRoleLinkValidator(func(tenantID string, e *SyncedEnforcer) error {
				if tenantID == "tenant1" {
					return validationErr
				}
				return nil
			}),
		)
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		conflict := findConflict(t, report, "tenant1")
		if !errors.Is(conflict.Err, validationErr) {
			t.Fatalf("conflict error = %v, want %v", conflict.Err, validationErr)
		}
		if gen, ok := pool.ActiveGeneration("tenant1"); !ok || gen != 1 {
			t.Fatalf("generation = %d/%v, want 1/true", gen, ok)
		}
		if got, _ := pool.Get("tenant1", nil); got != oldEnforcer {
			t.Fatal("enforcer replaced despite validation failure")
		}
	})

	t.Run("non-RBAC model skips validation", func(t *testing.T) {
		pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
			return NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
		}, 10)
		report, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
			tenantSpec("tenant1", 1),
		})
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if report.HasConflicts() {
			t.Fatalf("unexpected conflicts for non-RBAC model: %+v", report.Conflicts)
		}
	})
}

type failingPoolStateStore struct {
	mu      sync.Mutex
	saves   int
	err     error
	last    map[string]TenantPoolState
	loadErr error
}

func (s *failingPoolStateStore) LoadTenantPoolState() (map[string]TenantPoolState, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return map[string]TenantPoolState{}, nil
}

func (s *failingPoolStateStore) SaveTenantPoolState(states map[string]TenantPoolState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	if s.err != nil {
		return s.err
	}
	s.last = make(map[string]TenantPoolState, len(states))
	for id, state := range states {
		s.last[id] = state
	}
	return nil
}

func TestReconcileStateStoreRollback(t *testing.T) {
	factory := newReconcileTestFactory(t)
	pool := NewEnforcerPool(factory.build, 10)
	store := &failingPoolStateStore{err: errors.New("disk full")}

	report, err := ReconcileTenantEnforcerPool(pool,
		[]TenantSpec{
			tenantSpec("tenant1", 1),
			tenantSpec("tenant2", 1),
		},
		WithPoolStateStore(store),
	)
	if err == nil {
		t.Fatal("expected state write error, got nil")
	}
	if !strings.Contains(err.Error(), "save tenant pool state failed") {
		t.Fatalf("error = %v, want state write failure", err)
	}
	if pool.Len() != 0 {
		t.Fatalf("Len = %d, want 0 after rollback", pool.Len())
	}
	if len(report.Added) != 0 || len(report.Updated) != 0 || len(report.Removed) != 0 {
		t.Fatalf("rollback report still claims structural changes: %+v", report)
	}
	if len(report.Conflicts) != 2 {
		t.Fatalf("conflicts = %d, want 2 (all touched tenants)", len(report.Conflicts))
	}
	for _, conflict := range report.Conflicts {
		if conflict.ActiveGeneration != 0 || conflict.WantedGeneration != 1 {
			t.Fatalf("conflict %+v has unexpected generations", conflict)
		}
	}

	// A later pass with a healthy store succeeds and persists the full map.
	healthy := NewInMemoryPoolStateStore()
	report, err = ReconcileTenantEnforcerPool(pool,
		[]TenantSpec{
			residentSpec("debug", 1),
			tenantSpec("tenant1", 1),
			tenantSpec("tenant2", 1),
		},
		WithPoolStateStore(healthy),
	)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if report.HasConflicts() {
		t.Fatalf("unexpected conflicts: %+v", report.Conflicts)
	}
	stored, err := healthy.LoadTenantPoolState()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(stored) != 3 {
		t.Fatalf("stored tenants = %d, want 3", len(stored))
	}
	if !stored["debug"].Resident || !stored["tenant1"].Tracked || stored["tenant2"].PolicyGeneration != 1 {
		t.Fatalf("stored state mismatch: %+v", stored)
	}
}

func TestReconcileRestartConvergesToCompleteGeneration(t *testing.T) {
	factory := newReconcileTestFactory(t)
	store := NewInMemoryPoolStateStore()

	// First process: run generation 1, then generation 2.
	pool1 := NewEnforcerPool(factory.build, 10)
	if _, err := ReconcileTenantEnforcerPool(pool1,
		[]TenantSpec{
			residentSpec("debug", 1),
			tenantSpec("tenant1", 1),
			tenantSpec("tenant2", 1),
		},
		WithPoolStateStore(store),
	); err != nil {
		t.Fatalf("reconcile gen1: %v", err)
	}
	if _, err := ReconcileTenantEnforcerPool(pool1,
		[]TenantSpec{
			residentSpec("debug", 1),
			tenantSpec("tenant1", 2),
			tenantSpec("tenant2", 2),
		},
		WithPoolStateStore(store),
	); err != nil {
		t.Fatalf("reconcile gen2: %v", err)
	}

	// Simulate a process restart: brand new pool, same durable state.
	pool2 := NewEnforcerPool(factory.build, 10)
	report, err := ReconcileTenantEnforcerPool(pool2,
		[]TenantSpec{
			tenantSpec("tenant1", 2),
			tenantSpec("tenant2", 2),
		},
		WithPoolStateStore(store),
	)
	if err != nil {
		t.Fatalf("restart reconcile: %v", err)
	}
	if report.HasConflicts() {
		t.Fatalf("unexpected conflicts after restart: %+v", report.Conflicts)
	}
	// Every declared tenant converges to the complete new generation.
	for _, id := range []string{"tenant1", "tenant2"} {
		if gen, ok := pool2.ActiveGeneration(id); !ok || gen != 2 {
			t.Fatalf("%s generation after restart = %d/%v, want 2/true", id, gen, ok)
		}
	}
	// The resident pin for the manifest-less debug tenant survived restart.
	if !pool2.IsResident("debug") {
		t.Fatal("resident pin for debug tenant lost across restart")
	}
	if _, err := pool2.Get("debug", tenantFilter{domain: "debug", generation: 1}); err != nil {
		t.Fatalf("Get debug after restart: %v", err)
	}
	if !pool2.IsResident("debug") {
		t.Fatal("lazily rebuilt debug tenant did not inherit its resident pin")
	}

	// A store stuck at the old generation plus an old manifest converges to
	// the complete old generation instead of a mixed one.
	oldStore := NewInMemoryPoolStateStore()
	pool3 := NewEnforcerPool(factory.build, 10)
	if _, err := ReconcileTenantEnforcerPool(pool3,
		[]TenantSpec{
			tenantSpec("tenant1", 1),
			tenantSpec("tenant2", 1),
		},
		WithPoolStateStore(oldStore),
	); err != nil {
		t.Fatalf("old-generation reconcile: %v", err)
	}
	pool4 := NewEnforcerPool(factory.build, 10)
	if _, err := ReconcileTenantEnforcerPool(pool4,
		[]TenantSpec{
			tenantSpec("tenant1", 1),
			tenantSpec("tenant2", 1),
		},
		WithPoolStateStore(oldStore),
	); err != nil {
		t.Fatalf("restart on old generation: %v", err)
	}
	for _, id := range []string{"tenant1", "tenant2"} {
		if gen, ok := pool4.ActiveGeneration(id); !ok || gen != 1 {
			t.Fatalf("%s generation = %d/%v, want complete old generation 1", id, gen, ok)
		}
	}
}

func TestReconcileConcurrentLookupsSeeOneActiveGeneration(t *testing.T) {
	factory := newReconcileTestFactory(t)
	pool := NewEnforcerPool(factory.build, 10)

	if _, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
		tenantSpec("tenant2", 1),
	}); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	steadyEnforcer, _ := pool.Get("tenant1", nil)

	seen, release := factory.gate("tenant2")
	done := make(chan struct{})
	var report *ReconcileReport
	var reconcileErr error
	go func() {
		report, reconcileErr = ReconcileTenantEnforcerPool(pool, []TenantSpec{
			tenantSpec("tenant1", 1),
			tenantSpec("tenant2", 2),
		})
		close(done)
	}()

	<-seen
	// While the new tenant2 instance is still loading, lookups keep serving
	// the complete old generation and no partial entry is visible.
	if pool.Len() != 2 {
		t.Fatalf("Len during build = %d, want 2", pool.Len())
	}
	if gen, ok := pool.ActiveGeneration("tenant2"); !ok || gen != 1 {
		t.Fatalf("tenant2 generation during build = %d/%v, want 1/true", gen, ok)
	}
	if got, _ := pool.Get("tenant1", nil); got != steadyEnforcer {
		t.Fatal("unrelated tenant enforcer changed during another tenant's build")
	}
	close(release)
	<-done
	if reconcileErr != nil {
		t.Fatalf("reconcile: %v", reconcileErr)
	}
	assertStrings(t, report.Updated, []string{"tenant2"}, "Updated")

	// After the swap, lookups and enforcement observe the new generation
	// through the same entry that ActiveGeneration reports.
	if gen, ok := pool.ActiveGeneration("tenant2"); !ok || gen != 2 {
		t.Fatalf("tenant2 generation after swap = %d/%v, want 2/true", gen, ok)
	}
	newEnforcer, err := pool.Get("tenant2", nil)
	if err != nil {
		t.Fatalf("Get after swap: %v", err)
	}
	allowed, err := newEnforcer.Enforce("alice", "tenant2", "data9", "read")
	if err != nil || !allowed {
		t.Fatalf("new generation not enforceable, allowed=%v err=%v", allowed, err)
	}
}

func TestReconcileInvalidateDuringBuildAborts(t *testing.T) {
	factory := newReconcileTestFactory(t)
	pool := NewEnforcerPool(factory.build, 10)

	if _, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
		tenantSpec("tenant2", 1),
	}); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}

	seen, release := factory.gate("tenant2")
	done := make(chan struct{})
	var err error
	go func() {
		_, err = ReconcileTenantEnforcerPool(pool, []TenantSpec{
			tenantSpec("tenant1", 1),
			tenantSpec("tenant2", 2),
		})
		close(done)
	}()

	<-seen
	pool.InvalidateAll()
	close(release)
	<-done

	if !errors.Is(err, errPoolEpochChanged) {
		t.Fatalf("reconcile error = %v, want %v", err, errPoolEpochChanged)
	}

	// Retrying after the concurrent invalidation converges cleanly.
	report, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
		tenantSpec("tenant2", 2),
	})
	if err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}
	if report.HasConflicts() {
		t.Fatalf("unexpected conflicts on retry: %+v", report.Conflicts)
	}
	if gen, ok := pool.ActiveGeneration("tenant2"); !ok || gen != 2 {
		t.Fatalf("tenant2 generation = %d/%v, want 2/true", gen, ok)
	}
}

func TestReconcileUntrackedEntryIsAdoptedOnce(t *testing.T) {
	factory := newReconcileTestFactory(t)
	pool := NewEnforcerPool(factory.build, 10)

	if _, err := pool.Get("tenant1", tenantFilter{domain: "tenant1", generation: 1}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, ok := pool.ActiveGeneration("tenant1"); ok {
		t.Fatal("lazy entry should not report an attested generation")
	}

	// The first pass cannot attest the lazy entry's generation, so it builds
	// a tracked replacement for the existing entry.
	report, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertStrings(t, report.Updated, []string{"tenant1"}, "Updated")
	if gen, ok := pool.ActiveGeneration("tenant1"); !ok || gen != 1 {
		t.Fatalf("generation = %d/%v, want 1/true", gen, ok)
	}

	// The second pass is a no-op for the same generation.
	report, err = ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	assertStrings(t, report.Unchanged, []string{"tenant1"}, "Unchanged")
	if factory.calls["tenant1"] != 2 {
		t.Fatalf("factory calls = %d, want 2 (lazy + reconciled)", factory.calls["tenant1"])
	}
}

func TestReconcileLRUKeepsResidents(t *testing.T) {
	factory := newReconcileTestFactory(t)
	pool := NewEnforcerPool(factory.build, 2)

	if _, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		residentSpec("resident1", 1),
		tenantSpec("normal1", 1),
	}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, err := pool.Get("normal2", tenantFilter{domain: "normal2", generation: 1}); err != nil {
		t.Fatalf("Get normal2: %v", err)
	}
	if !pool.IsResident("resident1") {
		t.Fatal("resident pin missing")
	}
	if _, ok := pool.enforcers["resident1"]; !ok {
		t.Fatal("resident tenant was LRU-evicted")
	}
	if _, ok := pool.enforcers["normal2"]; !ok {
		t.Fatal("new normal tenant was not cached")
	}
}

func TestReconcileInvalidInputs(t *testing.T) {
	if _, err := ReconcileTenantEnforcerPool(nil, nil); !errors.Is(err, errNilEnforcerPool) {
		t.Fatalf("nil pool error = %v, want %v", err, errNilEnforcerPool)
	}

	pool := NewEnforcerPool(nil, 10)
	if _, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{tenantSpec("tenant1", 1)}); !errors.Is(err, errNilEnforcerFactory) {
		t.Fatalf("nil factory error = %v, want %v", err, errNilEnforcerFactory)
	}

	factory := newReconcileTestFactory(t)
	pool = NewEnforcerPool(factory.build, 10)
	_, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
		tenantSpec("tenant1", 2),
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate tenant id") {
		t.Fatalf("duplicate manifest error = %v, want duplicate tenant id", err)
	}
}

func TestReconcileConcurrentReconcileAndGet(t *testing.T) {
	factory := newReconcileTestFactory(t)
	pool := NewEnforcerPool(factory.build, 100)

	if _, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
		tenantSpec("tenant1", 1),
		tenantSpec("tenant2", 1),
	}); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}

	const rounds = 20
	var wg sync.WaitGroup
	for round := 1; round <= rounds; round++ {
		gen := uint64(round + 1)
		wg.Add(2)
		go func(gen uint64) {
			defer wg.Done()
			_, err := ReconcileTenantEnforcerPool(pool, []TenantSpec{
				tenantSpec("tenant1", gen),
				tenantSpec("tenant2", gen),
			})
			if err != nil && !errors.Is(err, errPoolEpochChanged) {
				t.Errorf("reconcile: %v", err)
			}
		}(gen)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				e, err := pool.Get("tenant1", nil)
				if err != nil {
					t.Errorf("Get: %v", err)
					return
				}
				ok, err := e.Enforce("alice", "tenant1", "data1", "read")
				if err != nil || !ok {
					t.Errorf("Enforce through active enforcer failed: ok=%v err=%v", ok, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	// The serialized passes must leave both tenants at one consistent generation.
	gen1, ok1 := pool.ActiveGeneration("tenant1")
	gen2, ok2 := pool.ActiveGeneration("tenant2")
	if !ok1 || !ok2 || gen1 != gen2 {
		t.Fatalf("final generations tenant1=%d/%v tenant2=%d/%v, want equal tracked generations", gen1, ok1, gen2, ok2)
	}
}

func TestReconcileStoreLoadFailure(t *testing.T) {
	factory := newReconcileTestFactory(t)
	pool := NewEnforcerPool(factory.build, 10)
	loadErr := errors.New("cannot open state")
	store := &failingPoolStateStore{loadErr: loadErr}

	_, err := ReconcileTenantEnforcerPool(pool,
		[]TenantSpec{tenantSpec("tenant1", 1)},
		WithPoolStateStore(store),
	)
	if !errors.Is(err, loadErr) {
		t.Fatalf("error = %v, want %v", err, loadErr)
	}
	if pool.Len() != 0 {
		t.Fatalf("Len = %d, want 0 when state cannot be loaded", pool.Len())
	}
}

// Ensure the report helper stays meaningful.
func TestReconcileReportHasConflicts(t *testing.T) {
	report := &ReconcileReport{}
	if report.HasConflicts() {
		t.Fatal("empty report should have no conflicts")
	}
	report.Conflicts = append(report.Conflicts, TenantConflict{TenantID: "x"})
	if !report.HasConflicts() {
		t.Fatal("report with conflicts should report true")
	}
}
