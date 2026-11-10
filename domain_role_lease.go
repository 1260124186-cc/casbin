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
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/casbin/casbin/v3/persist"
)

const (
	// domainRoleLeaseMarker tags grouping rules that are issued and maintained
	// by a lease source. It is stored at a fixed position behind the regular
	// (user, role, domain) role-definition tuple, so it is ignored by the role
	// manager while keeping source ownership discoverable in the policy itself.
	domainRoleLeaseMarker = "casbin.io/domain-role-lease/v1"

	// domainRoleLeaseRuleSize is the number of fields of a well-formed lease rule:
	// user, role, domain, marker, source, grant ID, expiration time.
	domainRoleLeaseRuleSize = 7

	leaseUserIndex      = 0
	leaseRoleIndex      = 1
	leaseDomainIndex    = 2
	leaseMarkerIndex    = 3
	leaseSourceIndex    = 4
	leaseGrantIDIndex   = 5
	leaseExpiresAtIndex = 6
)

// DomainRoleLease is a domain-scoped role grant periodically delivered by an
// upstream lease system. The same user may hold different leases in different
// domains; every lease carries an authorization number and an expiration time.
type DomainRoleLease struct {
	// User is the subject the role is granted to.
	User string
	// Role is the role granted inside the domain.
	Role string
	// Domain is the domain in which the role assignment is valid.
	Domain string
	// GrantID is the authorization number assigned by the upstream lease system.
	GrantID string
	// ExpiresAt is the expiration time of the grant.
	ExpiresAt time.Time
}

// LeaseConflictKind classifies the reason a reconcile run refused to apply.
type LeaseConflictKind string

const (
	// LeaseConflictDuplicateLease means two input leases contend for the same
	// (user, role, domain) slot while carrying different grant content.
	LeaseConflictDuplicateLease LeaseConflictKind = "duplicate_lease"
	// LeaseConflictCorruptedRecord means an input lease or a stored lease rule
	// cannot be parsed into a valid lease record.
	LeaseConflictCorruptedRecord LeaseConflictKind = "corrupted_record"
)

// LeaseConflict describes a single conflict that made a reconcile run a no-op.
type LeaseConflict struct {
	// Kind classifies the conflict.
	Kind LeaseConflictKind
	// Message describes the conflict in human-readable form.
	Message string
	// Lease points at the offending input lease, when the conflict comes from
	// the delivered lease list.
	Lease *DomainRoleLease
	// Rule holds the offending stored grouping rule, when the conflict comes
	// from the persisted policy.
	Rule []string
}

// LeaseConflictError aggregates every conflict found in one reconcile run.
// A reconcile run returns this error without touching any relationship when
// the delivered list or the stored lease rules are inconsistent.
type LeaseConflictError struct {
	Conflicts []LeaseConflict
}

// Error implements the error interface.
func (e *LeaseConflictError) Error() string {
	messages := make([]string, 0, len(e.Conflicts))
	for _, conflict := range e.Conflicts {
		messages = append(messages, string(conflict.Kind)+": "+conflict.Message)
	}
	return fmt.Sprintf("domain role lease reconcile aborted with %d conflict(s): %s",
		len(e.Conflicts), strings.Join(messages, "; "))
}

// Is lets errors.Is match ErrLeaseConflict for every aggregated conflict.
func (e *LeaseConflictError) Is(target error) bool {
	return target == ErrLeaseConflict
}

// LeasePersistenceError wraps the adapter error that aborted a reconcile run.
// When the adapter supports transactions, the storage transaction has already
// been rolled back and no relationship has changed.
type LeasePersistenceError struct {
	// Op is the persistence operation that failed (add or remove).
	Op string
	// Err is the underlying adapter error.
	Err error
}

// Error implements the error interface.
func (e *LeasePersistenceError) Error() string {
	return fmt.Sprintf("domain role lease reconcile failed while persisting %s operation: %v", e.Op, e.Err)
}

// Unwrap exposes the underlying adapter error to errors.Is and errors.As.
func (e *LeasePersistenceError) Unwrap() error {
	return e.Err
}

// Is lets errors.Is match ErrLeasePersistence for every persistence failure.
func (e *LeasePersistenceError) Is(target error) bool {
	return target == ErrLeasePersistence
}

var (
	// ErrLeaseConflict is the sentinel for reconcile runs refused because of
	// duplicate or corrupted lease records.
	ErrLeaseConflict = errors.New("domain role lease conflict")
	// ErrLeasePersistence is the sentinel for reconcile runs aborted by an
	// adapter persistence failure.
	ErrLeasePersistence = errors.New("domain role lease persistence failure")
)

// ReconcileDomainRoleLeasesResult reports the outcome of a reconcile run.
type ReconcileDomainRoleLeasesResult struct {
	// Added are leases that had no source-owned relationship before.
	Added []DomainRoleLease
	// Updated are leases whose grant ID or expiration time changed.
	Updated []DomainRoleLease
	// Removed are source-owned relationships that were revoked or expired.
	Removed []DomainRoleLease
	// Unchanged are leases that already matched the stored relationship.
	Unchanged []DomainRoleLease
	// Expired are input leases whose expiration time had already passed; they
	// never produce a relationship.
	Expired []DomainRoleLease
}

// domainRoleLeaseKey identifies the role slot a lease occupies inside a domain.
type domainRoleLeaseKey struct {
	user   string
	role   string
	domain string
}

// storedDomainRoleLease pairs a parsed lease with the exact grouping rule that
// stores it, so updates and removals can target the original rule verbatim.
type storedDomainRoleLease struct {
	lease DomainRoleLease
	rule  []string
}

// ReconcileDomainRoleLeases aligns the domain role relationships issued by
// source with the delivered lease list.
//
// Only grouping rules tagged for this source are reconciled: new leases are
// added, changed grant content is updated, and revoked or expired leases are
// deleted. Manual domain members, role inheritance rules and rules owned by
// other sources are never touched.
//
// The operation is state based: it diffs the delivered list against the
// currently stored source-owned rules, so applying the same list repeatedly
// rewrites nothing, and a restart after an interrupted run only applies the
// remaining differences.
//
// If the input list contains contending leases or corrupted records, or if a
// persistence operation fails, the run returns an error without changing any
// relationship and describes every conflict it found.
func (e *Enforcer) ReconcileDomainRoleLeases(source string, leases []DomainRoleLease) (*ReconcileDomainRoleLeasesResult, error) {
	if strings.TrimSpace(source) == "" {
		return nil, errors.New("source must not be empty")
	}
	if _, err := e.model.GetAssertion("g", "g"); err != nil {
		return nil, err
	}

	result := newReconcileDomainRoleLeasesResult()
	desired, inputConflicts := collectDesiredDomainRoleLeases(leases, time.Now(), result)
	current, storedConflicts, err := e.collectStoredDomainRoleLeases(source)
	if err != nil {
		return nil, err
	}
	conflicts := append(inputConflicts, storedConflicts...)

	// Refuse to write anything until every conflict has been reported.
	if len(conflicts) > 0 {
		return nil, &LeaseConflictError{Conflicts: conflicts}
	}

	addRules, removeRules := diffDomainRoleLeases(source, desired, current, result)
	sortLeases(result.Added)
	sortLeases(result.Updated)
	sortLeases(result.Removed)
	sortLeases(result.Unchanged)
	sortLeases(result.Expired)
	sortRules(addRules)
	sortRules(removeRules)

	// Nothing to do: do not touch the adapter or the model at all.
	if len(addRules) == 0 && len(removeRules) == 0 {
		return result, nil
	}

	// Persist every change before mutating the in-memory model. A transactional
	// adapter rolls the whole batch back on failure; other adapters leave the
	// model untouched and the next run converges.
	if err := e.persistDomainRoleLeaseRules(addRules, removeRules); err != nil {
		return nil, err
	}

	// Apply the same diff to the model and rebuild the role links.
	if err := e.applyDomainRoleLeaseRulesToModel(addRules, removeRules); err != nil {
		return nil, err
	}

	if err := e.notifyDomainRoleLeaseWatcher(addRules, removeRules); err != nil {
		return nil, err
	}

	return result, nil
}

// newReconcileDomainRoleLeasesResult creates a result with non-nil slices so
// callers never have to distinguish nil from empty.
func newReconcileDomainRoleLeasesResult() *ReconcileDomainRoleLeasesResult {
	return &ReconcileDomainRoleLeasesResult{
		Added:     []DomainRoleLease{},
		Updated:   []DomainRoleLease{},
		Removed:   []DomainRoleLease{},
		Unchanged: []DomainRoleLease{},
		Expired:   []DomainRoleLease{},
	}
}

// collectDesiredDomainRoleLeases validates the delivered leases and indexes
// the still-active ones by role slot. Expired leases are reported instead of
// indexed; malformed records and contending grants become conflicts.
func collectDesiredDomainRoleLeases(leases []DomainRoleLease, now time.Time,
	result *ReconcileDomainRoleLeasesResult) (map[domainRoleLeaseKey]DomainRoleLease, []LeaseConflict) {
	desired := make(map[domainRoleLeaseKey]DomainRoleLease, len(leases))
	conflicts := []LeaseConflict{}
	for i := range leases {
		lease := leases[i]
		if err := validateDomainRoleLease(lease); err != nil {
			conflicts = append(conflicts, LeaseConflict{
				Kind:    LeaseConflictCorruptedRecord,
				Message: fmt.Sprintf("invalid delivered lease at index %d: %v", i, err),
				Lease:   &leases[i],
			})
			continue
		}
		if !lease.ExpiresAt.After(now) {
			result.Expired = append(result.Expired, lease)
			continue
		}
		key := domainRoleLeaseKey{user: lease.User, role: lease.Role, domain: lease.Domain}
		if existing, ok := desired[key]; ok {
			// Exact duplicates collapse onto one slot; only incompatible
			// grants for the same slot are a contention conflict.
			if !sameLeaseContent(existing, lease) {
				conflicts = append(conflicts, LeaseConflict{
					Kind: LeaseConflictDuplicateLease,
					Message: fmt.Sprintf(
						"leases %q and %q both grant role %q to user %q in domain %q",
						existing.GrantID, lease.GrantID, lease.Role, lease.User, lease.Domain),
					Lease: &leases[i],
				})
			}
			continue
		}
		desired[key] = lease
	}
	return desired, conflicts
}

// collectStoredDomainRoleLeases indexes the source-owned grouping rules
// currently held by the model. Manual memberships, role inheritance and
// other sources' rules are skipped; malformed or ambiguous stored records
// are returned as conflicts.
func (e *Enforcer) collectStoredDomainRoleLeases(source string) (
	map[domainRoleLeaseKey]storedDomainRoleLease, []LeaseConflict, error) {
	current := make(map[domainRoleLeaseKey]storedDomainRoleLease)
	conflicts := []LeaseConflict{}
	groupingRules, err := e.GetNamedGroupingPolicy("g")
	if err != nil {
		return nil, nil, err
	}
	for _, rule := range groupingRules {
		if !isLeaseMarkerRule(rule) {
			continue
		}
		if len(rule) <= leaseSourceIndex || rule[leaseSourceIndex] != source {
			continue
		}
		stored, parseErr := parseStoredDomainRoleLease(rule)
		if parseErr != nil {
			conflicts = append(conflicts, LeaseConflict{
				Kind:    LeaseConflictCorruptedRecord,
				Message: fmt.Sprintf("stored lease rule is corrupted: %v", parseErr),
				Rule:    append([]string(nil), rule...),
			})
			continue
		}
		key := domainRoleLeaseKey{user: stored.User, role: stored.Role, domain: stored.Domain}
		if existing, ok := current[key]; ok {
			if !sameLeaseContent(existing.lease, stored) {
				conflicts = append(conflicts, LeaseConflict{
					Kind: LeaseConflictCorruptedRecord,
					Message: fmt.Sprintf(
						"stored rules %q and %q contend for role %q of user %q in domain %q",
						existing.lease.GrantID, stored.GrantID, stored.Role, stored.User, stored.Domain),
					Rule: append([]string(nil), rule...),
				})
			}
			continue
		}
		current[key] = storedDomainRoleLease{lease: stored, rule: append([]string(nil), rule...)}
	}
	return current, conflicts, nil
}

// diffDomainRoleLeases turns desired and current lease state into the exact
// grouping rules to add and remove, while classifying every delivered lease
// as added, updated or unchanged and every missing stored lease as removed.
func diffDomainRoleLeases(source string, desired map[domainRoleLeaseKey]DomainRoleLease,
	current map[domainRoleLeaseKey]storedDomainRoleLease,
	result *ReconcileDomainRoleLeasesResult) (addRules, removeRules [][]string) {
	addRules = [][]string{}
	removeRules = [][]string{}
	for key, lease := range desired {
		stored, ok := current[key]
		if !ok {
			addRules = append(addRules, encodeDomainRoleLeaseRule(source, lease))
			result.Added = append(result.Added, lease)
			continue
		}
		if sameLeaseContent(stored.lease, lease) {
			result.Unchanged = append(result.Unchanged, lease)
			continue
		}
		// An update keeps the role slot but replaces grant content: remove the
		// old tagged rule and add the new one.
		removeRules = append(removeRules, stored.rule)
		addRules = append(addRules, encodeDomainRoleLeaseRule(source, lease))
		result.Updated = append(result.Updated, lease)
	}
	for key, stored := range current {
		if _, ok := desired[key]; ok {
			continue
		}
		removeRules = append(removeRules, stored.rule)
		result.Removed = append(result.Removed, stored.lease)
	}
	return addRules, removeRules
}

// validateDomainRoleLease rejects lease records that cannot be stored or
// reconciled safely.
func validateDomainRoleLease(lease DomainRoleLease) error {
	if lease.User == "" {
		return errors.New("user must not be empty")
	}
	if lease.Role == "" {
		return errors.New("role must not be empty")
	}
	if lease.Domain == "" {
		return errors.New("domain must not be empty")
	}
	if lease.GrantID == "" {
		return errors.New("grant ID must not be empty")
	}
	if lease.ExpiresAt.IsZero() {
		return errors.New("expiration time must not be zero")
	}
	return nil
}

// sameLeaseContent reports whether two leases carry the same grant content.
// The role slot (user, role, domain) is compared by the caller via the map key.
func sameLeaseContent(a, b DomainRoleLease) bool {
	return a.GrantID == b.GrantID && a.ExpiresAt.Equal(b.ExpiresAt)
}

// isLeaseMarkerRule reports whether a grouping rule carries the lease marker.
func isLeaseMarkerRule(rule []string) bool {
	return len(rule) > leaseMarkerIndex && rule[leaseMarkerIndex] == domainRoleLeaseMarker
}

// encodeDomainRoleLeaseRule turns a lease into the tagged grouping rule stored
// in the "g" policy. The first three fields stay a regular domain role link, so
// the role manager keeps enforcing the assignment while the suffix records
// source ownership, the authorization number and the expiration time.
func encodeDomainRoleLeaseRule(source string, lease DomainRoleLease) []string {
	return []string{
		lease.User,
		lease.Role,
		lease.Domain,
		domainRoleLeaseMarker,
		source,
		lease.GrantID,
		lease.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
}

// parseStoredDomainRoleLease parses a source-owned grouping rule back into a
// lease. Any structural or formatting problem is reported as corruption.
func parseStoredDomainRoleLease(rule []string) (DomainRoleLease, error) {
	if len(rule) != domainRoleLeaseRuleSize {
		return DomainRoleLease{}, fmt.Errorf("expected %d fields, got %d in rule %v",
			domainRoleLeaseRuleSize, len(rule), rule)
	}
	if rule[leaseMarkerIndex] != domainRoleLeaseMarker {
		return DomainRoleLease{}, fmt.Errorf("missing lease marker in rule %v", rule)
	}
	if rule[leaseUserIndex] == "" || rule[leaseRoleIndex] == "" ||
		rule[leaseDomainIndex] == "" || rule[leaseSourceIndex] == "" ||
		rule[leaseGrantIDIndex] == "" {
		return DomainRoleLease{}, fmt.Errorf("empty mandatory field in rule %v", rule)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, rule[leaseExpiresAtIndex])
	if err != nil {
		return DomainRoleLease{}, fmt.Errorf("unparseable expiration time %q in rule %v: %w",
			rule[leaseExpiresAtIndex], rule, err)
	}
	return DomainRoleLease{
		User:      rule[leaseUserIndex],
		Role:      rule[leaseRoleIndex],
		Domain:    rule[leaseDomainIndex],
		GrantID:   rule[leaseGrantIDIndex],
		ExpiresAt: expiresAt,
	}, nil
}

// persistDomainRoleLeaseRules writes the full diff to the adapter. Adapters
// implementing TransactionalAdapter get an all-or-nothing transaction; any
// failure rolls the storage changes back. Other adapters are written
// directly, and the model is only updated after every write succeeds.
func (e *Enforcer) persistDomainRoleLeaseRules(addRules, removeRules [][]string) error {
	if !e.shouldPersist() {
		return nil
	}

	if txAdapter, ok := e.adapter.(persist.TransactionalAdapter); ok {
		txContext, err := txAdapter.BeginTransaction(context.Background())
		if err != nil {
			return &LeasePersistenceError{Op: "begin", Err: err}
		}
		txPersistenceAdapter := txContext.GetAdapter()
		if txPersistenceAdapter == nil {
			_ = txContext.Rollback()
			return &LeasePersistenceError{Op: "begin", Err: errors.New("transaction returned a nil adapter")}
		}
		if err := writeDomainRoleLeaseRules(txPersistenceAdapter, addRules, removeRules); err != nil {
			_ = txContext.Rollback()
			return err
		}
		if err := txContext.Commit(); err != nil {
			return &LeasePersistenceError{Op: "commit", Err: err}
		}
		return nil
	}

	return writeDomainRoleLeaseRules(e.adapter, addRules, removeRules)
}

// writeDomainRoleLeaseRules applies removals before additions so an update
// never collides with the rule it replaces. Adapters that do not implement
// incremental persistence ("not implemented") are tolerated the same way as
// the regular management API.
func writeDomainRoleLeaseRules(adapter persist.Adapter, addRules, removeRules [][]string) error {
	if len(removeRules) > 0 {
		if batchAdapter, ok := adapter.(persist.BatchAdapter); ok {
			if err := batchAdapter.RemovePolicies("g", "g", removeRules); err != nil {
				if err.Error() != notImplemented {
					return &LeasePersistenceError{Op: "remove", Err: err}
				}
			}
		} else {
			for _, rule := range removeRules {
				if err := adapter.RemovePolicy("g", "g", rule); err != nil {
					if err.Error() != notImplemented {
						return &LeasePersistenceError{Op: "remove", Err: err}
					}
				}
			}
		}
	}
	if len(addRules) > 0 {
		if batchAdapter, ok := adapter.(persist.BatchAdapter); ok {
			if err := batchAdapter.AddPolicies("g", "g", addRules); err != nil {
				if err.Error() != notImplemented {
					return &LeasePersistenceError{Op: "add", Err: err}
				}
			}
		} else {
			for _, rule := range addRules {
				if err := adapter.AddPolicy("g", "g", rule); err != nil {
					if err.Error() != notImplemented {
						return &LeasePersistenceError{Op: "add", Err: err}
					}
				}
			}
		}
	}
	return nil
}

// applyDomainRoleLeaseRulesToModel mirrors the model side of the management
// API without touching the adapter again: removals and additions are applied
// to the model, role links are rebuilt from every grouping rule and
// constraints are re-validated. A full rebuild is required because a lease
// rule may share its (user, role, domain) link with a manual rule: deleting
// the lease rule must not tear down the link the manual rule still backs.
func (e *Enforcer) applyDomainRoleLeaseRulesToModel(addRules, removeRules [][]string) error {
	defer e.bumpPolicyVersion()

	if len(removeRules) > 0 {
		if _, err := e.model.RemovePoliciesWithAffected("g", "g", removeRules); err != nil {
			return err
		}
	}
	if len(addRules) > 0 {
		if _, err := e.model.AddPoliciesWithAffected("g", "g", addRules); err != nil {
			return err
		}
	}

	if e.autoBuildRoleLinks {
		e.invalidateMatcherMap()
		if err := e.rebuildRoleLinks(e.model); err != nil {
			return err
		}
		if err := e.rebuildConditionalRoleLinks(e.model); err != nil {
			return err
		}
	}
	return e.validateConstraintsForGroupingPolicy()
}

// notifyDomainRoleLeaseWatcher tells other instances about the committed
// diff, matching the notification behavior of the regular management API.
func (e *Enforcer) notifyDomainRoleLeaseWatcher(addRules, removeRules [][]string) error {
	if !e.shouldNotify() {
		return nil
	}
	watcherEx, isWatcherEx := e.watcher.(persist.WatcherEx)
	if !isWatcherEx {
		return e.watcher.Update()
	}
	if len(removeRules) > 0 {
		if err := watcherEx.UpdateForRemovePolicies("g", "g", removeRules...); err != nil {
			return err
		}
	}
	if len(addRules) > 0 {
		if err := watcherEx.UpdateForAddPolicies("g", "g", addRules...); err != nil {
			return err
		}
	}
	return nil
}

// sortLeases gives result slices a deterministic order across runs.
func sortLeases(leases []DomainRoleLease) {
	sort.SliceStable(leases, func(i, j int) bool {
		if leases[i].Domain != leases[j].Domain {
			return leases[i].Domain < leases[j].Domain
		}
		if leases[i].User != leases[j].User {
			return leases[i].User < leases[j].User
		}
		if leases[i].Role != leases[j].Role {
			return leases[i].Role < leases[j].Role
		}
		return leases[i].GrantID < leases[j].GrantID
	})
}

// sortRules gives persisted rule slices a deterministic order.
func sortRules(rules [][]string) {
	sort.SliceStable(rules, func(i, j int) bool {
		return strings.Join(rules[i], ",") < strings.Join(rules[j], ",")
	})
}
