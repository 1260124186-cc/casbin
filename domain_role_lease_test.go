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
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/util"
)

// leaseSpyAdapter is an in-memory BatchAdapter that records every persistence
// call and can inject failures, so tests can prove unchanged relationships are
// never rewritten and failed runs do not mutate the model.
type leaseSpyAdapter struct {
	rules         [][]string
	addBatches    [][][]string
	removeBatches [][][]string
	failAdd       bool
	failRemove    bool
	failErr       error
}

func newLeaseSpyAdapter(rules ...[]string) *leaseSpyAdapter {
	copied := make([][]string, 0, len(rules))
	for _, rule := range rules {
		copied = append(copied, append([]string(nil), rule...))
	}
	return &leaseSpyAdapter{
		rules:   copied,
		failErr: errors.New("spy adapter injected persistence failure"),
	}
}

func asInterfaces(rule []string) []interface{} {
	out := make([]interface{}, len(rule))
	for i, value := range rule {
		out[i] = value
	}
	return out
}

func cloneLeaseRules(rules [][]string) [][]string {
	copied := make([][]string, 0, len(rules))
	for _, rule := range rules {
		copied = append(copied, append([]string(nil), rule...))
	}
	return copied
}

func (a *leaseSpyAdapter) LoadPolicy(m model.Model) error {
	for _, rule := range a.rules {
		if err := persist.LoadPolicyArray(append([]string{"g"}, rule...), m); err != nil {
			return err
		}
	}
	return nil
}

func (a *leaseSpyAdapter) SavePolicy(m model.Model) error {
	return nil
}

func (a *leaseSpyAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.addPolicies([][]string{rule})
}

func (a *leaseSpyAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return a.addPolicies(rules)
}

func (a *leaseSpyAdapter) addPolicies(rules [][]string) error {
	if a.failAdd {
		return a.failErr
	}
	a.addBatches = append(a.addBatches, cloneLeaseRules(rules))
	a.rules = append(a.rules, cloneLeaseRules(rules)...)
	return nil
}

func (a *leaseSpyAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.removePolicies([][]string{rule})
}

func (a *leaseSpyAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.removePolicies(rules)
}

func (a *leaseSpyAdapter) removePolicies(rules [][]string) error {
	if a.failRemove {
		return a.failErr
	}
	a.removeBatches = append(a.removeBatches, cloneLeaseRules(rules))
	removed := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		removed[strings.Join(rule, ",")] = struct{}{}
	}
	kept := a.rules[:0]
	for _, rule := range a.rules {
		if _, ok := removed[strings.Join(rule, ",")]; ok {
			continue
		}
		kept = append(kept, rule)
	}
	a.rules = kept
	return nil
}

func (a *leaseSpyAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New("not implemented")
}

func (a *leaseSpyAdapter) totalAddCalls() int {
	return len(a.addBatches)
}

func (a *leaseSpyAdapter) totalRemoveCalls() int {
	return len(a.removeBatches)
}

// leaseTxSpyAdapter is a transactional version of the spy adapter. A
// transaction works on a private copy; commit publishes it while rollback
// discards every staged write.
type leaseTxSpyAdapter struct {
	*leaseSpyAdapter
	committed  int
	rolledBack int
}

func newLeaseTxSpyAdapter(rules ...[]string) *leaseTxSpyAdapter {
	return &leaseTxSpyAdapter{leaseSpyAdapter: newLeaseSpyAdapter(rules...)}
}

type leaseTxSpyContext struct {
	parent  *leaseTxSpyAdapter
	working *leaseSpyAdapter
}

func (a *leaseTxSpyAdapter) BeginTransaction(ctx context.Context) (persist.TransactionContext, error) {
	working := newLeaseSpyAdapter(a.rules...)
	working.failAdd = a.failAdd
	working.failRemove = a.failRemove
	working.failErr = a.failErr
	return &leaseTxSpyContext{parent: a, working: working}, nil
}

func (c *leaseTxSpyContext) Commit() error {
	c.parent.rules = cloneLeaseRules(c.working.rules)
	c.parent.addBatches = append(c.parent.addBatches, c.working.addBatches...)
	c.parent.removeBatches = append(c.parent.removeBatches, c.working.removeBatches...)
	c.parent.committed++
	return nil
}

func (c *leaseTxSpyContext) Rollback() error {
	c.parent.rolledBack++
	return nil
}

func (c *leaseTxSpyContext) GetAdapter() persist.Adapter {
	return c.working
}

// newLeaseTestEnforcer builds an enforcer on the domain RBAC model backed by
// the given spy adapter.
func newLeaseTestEnforcer(t *testing.T, adapter persist.Adapter) *Enforcer {
	t.Helper()
	e, err := NewEnforcer("examples/rbac_with_domains_model.conf", adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	return e
}

func leaseAt(user, role, domain, grant string, expiresAt time.Time) DomainRoleLease {
	return DomainRoleLease{
		User:      user,
		Role:      role,
		Domain:    domain,
		GrantID:   grant,
		ExpiresAt: expiresAt,
	}
}

func futureLease(user, role, domain, grant string) DomainRoleLease {
	return leaseAt(user, role, domain, grant, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
}

func pastLease(user, role, domain, grant string) DomainRoleLease {
	return leaseAt(user, role, domain, grant, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
}

func leaseRuleSet(rules [][]string) map[string]struct{} {
	set := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		set[strings.Join(rule, ",")] = struct{}{}
	}
	return set
}

func groupingRuleSet(t *testing.T, e *Enforcer) map[string]struct{} {
	t.Helper()
	rules, err := e.GetNamedGroupingPolicy("g")
	if err != nil {
		t.Fatalf("failed to read grouping policy: %v", err)
	}
	return leaseRuleSet(rules)
}

func findStoredLeaseRule(t *testing.T, e *Enforcer, source, user, role, domain string) ([]string, bool) {
	t.Helper()
	rules, err := e.GetNamedGroupingPolicy("g")
	if err != nil {
		t.Fatalf("failed to read grouping policy: %v", err)
	}
	for _, rule := range rules {
		if len(rule) == domainRoleLeaseRuleSize &&
			rule[leaseMarkerIndex] == domainRoleLeaseMarker &&
			rule[leaseSourceIndex] == source &&
			rule[leaseUserIndex] == user &&
			rule[leaseRoleIndex] == role &&
			rule[leaseDomainIndex] == domain {
			return rule, true
		}
	}
	return nil, false
}

func assertLeaseResultCounts(t *testing.T, result *ReconcileDomainRoleLeasesResult, added, updated, removed, unchanged, expired int) {
	t.Helper()
	if len(result.Added) != added || len(result.Updated) != updated ||
		len(result.Removed) != removed || len(result.Unchanged) != unchanged ||
		len(result.Expired) != expired {
		t.Fatalf("unexpected result counts: added=%d updated=%d removed=%d unchanged=%d expired=%d, want added=%d updated=%d removed=%d unchanged=%d expired=%d",
			len(result.Added), len(result.Updated), len(result.Removed), len(result.Unchanged), len(result.Expired),
			added, updated, removed, unchanged, expired)
	}
}

func assertRolesInDomain(t *testing.T, e *Enforcer, user, domain string, expected []string) {
	t.Helper()
	roles := e.GetRolesForUserInDomain(user, domain)
	if !util.SetEquals(roles, expected) {
		t.Fatalf("roles for %s in %s = %v, want %v", user, domain, roles, expected)
	}
}

// TestReconcileDomainRoleLeasesAddsAndEnforces verifies that fresh leases are
// stored as tagged grouping rules and immediately drive role links.
func TestReconcileDomainRoleLeasesAddsAndEnforces(t *testing.T) {
	adapter := newLeaseSpyAdapter()
	e := newLeaseTestEnforcer(t, adapter)

	leases := []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
		futureLease("bob", "admin", "domain2", "G-002"),
	}
	result, err := e.ReconcileDomainRoleLeases("upstream-a", leases)
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 2, 0, 0, 0, 0)

	if adapter.totalAddCalls() != 1 || adapter.totalRemoveCalls() != 0 {
		t.Fatalf("expected one add batch and no remove batch, got add=%d remove=%d",
			adapter.totalAddCalls(), adapter.totalRemoveCalls())
	}

	rule, ok := findStoredLeaseRule(t, e, "upstream-a", "alice", "admin", "domain1")
	if !ok {
		t.Fatal("alice's lease rule was not stored")
	}
	if rule[leaseGrantIDIndex] != "G-001" {
		t.Fatalf("unexpected grant ID in stored rule: %v", rule)
	}

	assertRolesInDomain(t, e, "alice", "domain1", []string{"admin"})
	assertRolesInDomain(t, e, "bob", "domain2", []string{"admin"})

	// The tagged rule behaves as a regular domain role link in enforcement.
	if _, err := e.AddPolicy("admin", "domain1", "data1", "read"); err != nil {
		t.Fatalf("failed to seed permission policy: %v", err)
	}
	allowed, err := e.Enforce("alice", "domain1", "data1", "read")
	if err != nil || !allowed {
		t.Fatalf("alice should inherit admin permissions, allowed=%v err=%v", allowed, err)
	}
}

// TestReconcileDomainRoleLeasesIdempotent verifies that re-applying the same
// list performs no persistence and no model writes at all.
func TestReconcileDomainRoleLeasesIdempotent(t *testing.T) {
	adapter := newLeaseSpyAdapter()
	e := newLeaseTestEnforcer(t, adapter)

	leases := []DomainRoleLease{futureLease("alice", "admin", "domain1", "G-001")}
	if _, err := e.ReconcileDomainRoleLeases("upstream-a", leases); err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}
	before := groupingRuleSet(t, e)

	result, err := e.ReconcileDomainRoleLeases("upstream-a", leases)
	if err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 0, 0, 0, 1, 0)

	if adapter.totalAddCalls() != 1 || adapter.totalRemoveCalls() != 0 {
		t.Fatalf("idempotent run must not persist anything, got add=%d remove=%d",
			adapter.totalAddCalls(), adapter.totalRemoveCalls())
	}
	after := groupingRuleSet(t, e)
	if len(before) != len(after) {
		t.Fatalf("idempotent run changed the model: before=%v after=%v", before, after)
	}
	for key := range before {
		if _, ok := after[key]; !ok {
			t.Fatalf("idempotent run dropped rule %q", key)
		}
	}

	// An empty desired list reconciled by a source that owns nothing is a no-op.
	emptyEnforcer := newLeaseTestEnforcer(t, newLeaseSpyAdapter())
	emptyResult, err := emptyEnforcer.ReconcileDomainRoleLeases("upstream-a", nil)
	if err != nil {
		t.Fatalf("empty reconcile failed: %v", err)
	}
	assertLeaseResultCounts(t, emptyResult, 0, 0, 0, 0, 0)
	if spy := emptyEnforcer.adapter.(*leaseSpyAdapter); spy.totalRemoveCalls() != 0 {
		t.Fatalf("empty reconcile with no owned rules must not remove anything")
	}
}

// TestReconcileDomainRoleLeasesUpdatesChangedContent verifies grant content
// changes replace only the affected rule while untouched leases stay put.
func TestReconcileDomainRoleLeasesUpdatesChangedContent(t *testing.T) {
	adapter := newLeaseSpyAdapter()
	e := newLeaseTestEnforcer(t, adapter)

	original := []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
		futureLease("bob", "admin", "domain2", "G-002"),
	}
	if _, err := e.ReconcileDomainRoleLeases("upstream-a", original); err != nil {
		t.Fatalf("seed reconcile failed: %v", err)
	}

	changed := []DomainRoleLease{
		leaseAt("alice", "admin", "domain1", "G-001", time.Date(2099, 6, 1, 0, 0, 0, 0, time.UTC)),
		leaseAt("bob", "admin", "domain2", "G-003", time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)),
	}
	result, err := e.ReconcileDomainRoleLeases("upstream-a", changed)
	if err != nil {
		t.Fatalf("update reconcile failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 0, 2, 0, 0, 0)

	if adapter.totalRemoveCalls() != 1 || adapter.totalAddCalls() != 2 {
		t.Fatalf("update run expected one remove batch and two add batches total, got add=%d remove=%d",
			adapter.totalAddCalls(), adapter.totalRemoveCalls())
	}

	aliceRule, ok := findStoredLeaseRule(t, e, "upstream-a", "alice", "admin", "domain1")
	if !ok {
		t.Fatal("alice's updated lease rule is missing")
	}
	if aliceRule[leaseExpiresAtIndex] != "2099-06-01T00:00:00Z" {
		t.Fatalf("alice's expiration was not updated: %v", aliceRule)
	}
	bobRule, ok := findStoredLeaseRule(t, e, "upstream-a", "bob", "admin", "domain2")
	if !ok {
		t.Fatal("bob's updated lease rule is missing")
	}
	if bobRule[leaseGrantIDIndex] != "G-003" {
		t.Fatalf("bob's grant ID was not updated: %v", bobRule)
	}
	assertRolesInDomain(t, e, "alice", "domain1", []string{"admin"})
	assertRolesInDomain(t, e, "bob", "domain2", []string{"admin"})

	// Re-applying the updated list is a no-op.
	again, err := e.ReconcileDomainRoleLeases("upstream-a", changed)
	if err != nil {
		t.Fatalf("repeated update reconcile failed: %v", err)
	}
	assertLeaseResultCounts(t, again, 0, 0, 0, 2, 0)
	if adapter.totalRemoveCalls() != 1 || adapter.totalAddCalls() != 2 {
		t.Fatalf("unchanged re-run must not persist anything")
	}
}

// TestReconcileDomainRoleLeasesRemovesRevokedAndExpired verifies revocation
// (missing from the list) and expiration both delete the owned relationship.
func TestReconcileDomainRoleLeasesRemovesRevokedAndExpired(t *testing.T) {
	adapter := newLeaseSpyAdapter()
	e := newLeaseTestEnforcer(t, adapter)

	initial := []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
		futureLease("bob", "admin", "domain2", "G-002"),
		pastLease("carol", "admin", "domain1", "G-003"),
	}
	result, err := e.ReconcileDomainRoleLeases("upstream-a", initial)
	if err != nil {
		t.Fatalf("seed reconcile failed: %v", err)
	}
	// The already-expired input lease never creates a relationship.
	assertLeaseResultCounts(t, result, 2, 0, 0, 0, 1)
	if _, ok := findStoredLeaseRule(t, e, "upstream-a", "carol", "admin", "domain1"); ok {
		t.Fatal("an expired input lease must not be stored")
	}

	// Revoke alice by dropping her; bob stays; carol is still reported expired.
	next := []DomainRoleLease{
		futureLease("bob", "admin", "domain2", "G-002"),
		pastLease("carol", "admin", "domain1", "G-003"),
	}
	result, err = e.ReconcileDomainRoleLeases("upstream-a", next)
	if err != nil {
		t.Fatalf("revoke reconcile failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 0, 0, 1, 1, 1)
	if result.Removed[0].User != "alice" {
		t.Fatalf("expected alice to be removed, got %v", result.Removed)
	}
	if _, ok := findStoredLeaseRule(t, e, "upstream-a", "alice", "admin", "domain1"); ok {
		t.Fatal("revoked lease rule should have been deleted")
	}
	assertRolesInDomain(t, e, "alice", "domain1", []string{})
	if _, ok := findStoredLeaseRule(t, e, "upstream-a", "bob", "admin", "domain2"); !ok {
		t.Fatal("bob's unchanged lease rule must survive")
	}
	if adapter.totalRemoveCalls() != 1 {
		t.Fatalf("expected exactly one remove batch, got %d", adapter.totalRemoveCalls())
	}

	// An expired rule already in storage is removed even when the list is empty.
	expiredRule := encodeDomainRoleLeaseRule("upstream-a", pastLease("dave", "admin", "domain1", "G-004"))
	if _, err := e.AddGroupingPolicy(asInterfaces(expiredRule)...); err != nil {
		t.Fatalf("failed to seed expired stored rule: %v", err)
	}
	result, err = e.ReconcileDomainRoleLeases("upstream-a", next)
	if err != nil {
		t.Fatalf("expiry reconcile failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 0, 0, 1, 1, 1)
	if _, ok := findStoredLeaseRule(t, e, "upstream-a", "dave", "admin", "domain1"); ok {
		t.Fatal("expired stored lease rule should have been deleted")
	}
}

// TestReconcileDomainRoleLeasesKeepsManualAndInheritance verifies that manual
// domain members and role inheritance rules are never modified.
func TestReconcileDomainRoleLeasesKeepsManualAndInheritance(t *testing.T) {
	manual := []string{"manual-user", "admin", "domain1"}
	inheritance := []string{"role:writer", "role:reader", "domain1"}
	adapter := newLeaseSpyAdapter(manual, inheritance)
	e := newLeaseTestEnforcer(t, adapter)

	before := groupingRuleSet(t, e)
	result, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
	})
	if err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 1, 0, 0, 0, 0)

	after := groupingRuleSet(t, e)
	if _, ok := after[strings.Join(manual, ",")]; !ok {
		t.Fatal("manual membership rule was removed")
	}
	if _, ok := after[strings.Join(inheritance, ",")]; !ok {
		t.Fatal("role inheritance rule was removed")
	}
	if _, ok := findStoredLeaseRule(t, e, "upstream-a", "alice", "admin", "domain1"); !ok {
		t.Fatal("lease rule was not added")
	}

	// Deleting every owned lease still leaves the manual rules untouched.
	if _, err := e.ReconcileDomainRoleLeases("upstream-a", nil); err != nil {
		t.Fatalf("revoke-all reconcile failed: %v", err)
	}
	final := groupingRuleSet(t, e)
	if len(final) != len(before) {
		t.Fatalf("manual rules must remain after lease cleanup: before=%v final=%v", before, final)
	}
	for key := range before {
		if _, ok := final[key]; !ok {
			t.Fatalf("manual rule %q disappeared after lease cleanup", key)
		}
	}
}

// TestReconcileDomainRoleLeasesCoexistsWithManualMember verifies a lease can
// target a slot already held manually, and removing the lease never revokes the
// manual membership.
func TestReconcileDomainRoleLeasesCoexistsWithManualMember(t *testing.T) {
	manual := []string{"alice", "admin", "domain1"}
	adapter := newLeaseSpyAdapter(manual)
	e := newLeaseTestEnforcer(t, adapter)

	if _, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
	}); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if _, ok := findStoredLeaseRule(t, e, "upstream-a", "alice", "admin", "domain1"); !ok {
		t.Fatal("lease rule should coexist with the manual rule")
	}
	if ok, _ := e.HasGroupingPolicy(asInterfaces(manual)...); !ok {
		t.Fatal("manual rule must still exist alongside the lease rule")
	}
	assertRolesInDomain(t, e, "alice", "domain1", []string{"admin"})

	if _, err := e.ReconcileDomainRoleLeases("upstream-a", nil); err != nil {
		t.Fatalf("lease cleanup failed: %v", err)
	}
	if ok, _ := e.HasGroupingPolicy(asInterfaces(manual)...); !ok {
		t.Fatal("manual rule must survive lease removal")
	}
	assertRolesInDomain(t, e, "alice", "domain1", []string{"admin"})
}

// TestReconcileDomainRoleLeasesIsolatesSources verifies rules owned by another
// lease source are outside the reconcile scope.
func TestReconcileDomainRoleLeasesIsolatesSources(t *testing.T) {
	otherRule := encodeDomainRoleLeaseRule("upstream-b", futureLease("zoe", "admin", "domain1", "B-001"))
	adapter := newLeaseSpyAdapter(otherRule)
	e := newLeaseTestEnforcer(t, adapter)

	if _, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "A-001"),
	}); err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}
	if _, err := e.ReconcileDomainRoleLeases("upstream-a", nil); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	rules, _ := e.GetNamedGroupingPolicy("g")
	if !util.Array2DEquals(rules, [][]string{otherRule}) {
		t.Fatalf("the other source's rule must be untouched, got %v", rules)
	}
	assertRolesInDomain(t, e, "zoe", "domain1", []string{"admin"})
}

// TestReconcileDomainRoleLeasesDuplicateConflict verifies two contending
// grants abort the run without any write.
func TestReconcileDomainRoleLeasesDuplicateConflict(t *testing.T) {
	adapter := newLeaseSpyAdapter()
	e := newLeaseTestEnforcer(t, adapter)
	before := groupingRuleSet(t, e)

	_, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
		futureLease("alice", "admin", "domain1", "G-002"),
	})
	if err == nil {
		t.Fatal("contending leases must produce an error")
	}
	if !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("expected ErrLeaseConflict, got %v", err)
	}
	var conflictErr *LeaseConflictError
	if !errors.As(err, &conflictErr) || len(conflictErr.Conflicts) != 1 {
		t.Fatalf("expected one aggregated conflict, got %v", err)
	}
	if conflictErr.Conflicts[0].Kind != LeaseConflictDuplicateLease {
		t.Fatalf("expected duplicate conflict kind, got %q", conflictErr.Conflicts[0].Kind)
	}
	if adapter.totalAddCalls() != 0 || adapter.totalRemoveCalls() != 0 {
		t.Fatal("a conflict run must not persist anything")
	}
	if len(groupingRuleSet(t, e)) != len(before) {
		t.Fatal("a conflict run must not change the model")
	}

	// Exact duplicates are deduped instead of treated as a conflict.
	dup := futureLease("alice", "admin", "domain1", "G-001")
	result, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{dup, dup})
	if err != nil {
		t.Fatalf("identical duplicates should be accepted: %v", err)
	}
	assertLeaseResultCounts(t, result, 1, 0, 0, 0, 0)
}

// TestReconcileDomainRoleLeasesCorruptedInput verifies malformed delivered
// leases are reported without changing anything.
func TestReconcileDomainRoleLeasesCorruptedInput(t *testing.T) {
	adapter := newLeaseSpyAdapter()
	e := newLeaseTestEnforcer(t, adapter)

	cases := []DomainRoleLease{
		{User: "", Role: "admin", Domain: "domain1", GrantID: "G-1", ExpiresAt: time.Now().Add(time.Hour)},
		{User: "bob", Role: "", Domain: "domain1", GrantID: "G-2", ExpiresAt: time.Now().Add(time.Hour)},
		{User: "carol", Role: "admin", Domain: "", GrantID: "G-3", ExpiresAt: time.Now().Add(time.Hour)},
		{User: "dave", Role: "admin", Domain: "domain1", GrantID: "", ExpiresAt: time.Now().Add(time.Hour)},
		{User: "erin", Role: "admin", Domain: "domain1", GrantID: "G-5", ExpiresAt: time.Time{}},
	}
	_, err := e.ReconcileDomainRoleLeases("upstream-a", cases)
	if !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("expected ErrLeaseConflict, got %v", err)
	}
	var conflictErr *LeaseConflictError
	if !errors.As(err, &conflictErr) || len(conflictErr.Conflicts) != len(cases) {
		t.Fatalf("expected %d aggregated conflicts, got %v", len(cases), err)
	}
	for _, conflict := range conflictErr.Conflicts {
		if conflict.Kind != LeaseConflictCorruptedRecord {
			t.Fatalf("expected corrupted record conflict, got %q", conflict.Kind)
		}
	}
	if adapter.totalAddCalls() != 0 {
		t.Fatal("corrupted input must not be persisted")
	}
	if rules, _ := e.GetNamedGroupingPolicy("g"); len(rules) != 0 {
		t.Fatalf("corrupted input must not change the model, got %v", rules)
	}
}

// TestReconcileDomainRoleLeasesCorruptedStoredRule verifies unparseable stored
// lease rules block the run while another source's malformed rules are ignored.
func TestReconcileDomainRoleLeasesCorruptedStoredRule(t *testing.T) {
	badExpiry := []string{"alice", "admin", "domain1", domainRoleLeaseMarker, "upstream-a", "G-001", "not-a-time"}
	badShape := []string{"bob", "admin", "domain1", domainRoleLeaseMarker, "upstream-a", "G-002"}
	adapter := newLeaseSpyAdapter(badExpiry, badShape)
	e := newLeaseTestEnforcer(t, adapter)

	_, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("carol", "admin", "domain1", "G-003"),
	})
	if !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("expected ErrLeaseConflict, got %v", err)
	}
	var conflictErr *LeaseConflictError
	if !errors.As(err, &conflictErr) || len(conflictErr.Conflicts) != 2 {
		t.Fatalf("expected two corrupted-record conflicts, got %v", err)
	}
	if adapter.totalAddCalls() != 0 || adapter.totalRemoveCalls() != 0 {
		t.Fatal("a corrupted-stored-rule run must not write anything")
	}
	if _, ok := findStoredLeaseRule(t, e, "upstream-a", "carol", "admin", "domain1"); ok {
		t.Fatal("no lease may be added while conflicts are pending")
	}

	// The same malformed rules belong to another source: this source sees no conflict.
	otherAdapter := newLeaseSpyAdapter(badExpiry, badShape)
	otherEnforcer := newLeaseTestEnforcer(t, otherAdapter)
	result, err := otherEnforcer.ReconcileDomainRoleLeases("upstream-c", []DomainRoleLease{
		futureLease("carol", "admin", "domain1", "C-001"),
	})
	if err != nil {
		t.Fatalf("another source's malformed rules must be out of scope: %v", err)
	}
	assertLeaseResultCounts(t, result, 1, 0, 0, 0, 0)
}

// TestReconcileDomainRoleLeasesPersistenceFailureRollsBack verifies a
// transactional adapter rolls the whole batch back and the model stays intact.
func TestReconcileDomainRoleLeasesPersistenceFailureRollsBack(t *testing.T) {
	adapter := newLeaseTxSpyAdapter()
	adapter.failAdd = true
	e := newLeaseTestEnforcer(t, adapter)
	before := groupingRuleSet(t, e)

	_, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
		futureLease("bob", "admin", "domain2", "G-002"),
	})
	if !errors.Is(err, ErrLeasePersistence) {
		t.Fatalf("expected ErrLeasePersistence, got %v", err)
	}
	var persistenceErr *LeasePersistenceError
	if !errors.As(err, &persistenceErr) {
		t.Fatalf("expected a LeasePersistenceError, got %T", err)
	}
	if adapter.rolledBack != 1 || adapter.committed != 0 {
		t.Fatalf("expected rollback without commit, got rolledBack=%d committed=%d",
			adapter.rolledBack, adapter.committed)
	}
	if len(adapter.rules) != 0 || adapter.totalAddCalls() != 0 {
		t.Fatal("rolled-back writes must not reach the committed storage")
	}
	if len(groupingRuleSet(t, e)) != len(before) {
		t.Fatal("the model must stay unchanged after a rollback")
	}

	// After the adapter recovers, the same list applies cleanly.
	adapter.failAdd = false
	result, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
		futureLease("bob", "admin", "domain2", "G-002"),
	})
	if err != nil {
		t.Fatalf("retry after recovery failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 2, 0, 0, 0, 0)
	if adapter.committed != 1 {
		t.Fatalf("the recovered run should commit once, got %d", adapter.committed)
	}
}

// TestReconcileDomainRoleLeasesPersistenceFailureKeepsModel verifies a
// non-transactional adapter failure leaves the in-memory relationships
// untouched, and a later run converges.
func TestReconcileDomainRoleLeasesPersistenceFailureKeepsModel(t *testing.T) {
	adapter := newLeaseSpyAdapter()
	adapter.failAdd = true
	e := newLeaseTestEnforcer(t, adapter)

	_, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
	})
	if !errors.Is(err, ErrLeasePersistence) {
		t.Fatalf("expected ErrLeasePersistence, got %v", err)
	}
	if rules, _ := e.GetNamedGroupingPolicy("g"); len(rules) != 0 {
		t.Fatalf("the model must not change when persistence fails, got %v", rules)
	}

	adapter.failAdd = false
	result, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
	})
	if err != nil {
		t.Fatalf("converging retry failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 1, 0, 0, 0, 0)
	if _, ok := findStoredLeaseRule(t, e, "upstream-a", "alice", "admin", "domain1"); !ok {
		t.Fatal("the converging retry should store the lease")
	}
}

// TestReconcileDomainRoleLeasesResumableAfterCrash verifies that a restart
// after an interrupted run only applies the still-missing differences.
func TestReconcileDomainRoleLeasesResumableAfterCrash(t *testing.T) {
	desired := []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
		futureLease("bob", "admin", "domain2", "G-002"),
	}

	// Simulate a process exit after only alice's lease reached the storage.
	partialAdapter := newLeaseSpyAdapter(encodeDomainRoleLeaseRule("upstream-a", desired[0]))
	e := newLeaseTestEnforcer(t, partialAdapter)

	result, err := e.ReconcileDomainRoleLeases("upstream-a", desired)
	if err != nil {
		t.Fatalf("resumed reconcile failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 1, 0, 0, 1, 0)
	if result.Added[0].User != "bob" || result.Unchanged[0].User != "alice" {
		t.Fatalf("resumed run should only add bob, got added=%v unchanged=%v", result.Added, result.Unchanged)
	}
	if partialAdapter.totalAddCalls() != 1 || partialAdapter.totalRemoveCalls() != 0 {
		t.Fatalf("resumed run must only persist the missing lease, got add=%d remove=%d",
			partialAdapter.totalAddCalls(), partialAdapter.totalRemoveCalls())
	}
	expectedRules := leaseRuleSet([][]string{
		encodeDomainRoleLeaseRule("upstream-a", desired[0]),
		encodeDomainRoleLeaseRule("upstream-a", desired[1]),
	})
	actualRules := groupingRuleSet(t, e)
	if len(actualRules) != len(expectedRules) {
		t.Fatalf("final state mismatch: %v want %v", actualRules, expectedRules)
	}
	for key := range expectedRules {
		if _, ok := actualRules[key]; !ok {
			t.Fatalf("missing expected rule %q after resume", key)
		}
	}

	// A second interrupted scenario: alice's renewal was only half applied, so
	// the old rule still sits in storage while the new content is desired.
	renewed := leaseAt("alice", "admin", "domain1", "G-009", time.Date(2099, 9, 9, 0, 0, 0, 0, time.UTC))
	interruptedAdapter := newLeaseTxSpyAdapter(
		encodeDomainRoleLeaseRule("upstream-a", desired[0]),
		encodeDomainRoleLeaseRule("upstream-a", desired[1]),
	)
	restarted := newLeaseTestEnforcer(t, interruptedAdapter)
	result, err = restarted.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{renewed, desired[1]})
	if err != nil {
		t.Fatalf("restart after interrupted update failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 0, 1, 0, 1, 0)
	aliceRule, ok := findStoredLeaseRule(t, restarted, "upstream-a", "alice", "admin", "domain1")
	if !ok || aliceRule[leaseGrantIDIndex] != "G-009" {
		t.Fatalf("alice's renewal should be completed after restart, got %v", aliceRule)
	}
	if interruptedAdapter.rolledBack != 0 {
		t.Fatal("a clean resumed run must not roll back")
	}
}

// TestReconcileDomainRoleLeasesWatcherNotified verifies watchers receive an
// update notification when the reconciled policy changes.
func TestReconcileDomainRoleLeasesWatcherNotified(t *testing.T) {
	adapter := newLeaseSpyAdapter()
	e := newLeaseTestEnforcer(t, adapter)

	notifications := 0
	watcher := &SampleWatcher{}
	if err := e.SetWatcher(watcher); err != nil {
		t.Fatalf("failed to set watcher: %v", err)
	}
	// SetWatcher registers its own callback; install the counting one afterwards.
	watcher.callback = func(string) { notifications++ }

	if _, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
	}); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}
	if notifications != 1 {
		t.Fatalf("watcher should be notified once after a change, got %d", notifications)
	}

	if _, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
	}); err != nil {
		t.Fatalf("idempotent reconcile failed: %v", err)
	}
	if notifications != 1 {
		t.Fatalf("an unchanged run must not notify the watcher again, got %d", notifications)
	}
}

// TestReconcileDomainRoleLeasesArguments verifies caller and model errors.
func TestReconcileDomainRoleLeasesArguments(t *testing.T) {
	adapter := newLeaseSpyAdapter()
	e := newLeaseTestEnforcer(t, adapter)

	if _, err := e.ReconcileDomainRoleLeases(" ", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
	}); err == nil {
		t.Fatal("an empty source must be rejected")
	}

	noRoleEnforcer, err := NewEnforcer("examples/basic_model.conf")
	if err != nil {
		t.Fatalf("failed to create model without role definition: %v", err)
	}
	if _, err := noRoleEnforcer.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
	}); err == nil {
		t.Fatal("reconciling without a role definition must fail")
	}
}

// TestReconcileDomainRoleLeasesInterfacePromotion verifies the method is part
// of IEnforcer and is promoted to the embedding enforcer wrappers.
func TestReconcileDomainRoleLeasesInterfacePromotion(t *testing.T) {
	var _ IEnforcer = &Enforcer{}
	var _ IEnforcer = &SyncedEnforcer{}
	var _ IEnforcer = &CachedEnforcer{}

	synced, err := NewSyncedEnforcer("examples/rbac_with_domains_model.conf", newLeaseSpyAdapter())
	if err != nil {
		t.Fatalf("failed to create synced enforcer: %v", err)
	}
	result, err := synced.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
	})
	if err != nil {
		t.Fatalf("synced enforcer reconcile failed: %v", err)
	}
	assertLeaseResultCounts(t, result, 1, 0, 0, 0, 0)

	iface := IEnforcer(synced)
	if _, err := iface.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("alice", "admin", "domain1", "G-001"),
	}); err != nil {
		t.Fatalf("interface call failed: %v", err)
	}
}

// TestReconcileDomainRoleLeasesRuleEncoding verifies the stored rule layout and
// round-trip parsing of a lease record.
func TestReconcileDomainRoleLeasesRuleEncoding(t *testing.T) {
	lease := futureLease("alice", "admin", "domain1", "G-001")
	rule := encodeDomainRoleLeaseRule("upstream-a", lease)
	if len(rule) != domainRoleLeaseRuleSize {
		t.Fatalf("expected %d fields, got %d", domainRoleLeaseRuleSize, len(rule))
	}
	if rule[leaseMarkerIndex] != domainRoleLeaseMarker || rule[leaseSourceIndex] != "upstream-a" {
		t.Fatalf("unexpected marker/source in rule %v", rule)
	}
	parsed, err := parseStoredDomainRoleLease(rule)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}
	if parsed.User != lease.User || parsed.Role != lease.Role || parsed.Domain != lease.Domain ||
		parsed.GrantID != lease.GrantID || !parsed.ExpiresAt.Equal(lease.ExpiresAt) {
		t.Fatalf("round-trip mismatch: %v vs %v", parsed, lease)
	}
	if !isLeaseMarkerRule(rule) {
		t.Fatal("encoded rule should be recognized as a marker rule")
	}
	if isLeaseMarkerRule([]string{"alice", "admin", "domain1"}) {
		t.Fatal("a plain grouping rule must not be recognized as a marker rule")
	}
	if _, err := parseStoredDomainRoleLease([]string{"alice", "admin", "domain1", domainRoleLeaseMarker, "upstream-a", "G-001"}); err == nil {
		t.Fatal("a short marker rule should fail parsing")
	}
	if _, err := parseStoredDomainRoleLease(append(append([]string(nil), rule...), "extra")); err == nil {
		t.Fatal("an over-long marker rule should fail parsing")
	}
	if err := validateDomainRoleLease(lease); err != nil {
		t.Fatalf("valid lease rejected: %v", err)
	}
	if err := validateDomainRoleLease(DomainRoleLease{}); err == nil {
		t.Fatal("the zero lease should be invalid")
	}
}

// TestReconcileDomainRoleLeasesStoredContention verifies two source-owned
// rules contending for the same role slot abort the run without writes.
func TestReconcileDomainRoleLeasesStoredContention(t *testing.T) {
	first := encodeDomainRoleLeaseRule("upstream-a", futureLease("alice", "admin", "domain1", "G-001"))
	second := encodeDomainRoleLeaseRule("upstream-a",
		leaseAt("alice", "admin", "domain1", "G-002", time.Date(2099, 3, 3, 0, 0, 0, 0, time.UTC)))
	adapter := newLeaseSpyAdapter(first, second)
	e := newLeaseTestEnforcer(t, adapter)

	_, err := e.ReconcileDomainRoleLeases("upstream-a", []DomainRoleLease{
		futureLease("bob", "admin", "domain1", "G-003"),
	})
	if !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("expected ErrLeaseConflict, got %v", err)
	}
	var conflictErr *LeaseConflictError
	if !errors.As(err, &conflictErr) || len(conflictErr.Conflicts) != 1 {
		t.Fatalf("expected one stored-contention conflict, got %v", err)
	}
	if conflictErr.Conflicts[0].Kind != LeaseConflictCorruptedRecord {
		t.Fatalf("expected corrupted record kind, got %q", conflictErr.Conflicts[0].Kind)
	}
	if adapter.totalAddCalls() != 0 || adapter.totalRemoveCalls() != 0 {
		t.Fatal("a conflict run must not persist anything")
	}
	if _, ok := findStoredLeaseRule(t, e, "upstream-a", "bob", "admin", "domain1"); ok {
		t.Fatal("no lease may be added while stored contention is pending")
	}
}
