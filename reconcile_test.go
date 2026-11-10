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
	"testing"

	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/util"
)

const reconcileModelPath = "examples/rbac_with_domains_model.conf"

// newReconcileEnforcer builds an enforcer backed by an empty in-memory
// transactional adapter that supports managed-policy ownership.
func newReconcileEnforcer(t *testing.T) (*Enforcer, *persist.MemoryAdapter) {
	t.Helper()
	adapter := persist.NewMemoryAdapter()
	e, err := NewEnforcer(reconcileModelPath, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	return e, adapter
}

// seedReconcileState creates a mixed starting state: console-managed rules and
// manual rules in domain1, an unrelated domain2, plus role inheritance rules.
func seedReconcileState(t *testing.T, e *Enforcer, adapter *persist.MemoryAdapter) [][]string {
	t.Helper()

	managed := [][]string{
		{"alice", "domain1", "data1", "read"},
		{"bob", "domain1", "data2", "write"},
	}
	manual := [][]string{
		{"carol", "domain1", "data3", "read"},
	}
	otherDomain := [][]string{
		{"dave", "domain2", "data9", "read"},
	}

	for _, rule := range append(append(append([][]string{}, managed...), manual...), otherDomain...) {
		if _, err := e.AddPolicy(rule); err != nil {
			t.Fatalf("failed to seed policy %v: %v", rule, err)
		}
	}
	grouping := [][]string{
		{"alice", "admin", "domain1"},
		{"bob", "admin", "domain2"},
	}
	for _, rule := range grouping {
		if _, err := e.AddGroupingPolicy(rule); err != nil {
			t.Fatalf("failed to seed grouping policy %v: %v", rule, err)
		}
	}

	if err := adapter.ReplaceManagedPolicy("domain1", managed); err != nil {
		t.Fatalf("failed to seed ownership: %v", err)
	}
	return managed
}

func domain1Rules(t *testing.T, e *Enforcer) [][]string {
	t.Helper()
	rules, err := e.GetFilteredNamedPolicy("p", 1, "domain1")
	if err != nil {
		t.Fatalf("failed to read domain1 rules: %v", err)
	}
	return rules
}

func adapterDomainRules(t *testing.T, adapter persist.Adapter, domain string) [][]string {
	t.Helper()
	m := model.NewModel()
	if err := m.LoadModel(reconcileModelPath); err != nil {
		t.Fatalf("failed to load model: %v", err)
	}
	if err := adapter.LoadPolicy(m); err != nil {
		t.Fatalf("failed to load policy from adapter: %v", err)
	}
	rules, err := m.GetFilteredPolicy("p", "p", 1, domain)
	if err != nil {
		t.Fatalf("failed to read adapter rules: %v", err)
	}
	return rules
}

func assertRuleSet(t *testing.T, name string, got, want [][]string) {
	t.Helper()
	if !util.SortedArray2DEquals(got, want) {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

// TestReconcileDomainPolicySnapshotAddUpdateRevoke covers the main flow:
// managed rules are added/changed/revoked while manual rules, other domains
// and role inheritance stay untouched, and storage converges with the model.
func TestReconcileDomainPolicySnapshotAddUpdateRevoke(t *testing.T) {
	e, adapter := newReconcileEnforcer(t)
	seedReconcileState(t, e, adapter)

	snapshot := DomainPolicySnapshot{
		Domain: "domain1",
		Rules: [][]string{
			{"alice", "domain1", "data1", "read"},  // unchanged
			{"alice", "domain1", "data1", "write"}, // new
			// bob/data2/write is dropped and must be revoked because it is owned
		},
	}
	if err := e.ReconcileDomainPolicySnapshot(snapshot); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	wantDomain1 := [][]string{
		{"alice", "domain1", "data1", "read"},
		{"alice", "domain1", "data1", "write"},
		{"carol", "domain1", "data3", "read"}, // manual rule preserved
	}
	assertRuleSet(t, "domain1 model rules", domain1Rules(t, e), wantDomain1)
	// Enforcement and per-domain reads see the same result.
	assertRuleSet(t, "domain1 adapter rules", adapterDomainRules(t, adapter, "domain1"), wantDomain1)

	// Other domains are untouched.
	assertRuleSet(t, "domain2 rules", adapterDomainRules(t, adapter, "domain2"),
		[][]string{{"dave", "domain2", "data9", "read"}})

	// Role inheritance is untouched in both model and storage.
	wantGrouping := [][]string{
		{"alice", "admin", "domain1"},
		{"bob", "admin", "domain2"},
	}
	gRules, err := e.GetGroupingPolicy()
	if err != nil {
		t.Fatalf("failed to read grouping policy: %v", err)
	}
	assertRuleSet(t, "grouping rules", gRules, wantGrouping)
	if roles := e.GetRolesForUserInDomain("alice", "domain1"); !util.SetEquals(roles, []string{"admin"}) {
		t.Errorf("alice roles = %v, want [admin]", roles)
	}

	// Ownership record now equals the snapshot.
	owned, err := adapter.LoadManagedPolicy("domain1")
	if err != nil {
		t.Fatalf("failed to load ownership: %v", err)
	}
	assertRuleSet(t, "ownership record", owned, snapshot.Rules)
}

// TestReconcileDomainPolicySnapshotIdempotent verifies that re-applying the
// same snapshot performs no mutation at all.
func TestReconcileDomainPolicySnapshotIdempotent(t *testing.T) {
	e, adapter := newReconcileEnforcer(t)
	seedReconcileState(t, e, adapter)

	snapshot := DomainPolicySnapshot{
		Domain: "domain1",
		Rules: [][]string{
			{"alice", "domain1", "data1", "read"},
			{"carol", "domain1", "data3", "read"}, // claim a manual rule
		},
	}
	if err := e.ReconcileDomainPolicySnapshot(snapshot); err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}

	var mutations []string
	adapter.ErrorHook = func(operation string) error {
		switch operation {
		case persist.MemoryOpAddPolicies, persist.MemoryOpRemovePolicies,
			persist.MemoryOpAddPolicy, persist.MemoryOpRemovePolicy,
			persist.MemoryOpReplaceManagedPolicy:
			mutations = append(mutations, operation)
		}
		return nil
	}

	beforeModel := domain1Rules(t, e)
	beforeAdapter := adapterDomainRules(t, adapter, "domain1")
	beforeOwned, _ := adapter.LoadManagedPolicy("domain1")

	if err := e.ReconcileDomainPolicySnapshot(snapshot); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	if len(mutations) != 0 {
		t.Errorf("idempotent reconcile issued mutations: %v", mutations)
	}
	assertRuleSet(t, "model after re-run", domain1Rules(t, e), beforeModel)
	assertRuleSet(t, "storage after re-run", adapterDomainRules(t, adapter, "domain1"), beforeAdapter)
	ownedAfter, _ := adapter.LoadManagedPolicy("domain1")
	assertRuleSet(t, "ownership after re-run", ownedAfter, beforeOwned)
}

// TestReconcileDomainPolicySnapshotInvalidSnapshot covers duplicate and
// conflicting snapshot items, bad arity and empty domains.
func TestReconcileDomainPolicySnapshotInvalidSnapshot(t *testing.T) {
	cases := []struct {
		name     string
		snapshot DomainPolicySnapshot
		want     error
	}{
		{
			name: "empty domain",
			snapshot: DomainPolicySnapshot{
				Domain: "",
				Rules:  [][]string{{"alice", "domain1", "data1", "read"}},
			},
			want: ErrReconcileInvalidSnapshot,
		},
		{
			name: "wrong arity",
			snapshot: DomainPolicySnapshot{
				Domain: "domain1",
				Rules:  [][]string{{"alice", "domain1", "data1"}},
			},
			want: ErrReconcileInvalidSnapshot,
		},
		{
			name: "rule from another domain",
			snapshot: DomainPolicySnapshot{
				Domain: "domain1",
				Rules:  [][]string{{"alice", "domain2", "data1", "read"}},
			},
			want: ErrReconcileConflictingRule,
		},
		{
			name: "duplicate rule",
			snapshot: DomainPolicySnapshot{
				Domain: "domain1",
				Rules: [][]string{
					{"alice", "domain1", "data1", "read"},
					{"alice", "domain1", "data1", "read"},
				},
			},
			want: ErrReconcileDuplicateRule,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, adapter := newReconcileEnforcer(t)
			seedReconcileState(t, e, adapter)

			beforeModel := domain1Rules(t, e)
			beforeAdapter := adapterDomainRules(t, adapter, "domain1")
			beforeOwned, _ := adapter.LoadManagedPolicy("domain1")

			err := e.ReconcileDomainPolicySnapshot(tc.snapshot)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got error %v, want %v", err, tc.want)
			}

			assertRuleSet(t, "model unchanged", domain1Rules(t, e), beforeModel)
			assertRuleSet(t, "storage unchanged", adapterDomainRules(t, adapter, "domain1"), beforeAdapter)
			ownedAfter, _ := adapter.LoadManagedPolicy("domain1")
			assertRuleSet(t, "ownership unchanged", ownedAfter, beforeOwned)
		})
	}
}

// TestReconcileDomainPolicySnapshotOwnershipCorrupt verifies that corrupted
// ownership records fail the reconciliation and leave the domain untouched.
func TestReconcileDomainPolicySnapshotOwnershipCorrupt(t *testing.T) {
	corruptCases := []struct {
		name  string
		owned [][]string
	}{
		{
			name:  "wrong arity",
			owned: [][]string{{"alice", "domain1"}},
		},
		{
			name:  "wrong domain",
			owned: [][]string{{"alice", "domain2", "data1", "read"}},
		},
		{
			name: "duplicate entries",
			owned: [][]string{
				{"alice", "domain1", "data1", "read"},
				{"alice", "domain1", "data1", "read"},
			},
		},
	}

	for _, tc := range corruptCases {
		t.Run(tc.name, func(t *testing.T) {
			e, adapter := newReconcileEnforcer(t)
			seedReconcileState(t, e, adapter)
			if err := adapter.ReplaceManagedPolicy("domain1", tc.owned); err != nil {
				t.Fatalf("failed to corrupt ownership: %v", err)
			}

			beforeModel := domain1Rules(t, e)
			snapshot := DomainPolicySnapshot{
				Domain: "domain1",
				Rules:  [][]string{{"alice", "domain1", "data1", "read"}},
			}
			err := e.ReconcileDomainPolicySnapshot(snapshot)
			if !errors.Is(err, ErrReconcileOwnershipCorrupt) {
				t.Fatalf("got error %v, want ErrReconcileOwnershipCorrupt", err)
			}
			assertRuleSet(t, "model unchanged", domain1Rules(t, e), beforeModel)
			assertRuleSet(t, "storage unchanged", adapterDomainRules(t, adapter, "domain1"), beforeModel)
		})
	}
}

// TestReconcileDomainPolicySnapshotPersistenceFailure verifies that a storage
// failure rolls the whole reconciliation back, including the ownership write.
func TestReconcileDomainPolicySnapshotPersistenceFailure(t *testing.T) {
	e, adapter := newReconcileEnforcer(t)
	seed := seedReconcileState(t, e, adapter)

	adapter.ErrorHook = func(operation string) error {
		if operation == persist.MemoryOpAddPolicies {
			return errors.New("simulated storage outage")
		}
		return nil
	}

	beforeModel := domain1Rules(t, e)
	snapshot := DomainPolicySnapshot{
		Domain: "domain1",
		Rules: [][]string{
			{"alice", "domain1", "data1", "read"},
			{"alice", "domain1", "data1", "write"},
		},
	}
	if err := e.ReconcileDomainPolicySnapshot(snapshot); err == nil {
		t.Fatal("expected persistence failure, got nil")
	}

	assertRuleSet(t, "model unchanged after failure", domain1Rules(t, e), beforeModel)
	assertRuleSet(t, "storage unchanged after failure", adapterDomainRules(t, adapter, "domain1"), beforeModel)
	owned, _ := adapter.LoadManagedPolicy("domain1")
	assertRuleSet(t, "ownership unchanged after failure", owned, seed)

	// The rolled-back transaction must not poison later reconciliations.
	adapter.ErrorHook = nil
	if err := e.ReconcileDomainPolicySnapshot(snapshot); err != nil {
		t.Fatalf("reconcile after rollback failed: %v", err)
	}
	assertRuleSet(t, "model converged after retry", domain1Rules(t, e),
		[][]string{
			{"alice", "domain1", "data1", "read"},
			{"alice", "domain1", "data1", "write"},
			{"carol", "domain1", "data3", "read"},
		})
}

// TestReconcileDomainPolicySnapshotCrashBeforeCommit simulates a process exit
// before commit: the transaction is never published. A fresh enforcer loading
// the same storage re-runs the reconciliation and converges to the snapshot.
func TestReconcileDomainPolicySnapshotCrashBeforeCommit(t *testing.T) {
	e, adapter := newReconcileEnforcer(t)
	seedReconcileState(t, e, adapter)

	snapshot := DomainPolicySnapshot{
		Domain: "domain1",
		Rules: [][]string{
			{"alice", "domain1", "data1", "read"},
			{"alice", "domain1", "data1", "write"},
		},
	}

	// Fail the commit itself: policy and ownership writes live only in the
	// discarded transaction shadow.
	adapter.ErrorHook = func(operation string) error {
		if operation == persist.MemoryOpTransactionCommit {
			return errors.New("simulated crash before commit")
		}
		return nil
	}
	if err := e.ReconcileDomainPolicySnapshot(snapshot); err == nil {
		t.Fatal("expected commit failure, got nil")
	}
	adapter.ErrorHook = nil

	// "Restart": a brand new enforcer reloads the untouched storage.
	restarted, err := NewEnforcer(reconcileModelPath, adapter)
	if err != nil {
		t.Fatalf("failed to restart enforcer: %v", err)
	}
	if err := restarted.ReconcileDomainPolicySnapshot(snapshot); err != nil {
		t.Fatalf("reconcile after restart failed: %v", err)
	}

	want := [][]string{
		{"alice", "domain1", "data1", "read"},
		{"alice", "domain1", "data1", "write"},
		{"carol", "domain1", "data3", "read"},
	}
	assertRuleSet(t, "restarted model converged", domain1Rules(t, restarted), want)
	assertRuleSet(t, "restarted storage converged", adapterDomainRules(t, adapter, "domain1"), want)
	owned, _ := adapter.LoadManagedPolicy("domain1")
	assertRuleSet(t, "restarted ownership converged", owned, snapshot.Rules)

	// Re-running once more is a no-op and yields the exact same state.
	if err := restarted.ReconcileDomainPolicySnapshot(snapshot); err != nil {
		t.Fatalf("idempotent re-run after restart failed: %v", err)
	}
	assertRuleSet(t, "stable after second run", domain1Rules(t, restarted), want)
}

// TestReconcileDomainPolicySnapshotEmptySnapshot revokes every owned rule but
// keeps manual rules in place.
func TestReconcileDomainPolicySnapshotEmptySnapshot(t *testing.T) {
	e, adapter := newReconcileEnforcer(t)
	seedReconcileState(t, e, adapter)

	snapshot := DomainPolicySnapshot{Domain: "domain1"}
	if err := e.ReconcileDomainPolicySnapshot(snapshot); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	want := [][]string{{"carol", "domain1", "data3", "read"}}
	assertRuleSet(t, "model keeps only manual rules", domain1Rules(t, e), want)
	assertRuleSet(t, "storage keeps only manual rules", adapterDomainRules(t, adapter, "domain1"), want)
	owned, _ := adapter.LoadManagedPolicy("domain1")
	if len(owned) != 0 {
		t.Errorf("ownership record should be cleared, got %v", owned)
	}
	assertRuleSet(t, "domain2 untouched", adapterDomainRules(t, adapter, "domain2"),
		[][]string{{"dave", "domain2", "data9", "read"}})
}

// TestReconcileDomainPolicySnapshotClaimsThenRevokesManualRule verifies that a
// manual rule appearing in a snapshot becomes owned: a later snapshot without
// it is allowed to revoke the rule.
func TestReconcileDomainPolicySnapshotClaimsThenRevokesManualRule(t *testing.T) {
	e, adapter := newReconcileEnforcer(t)
	seedReconcileState(t, e, adapter)

	claim := DomainPolicySnapshot{
		Domain: "domain1",
		Rules:  [][]string{{"carol", "domain1", "data3", "read"}},
	}
	if err := e.ReconcileDomainPolicySnapshot(claim); err != nil {
		t.Fatalf("claim reconcile failed: %v", err)
	}
	owned, _ := adapter.LoadManagedPolicy("domain1")
	assertRuleSet(t, "manual rule claimed", owned, claim.Rules)

	revoke := DomainPolicySnapshot{
		Domain: "domain1",
		Rules:  [][]string{{"alice", "domain1", "data1", "read"}},
	}
	if err := e.ReconcileDomainPolicySnapshot(revoke); err != nil {
		t.Fatalf("revoke reconcile failed: %v", err)
	}
	hasCarol, err := e.HasPolicy("carol", "domain1", "data3", "read")
	if err != nil {
		t.Fatalf("HasPolicy failed: %v", err)
	}
	if hasCarol {
		t.Error("claimed rule should have been revoked when it left the snapshot")
	}
	// The originally managed alice rule survives because it is still desired.
	hasAlice, err := e.HasPolicy("alice", "domain1", "data1", "read")
	if err != nil {
		t.Fatalf("HasPolicy failed: %v", err)
	}
	if !hasAlice {
		t.Error("desired managed rule should remain")
	}
}

// TestReconcileDomainPolicySnapshotEnforcementConsistency verifies that
// enforcement decisions and per-domain rule reads reflect the same state.
func TestReconcileDomainPolicySnapshotEnforcementConsistency(t *testing.T) {
	e, adapter := newReconcileEnforcer(t)
	seedReconcileState(t, e, adapter)

	snapshot := DomainPolicySnapshot{
		Domain: "domain1",
		Rules: [][]string{
			{"alice", "domain1", "data1", "read"},
			{"alice", "domain1", "data1", "write"},
		},
	}
	if err := e.ReconcileDomainPolicySnapshot(snapshot); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	cases := []struct {
		request []interface{}
		want    bool
		reason  string
	}{
		{[]interface{}{"alice", "domain1", "data1", "read"}, true, "retained managed rule"},
		{[]interface{}{"alice", "domain1", "data1", "write"}, true, "newly added rule"},
		{[]interface{}{"bob", "domain1", "data2", "write"}, false, "revoked managed rule"},
		{[]interface{}{"carol", "domain1", "data3", "read"}, true, "manual rule preserved"},
		{[]interface{}{"dave", "domain2", "data9", "read"}, true, "other domain untouched"},
	}
	for _, tc := range cases {
		got, err := e.Enforce(tc.request...)
		if err != nil {
			t.Fatalf("Enforce(%v) failed: %v", tc.request, err)
		}
		if got != tc.want {
			t.Errorf("Enforce(%v) = %v (%s), want %v", tc.request, got, tc.reason, tc.want)
		}
	}

	// The per-domain read view matches both the model and the storage.
	assertRuleSet(t, "read view matches storage",
		domain1Rules(t, e), adapterDomainRules(t, adapter, "domain1"))
}

// TestReconcileDomainPolicySnapshotUnsupportedAdapter verifies the capability
// checks for adapters without transaction or ownership support.
func TestReconcileDomainPolicySnapshotUnsupportedAdapter(t *testing.T) {
	// Non-transactional adapter.
	fileE, err := NewEnforcer(reconcileModelPath, fileadapter.NewAdapter(""))
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	err = fileE.ReconcileDomainPolicySnapshot(DomainPolicySnapshot{Domain: "domain1"})
	if !errors.Is(err, ErrReconcileUnsupportedAdapter) {
		t.Fatalf("non-transactional adapter: got %v, want ErrReconcileUnsupportedAdapter", err)
	}

	// Transactional adapter without managed-policy ownership support.
	mockE, err := NewEnforcer(reconcileModelPath, NewMockTransactionalAdapter())
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	err = mockE.ReconcileDomainPolicySnapshot(DomainPolicySnapshot{Domain: "domain1"})
	if !errors.Is(err, ErrReconcileUnsupportedAdapter) {
		t.Fatalf("mock adapter: got %v, want ErrReconcileUnsupportedAdapter", err)
	}
}

// TestReconcileDomainPolicySnapshotReloadConverges verifies that an enforcer
// rebuilt from the committed storage sees an already converged state.
func TestReconcileDomainPolicySnapshotReloadConverges(t *testing.T) {
	e, adapter := newReconcileEnforcer(t)
	seedReconcileState(t, e, adapter)

	snapshot := DomainPolicySnapshot{
		Domain: "domain1",
		Rules: [][]string{
			{"alice", "domain1", "data1", "read"},
			{"alice", "domain1", "data1", "write"},
		},
	}
	if err := e.ReconcileDomainPolicySnapshot(snapshot); err != nil {
		t.Fatalf("reconcile failed: %v", err)
	}

	reloaded, err := NewEnforcer(reconcileModelPath, adapter)
	if err != nil {
		t.Fatalf("failed to reload enforcer: %v", err)
	}
	assertRuleSet(t, "reloaded domain1 rules", domain1Rules(t, reloaded),
		[][]string{
			{"alice", "domain1", "data1", "read"},
			{"alice", "domain1", "data1", "write"},
			{"carol", "domain1", "data3", "read"},
		})
	if err := reloaded.ReconcileDomainPolicySnapshot(snapshot); err != nil {
		t.Fatalf("reconcile after reload failed: %v", err)
	}
}
