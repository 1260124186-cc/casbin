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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

const testQuorumModel = "examples/rbac_model.conf"

// quorumMemoryAdapter is an in-memory adapter that keeps real rule state so
// quorum replay and repair can be tested end to end. A failing operation is
// applied first and then returns an error, which models a process dying after
// the storage write but before the durable progress marker was updated.
type quorumMemoryAdapter struct {
	name        string
	mu          sync.Mutex
	rules       map[string][][]string
	failKinds   map[string]bool
	onWrite     func()
	addCalls    int
	removeCalls int
	updateCalls int
	loadCalls   int
}

func newQuorumMemoryAdapter(name string) *quorumMemoryAdapter {
	return &quorumMemoryAdapter{
		name:      name,
		rules:     map[string][][]string{},
		failKinds: map[string]bool{},
	}
}

func quorumRuleKey(rule []string) string {
	return strings.Join(rule, "\x00")
}

func quorumStoreKey(sec string, ptype string) string {
	return sec + "\x00" + ptype
}

func (a *quorumMemoryAdapter) fail(kind string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failKinds[kind] = true
}

func (a *quorumMemoryAdapter) heal() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failKinds = map[string]bool{}
}

// reset wipes every stored rule and failure hook, modeling a rebuilt backend
// while keeping the same adapter instance inside the quorum.
func (a *quorumMemoryAdapter) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = map[string][][]string{}
	a.failKinds = map[string]bool{}
	a.onWrite = nil
}

func (a *quorumMemoryAdapter) contains(sec string, ptype string, rule []string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, existing := range a.rules[quorumStoreKey(sec, ptype)] {
		if quorumRuleKey(existing) == quorumRuleKey(rule) {
			return true
		}
	}
	return false
}

func (a *quorumMemoryAdapter) ruleCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	total := 0
	for _, rules := range a.rules {
		total += len(rules)
	}
	return total
}

// LoadPolicy implements persist.Adapter.
func (a *quorumMemoryAdapter) LoadPolicy(m model.Model) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.loadCalls++
	if a.failKinds["load"] {
		return fmt.Errorf("backend %s is unreachable", a.name)
	}
	for key, rules := range a.rules {
		parts := strings.SplitN(key, "\x00", 2)
		for _, rule := range rules {
			if err := m.AddPolicy(parts[0], parts[1], append([]string(nil), rule...)); err != nil {
				return err
			}
		}
	}
	return nil
}

// SavePolicy implements persist.Adapter.
func (a *quorumMemoryAdapter) SavePolicy(m model.Model) error {
	return nil
}

// AddPolicy implements persist.Adapter.
func (a *quorumMemoryAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.AddPolicies(sec, ptype, [][]string{rule})
}

// AddPolicies implements persist.BatchAdapter.
func (a *quorumMemoryAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.addCalls++
	if a.onWrite != nil {
		a.onWrite()
	}
	key := quorumStoreKey(sec, ptype)
	existing := map[string]bool{}
	for _, rule := range a.rules[key] {
		existing[quorumRuleKey(rule)] = true
	}
	for _, rule := range rules {
		if !existing[quorumRuleKey(rule)] {
			a.rules[key] = append(a.rules[key], append([]string(nil), rule...))
			existing[quorumRuleKey(rule)] = true
		}
	}
	if a.failKinds["add"] {
		return fmt.Errorf("backend %s failed after writing add", a.name)
	}
	return nil
}

// RemovePolicy implements persist.Adapter.
func (a *quorumMemoryAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicies(sec, ptype, [][]string{rule})
}

// RemovePolicies implements persist.BatchAdapter.
func (a *quorumMemoryAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.removeCalls++
	if a.onWrite != nil {
		a.onWrite()
	}
	key := quorumStoreKey(sec, ptype)
	removed := map[string]bool{}
	for _, rule := range rules {
		removed[quorumRuleKey(rule)] = true
	}
	kept := a.rules[key][:0]
	for _, rule := range a.rules[key] {
		if !removed[quorumRuleKey(rule)] {
			kept = append(kept, rule)
		}
	}
	a.rules[key] = kept
	if a.failKinds["remove"] {
		return fmt.Errorf("backend %s failed after writing remove", a.name)
	}
	return nil
}

// RemoveFilteredPolicy implements persist.Adapter.
func (a *quorumMemoryAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := quorumStoreKey(sec, ptype)
	kept := a.rules[key][:0]
	for _, rule := range a.rules[key] {
		matched := true
		for i, value := range fieldValues {
			if value != "" && rule[fieldIndex+i] != value {
				matched = false
				break
			}
		}
		if !matched {
			kept = append(kept, rule)
		}
	}
	a.rules[key] = kept
	return nil
}

// UpdatePolicy implements persist.UpdatableAdapter.
func (a *quorumMemoryAdapter) UpdatePolicy(sec string, ptype string, oldRule []string, newRule []string) error {
	return a.UpdatePolicies(sec, ptype, [][]string{oldRule}, [][]string{newRule})
}

// UpdatePolicies implements persist.UpdatableAdapter.
func (a *quorumMemoryAdapter) UpdatePolicies(sec string, ptype string, oldRules [][]string, newRules [][]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.updateCalls++
	if a.onWrite != nil {
		a.onWrite()
	}
	key := quorumStoreKey(sec, ptype)
	for i, oldRule := range oldRules {
		for j, rule := range a.rules[key] {
			if quorumRuleKey(rule) == quorumRuleKey(oldRule) {
				a.rules[key][j] = append([]string(nil), newRules[i]...)
				break
			}
		}
	}
	if a.failKinds["update"] {
		return fmt.Errorf("backend %s failed after writing update", a.name)
	}
	return nil
}

// newTestBackends builds the online, mirror and disaster recovery backends.
func newTestBackends() (map[string]*quorumMemoryAdapter, []QuorumBackend) {
	names := []string{"online", "mirror", "dr"}
	adapters := map[string]*quorumMemoryAdapter{}
	backends := make([]QuorumBackend, 0, len(names))
	for _, name := range names {
		adapter := newQuorumMemoryAdapter(name)
		adapters[name] = adapter
		backends = append(backends, QuorumBackend{Name: name, Adapter: adapter})
	}
	return adapters, backends
}

// newTestQuorum wires a quorum manager to a fresh memory store.
func newTestQuorum(t *testing.T, backends []QuorumBackend) (*PolicyQuorum, CommitStore) {
	t.Helper()
	store := NewMemoryCommitStore()
	quorum, err := NewPolicyQuorum(testQuorumModel, backends, store)
	if err != nil {
		t.Fatalf("failed to create policy quorum: %v", err)
	}
	return quorum, store
}

// reopenQuorum simulates a process restart while store and adapters survive.
func reopenQuorum(t *testing.T, store CommitStore, backends []QuorumBackend) *PolicyQuorum {
	t.Helper()
	quorum, err := NewPolicyQuorum(testQuorumModel, backends, store)
	if err != nil {
		t.Fatalf("failed to reopen policy quorum: %v", err)
	}
	return quorum
}

func backendView(status *QuorumStatus, name string) BackendStatusView {
	for _, view := range status.Backends {
		if view.Name == name {
			return view
		}
	}
	return BackendStatusView{}
}

// A commit reaching the quorum advances the active version and lands on
// every backend, while the status snapshot exposes each applied version.
func TestPolicyQuorumCommitReachesQuorum(t *testing.T) {
	adapters, backends := newTestBackends()
	quorum, _ := newTestQuorum(t, backends)
	ctx := context.Background()

	operations := []persist.PolicyOperation{
		NewAddPolicyOperation("p", "p", [][]string{{"alice", "data1", "read"}}),
		NewAddPolicyOperation("g", "g", [][]string{{"alice", "admin"}}),
	}
	commit, err := quorum.CommitPolicyQuorum(ctx, operations)
	if err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	if commit.Version != 1 || commit.Status != CommitCommitted {
		t.Fatalf("unexpected commit state: version=%d status=%d", commit.Version, commit.Status)
	}
	if quorum.ActiveVersion() != 1 || quorum.Quorum() != 2 {
		t.Fatalf("active version should be 1 and quorum 2, got %d/%d", quorum.ActiveVersion(), quorum.Quorum())
	}

	status, err := quorum.Status(ctx)
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	for _, name := range []string{"online", "mirror", "dr"} {
		view := backendView(status, name)
		if view.AppliedVersion != 1 || !view.UpToDate {
			t.Fatalf("backend %s should be at version 1 and up to date: %+v", name, view)
		}
		if !adapters[name].contains("p", "p", []string{"alice", "data1", "read"}) {
			t.Fatalf("backend %s missed the policy rule", name)
		}
	}

	allowed, err := quorum.Enforce("alice", "data1", "read")
	if err != nil || !allowed {
		t.Fatalf("grouping policy should grant alice read access, got %v (err %v)", allowed, err)
	}
}

// Without the quorum the active version stays put and the pending record
// retains per-backend diagnostics; recovery completes it once backends heal.
func TestPolicyQuorumFailureThenRecoverCompletes(t *testing.T) {
	adapters, backends := newTestBackends()
	quorum, store := newTestQuorum(t, backends)
	ctx := context.Background()
	adapters["mirror"].fail("add")
	adapters["dr"].fail("add")

	operations := []persist.PolicyOperation{
		NewAddPolicyOperation("p", "p", [][]string{{"bob", "data2", "write"}}),
	}
	_, err := quorum.CommitPolicyQuorum(ctx, operations)
	if !errors.Is(err, ErrQuorumNotReached) {
		t.Fatalf("expected ErrQuorumNotReached, got %v", err)
	}
	if quorum.ActiveVersion() != 0 {
		t.Fatalf("active version must stay 0 without quorum, got %d", quorum.ActiveVersion())
	}
	if ok, _ := quorum.Enforcer().HasPolicy("bob", "data2", "write"); ok {
		t.Fatal("the enforcer must not serve rules from an uncommitted version")
	}
	status, _ := quorum.Status(ctx)
	if status.Pending == nil || status.Pending.Version != 1 {
		t.Fatal("a pending commit with diagnostic state should be visible")
	}
	if view := backendView(status, "online"); view.AppliedVersion != 1 || view.UpToDate {
		t.Fatalf("online applied v1 while active stays v0: %+v", view)
	}

	// Restart with healed backends: the same record finishes the commit.
	adapters["mirror"].heal()
	adapters["dr"].heal()
	reopened := reopenQuorum(t, store, backends)
	if err := reopened.Recover(ctx); err != nil {
		t.Fatalf("recover failed: %v", err)
	}
	if reopened.ActiveVersion() != 1 {
		t.Fatalf("recovered active version should be 1, got %d", reopened.ActiveVersion())
	}
	for _, name := range []string{"online", "mirror", "dr"} {
		if !adapters[name].contains("p", "p", []string{"bob", "data2", "write"}) {
			t.Fatalf("backend %s should contain the committed rule", name)
		}
	}
	allowed, _ := reopened.Enforce("bob", "data2", "write")
	if !allowed {
		t.Fatal("the recovered enforcer should serve the committed rule")
	}
}

// A backend that wrote rules but died before recording its marker must not
// duplicate them when the commit is replayed after restart.
func TestPolicyQuorumCrashReplayIsIdempotent(t *testing.T) {
	adapters, backends := newTestBackends()
	quorum, store := newTestQuorum(t, backends)
	ctx := context.Background()
	adapters["mirror"].fail("add")
	adapters["dr"].fail("add")

	operations := []persist.PolicyOperation{
		NewAddPolicyOperation("p", "p", [][]string{{"carol", "data3", "read"}}),
	}
	_, err := quorum.CommitPolicyQuorum(ctx, operations)
	if !errors.Is(err, ErrQuorumNotReached) {
		t.Fatalf("expected quorum failure, got %v", err)
	}
	// mirror and dr stored the rule but never got their markers.
	for _, name := range []string{"mirror", "dr"} {
		if !adapters[name].contains("p", "p", []string{"carol", "data3", "read"}) {
			t.Fatalf("backend %s should hold the written rule", name)
		}
	}

	adapters["mirror"].heal()
	adapters["dr"].heal()
	reopened := reopenQuorum(t, store, backends)
	if err := reopened.Recover(ctx); err != nil {
		t.Fatalf("recover failed: %v", err)
	}
	for _, name := range []string{"online", "mirror", "dr"} {
		if adapters[name].ruleCount() != 1 {
			t.Fatalf("backend %s replayed the rule twice, count=%d", name, adapters[name].ruleCount())
		}
		state, _ := store.GetBackendState(ctx, name)
		if state == nil || state.AppliedVersion != 1 {
			t.Fatalf("backend %s marker should be at v1, got %+v", name, state)
		}
	}

	// Re-running recover on a converged cluster performs no writes at all.
	before := adapters["online"].addCalls
	if err := reopened.Recover(ctx); err != nil {
		t.Fatalf("second recover failed: %v", err)
	}
	if adapters["online"].addCalls != before {
		t.Fatal("replaying an already applied commit must not write again")
	}
}

// When the quorum can never be reached, recovery rolls every partial backend
// back to the old version and aborts the record.
func TestPolicyQuorumRecoverAbortsUnreachableCommit(t *testing.T) {
	adapters, backends := newTestBackends()
	quorum, store := newTestQuorum(t, backends)
	ctx := context.Background()
	adapters["mirror"].fail("load")
	adapters["dr"].fail("load")

	operations := []persist.PolicyOperation{
		NewAddPolicyOperation("p", "p", [][]string{{"dave", "data4", "read"}}),
	}
	_, err := quorum.CommitPolicyQuorum(ctx, operations)
	if !errors.Is(err, ErrQuorumNotReached) {
		t.Fatalf("expected quorum failure, got %v", err)
	}

	// Restart while mirror and dr remain unreachable: abort and roll back.
	reopened := reopenQuorum(t, store, backends)
	if recoverErr := reopened.Recover(ctx); recoverErr != nil {
		t.Fatalf("recover failed: %v", recoverErr)
	}
	if reopened.ActiveVersion() != 0 {
		t.Fatalf("aborted commit must not advance the active version, got %d", reopened.ActiveVersion())
	}
	if adapters["online"].ruleCount() != 0 {
		t.Fatal("the partial backend must be rolled back to the old version")
	}
	record, err := store.GetCommitByVersion(ctx, 1)
	if err != nil {
		t.Fatalf("get commit failed: %v", err)
	}
	if record == nil || record.Status != CommitAborted || record.AbortReason == "" {
		t.Fatalf("commit should be aborted with a reason, got %+v", record)
	}
	state, _ := store.GetBackendState(ctx, "online")
	if state == nil || state.AppliedVersion != 0 {
		t.Fatalf("online marker should return to v0, got %+v", state)
	}
}

// Repair replays committed records onto a lagging backend, and doing it again
// is a no-op because every marker is durable.
func TestPolicyQuorumRepairCatchesUpLaggard(t *testing.T) {
	adapters, backends := newTestBackends()
	quorum, store := newTestQuorum(t, backends)
	ctx := context.Background()

	operations := []persist.PolicyOperation{
		NewAddPolicyOperation("p", "p", [][]string{{"erin", "data5", "read"}}),
	}
	if _, err := quorum.CommitPolicyQuorum(ctx, operations); err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	// Simulate a rebuilt, empty disaster recovery backend.
	adapters["dr"].reset()
	if err := store.SaveBackendState(ctx, &BackendState{Name: "dr"}); err != nil {
		t.Fatalf("reset dr marker failed: %v", err)
	}

	report, err := quorum.Repair(ctx)
	if err != nil {
		t.Fatalf("repair failed: %v", err)
	}
	if len(report.RemainingLagging) != 0 {
		t.Fatalf("all backends should converge, lagging=%v", report.RemainingLagging)
	}
	if !adapters["dr"].contains("p", "p", []string{"erin", "data5", "read"}) {
		t.Fatal("repair should replay the committed rule onto dr")
	}
	for _, result := range report.Results {
		if result.Name == "dr" && len(result.ReplayedCommits) != 1 {
			t.Fatalf("dr should replay one commit, got %+v", result)
		}
	}

	second, err := quorum.Repair(ctx)
	if err != nil {
		t.Fatalf("second repair failed: %v", err)
	}
	for _, result := range second.Results {
		if len(result.ReplayedCommits) != 0 {
			t.Fatalf("re-running repair must be a no-op, got %+v", result)
		}
	}
}

// Repair stops at cancellation boundaries and resumes on the next run without
// re-applying commits that were already marked durable.
func TestPolicyQuorumRepairInterruptAndResume(t *testing.T) {
	adapters, backends := newTestBackends()
	quorum, store := newTestQuorum(t, backends)
	ctx := context.Background()

	commits := [][]string{
		{"frank", "data6", "read"},
		{"grace", "data7", "write"},
		{"heidi", "data8", "read"},
	}
	for i, rule := range commits {
		_, err := quorum.CommitPolicyQuorum(ctx, []persist.PolicyOperation{
			NewAddPolicyOperation("p", "p", [][]string{rule}),
		})
		if err != nil {
			t.Fatalf("commit %d failed: %v", i+1, err)
		}
	}

	// Reset dr to an empty backend lagging at v0.
	adapters["dr"].reset()
	if err := store.SaveBackendState(ctx, &BackendState{Name: "dr"}); err != nil {
		t.Fatalf("reset dr marker failed: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	adapters["dr"].onWrite = func() { cancel() }
	report, err := quorum.Repair(runCtx)
	if !errors.Is(err, context.Canceled) || !report.Interrupted {
		t.Fatalf("interrupted repair should return context.Canceled, got report=%+v err=%v", report, err)
	}
	state, _ := store.GetBackendState(ctx, "dr")
	if state == nil || state.AppliedVersion != 1 {
		t.Fatalf("dr should durably keep v1 after interruption, got %+v", state)
	}

	// Re-run with a healthy context: repair resumes from v2, never replays v1.
	adapters["dr"].onWrite = nil
	report, err = quorum.Repair(ctx)
	if err != nil {
		t.Fatalf("resumed repair failed: %v", err)
	}
	for _, result := range report.Results {
		if result.Name == "dr" {
			if len(result.ReplayedCommits) != 2 || result.ReplayedCommits[0] != 2 {
				t.Fatalf("dr should resume with v2 and v3, got %+v", result)
			}
		}
	}
	for _, rule := range commits {
		if !adapters["dr"].contains("p", "p", rule) {
			t.Fatalf("dr missed rule %v after resume", rule)
		}
	}
	if adapters["dr"].ruleCount() != len(commits) {
		t.Fatalf("dr should hold exactly %d rules, got %d", len(commits), adapters["dr"].ruleCount())
	}
}

// Update and remove operations round-trip through the quorum to every backend.
func TestPolicyQuorumUpdateAndRemoveOperations(t *testing.T) {
	_, backends := newTestBackends()
	quorum, _ := newTestQuorum(t, backends)
	ctx := context.Background()

	if _, err := quorum.CommitPolicyQuorum(ctx, []persist.PolicyOperation{
		NewAddPolicyOperation("p", "p", [][]string{{"ivan", "data9", "read"}}),
	}); err != nil {
		t.Fatalf("add commit failed: %v", err)
	}
	if _, err := quorum.CommitPolicyQuorum(ctx, []persist.PolicyOperation{
		NewUpdatePolicyOperation("p", "p",
			[][]string{{"ivan", "data9", "read"}},
			[][]string{{"ivan", "data9", "write"}}),
	}); err != nil {
		t.Fatalf("update commit failed: %v", err)
	}
	if _, err := quorum.CommitPolicyQuorum(ctx, []persist.PolicyOperation{
		NewRemovePolicyOperation("p", "p", [][]string{{"ivan", "data9", "write"}}),
	}); err != nil {
		t.Fatalf("remove commit failed: %v", err)
	}

	if quorum.ActiveVersion() != 3 {
		t.Fatalf("active version should be 3, got %d", quorum.ActiveVersion())
	}
	if ok, _ := quorum.Enforcer().HasPolicy("ivan", "data9", "write"); ok {
		t.Fatal("removed rule must not remain in the active model")
	}
	status, _ := quorum.Status(ctx)
	for _, view := range status.Backends {
		if view.AppliedVersion != 3 || !view.UpToDate {
			t.Fatalf("backend %s should converge at v3, got %+v", view.Name, view)
		}
	}
}

// A lost progress marker must not cause duplicate writes: the backend's own
// rules are diffed before any adapter write is issued.
func TestPolicyQuorumLostMarkerReplaysWithoutDuplicateWrite(t *testing.T) {
	adapters, backends := newTestBackends()
	quorum, store := newTestQuorum(t, backends)
	ctx := context.Background()
	rule := []string{"judy", "data10", "read"}

	commit, err := quorum.CommitPolicyQuorum(ctx, []persist.PolicyOperation{
		NewAddPolicyOperation("p", "p", [][]string{rule}),
	})
	if err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	// Lose the marker while the rules stay in the backend.
	if err := store.SaveBackendState(ctx, &BackendState{Name: "online"}); err != nil {
		t.Fatalf("reset marker failed: %v", err)
	}
	backend := backends[0]
	before := adapters["online"].addCalls
	if err := quorum.applyCommitToBackend(ctx, &backend, commit); err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	if adapters["online"].addCalls != before {
		t.Fatal("replay with existing rules must not issue another adapter write")
	}
	if adapters["online"].ruleCount() != 1 {
		t.Fatalf("rule must remain unique, count=%d", adapters["online"].ruleCount())
	}
}

// The file-backed store survives being recreated, simulating a real restart.
func TestFileCommitStoreSurvivesRestart(t *testing.T) {
	dir, err := os.MkdirTemp("", "casbin-quorum-")
	if err != nil {
		t.Fatalf("temp dir failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	storePath := filepath.Join(dir, "commits.json")

	store, err := NewFileCommitStore(storePath)
	if err != nil {
		t.Fatalf("file store failed: %v", err)
	}
	adapters, backends := newTestBackends()
	quorum, err := NewPolicyQuorum(testQuorumModel, backends, store)
	if err != nil {
		t.Fatalf("quorum failed: %v", err)
	}
	if _, commitErr := quorum.CommitPolicyQuorum(context.Background(), []persist.PolicyOperation{
		NewAddPolicyOperation("p", "p", [][]string{{"karl", "data11", "read"}}),
	}); commitErr != nil {
		t.Fatalf("commit failed: %v", commitErr)
	}

	reopenedStore, err := NewFileCommitStore(storePath)
	if err != nil {
		t.Fatalf("reopen store failed: %v", err)
	}
	active, err := reopenedStore.GetActiveVersion(context.Background())
	if err != nil {
		t.Fatalf("load active version failed: %v", err)
	}
	if active != 1 {
		t.Fatalf("durable active version should be 1, got %d", active)
	}
	reopened := reopenQuorum(t, reopenedStore, backends)
	if recoverErr := reopened.Recover(context.Background()); recoverErr != nil {
		t.Fatalf("recover with file store failed: %v", recoverErr)
	}
	if !adapters["online"].contains("p", "p", []string{"karl", "data11", "read"}) {
		t.Fatal("committed rules should remain available after a durable restart")
	}
}

// Invalid quorum configurations are rejected at construction time.
func TestPolicyQuorumRejectsInvalidConfig(t *testing.T) {
	store := NewMemoryCommitStore()
	if _, err := NewPolicyQuorum(testQuorumModel, nil, store); !errors.Is(err, ErrInvalidQuorumConfig) {
		t.Fatalf("expected ErrInvalidQuorumConfig for no backends, got %v", err)
	}
	_, backends := newTestBackends()
	backends[1].Name = backends[0].Name
	if _, err := NewPolicyQuorum(testQuorumModel, backends, store); !errors.Is(err, ErrInvalidQuorumConfig) {
		t.Fatalf("expected ErrInvalidQuorumConfig for duplicate names, got %v", err)
	}
	if _, err := NewPolicyQuorum(testQuorumModel, []QuorumBackend{{Name: "x"}}, store); !errors.Is(err, ErrInvalidQuorumConfig) {
		t.Fatalf("expected ErrInvalidQuorumConfig for nil adapter, got %v", err)
	}
	if _, err := NewPolicyQuorum(testQuorumModel, backends, nil); err == nil {
		t.Fatal("a nil store should be rejected")
	}
}

// A second commit is refused while the previous one is still pending.
func TestPolicyQuorumRejectsCommitWhilePending(t *testing.T) {
	adapters, backends := newTestBackends()
	quorum, _ := newTestQuorum(t, backends)
	ctx := context.Background()
	adapters["mirror"].fail("add")
	adapters["dr"].fail("add")

	if _, err := quorum.CommitPolicyQuorum(ctx, []persist.PolicyOperation{
		NewAddPolicyOperation("p", "p", [][]string{{"lisa", "data12", "read"}}),
	}); !errors.Is(err, ErrQuorumNotReached) {
		t.Fatalf("expected quorum failure, got %v", err)
	}
	_, err := quorum.CommitPolicyQuorum(ctx, []persist.PolicyOperation{
		NewAddPolicyOperation("p", "p", [][]string{{"mallory", "data13", "read"}}),
	})
	if !errors.Is(err, ErrPendingCommitExists) {
		t.Fatalf("expected ErrPendingCommitExists, got %v", err)
	}
}
