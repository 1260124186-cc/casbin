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
	"sort"
	"strconv"
	"strings"
	"testing"

	casbinerr "github.com/casbin/casbin/v3/errors"
	"github.com/casbin/casbin/v3/model"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	stringadapter "github.com/casbin/casbin/v3/persist/string-adapter"
)

// migrationRequest pairs an enforce request with the decision produced by the
// implicit-order priority policy in examples/priority_policy.csv.
type migrationRequest struct {
	args []interface{}
	want bool
}

var migrationRequests = []migrationRequest{
	{[]interface{}{"alice", "data1", "read"}, true},
	{[]interface{}{"alice", "data1", "write"}, false},
	{[]interface{}{"alice", "data2", "read"}, false},
	{[]interface{}{"alice", "data2", "write"}, false},
	{[]interface{}{"bob", "data1", "write"}, false},
	{[]interface{}{"bob", "data2", "read"}, true},
	{[]interface{}{"bob", "data2", "write"}, false},
}

// writeExplicitPriorityFixture converts the implicit-order fixture into an
// explicit-shape fixture. p rules gain a leading priority field: numeric for
// the first anchoredCount rules, empty afterwards (pending). g rules stay
// untouched. override lets individual tests corrupt a specific p rule.
func writeExplicitPriorityFixture(t *testing.T, anchoredCount int, override func(index int, fields []string) []string) string {
	t.Helper()
	raw, err := os.ReadFile("examples/priority_policy.csv")
	if err != nil {
		t.Fatalf("read implicit fixture: %v", err)
	}

	var lines []string
	pIndex := 0
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
			continue
		}
		tokens := strings.Split(trimmed, ",")
		for i := range tokens {
			tokens[i] = strings.TrimSpace(tokens[i])
		}
		if tokens[0] != "p" {
			lines = append(lines, trimmed)
			continue
		}
		priority := ""
		if pIndex < anchoredCount {
			priority = strconv.Itoa(pIndex + 1)
		}
		fields := append([]string{priority}, tokens[1:]...)
		if override != nil {
			fields = override(pIndex, fields)
		}
		lines = append(lines, "p, "+strings.Join(fields, ", "))
		pIndex++
	}

	path := filepath.Join(t.TempDir(), "priority_explicit.csv")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func copyFixture(t *testing.T, src string) string {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), filepath.Base(src))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write fixture copy: %v", err)
	}
	return path
}

func captureDecisions(t *testing.T, e *Enforcer) map[string]bool {
	t.Helper()
	got := make(map[string]bool, len(migrationRequests))
	for _, req := range migrationRequests {
		ok, err := e.Enforce(req.args...)
		if err != nil {
			t.Fatalf("Enforce(%v) failed: %v", req.args, err)
		}
		got[strings.Join(toStrings(req.args), "/")] = ok
	}
	return got
}

func toStrings(args []interface{}) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = arg.(string)
	}
	return out
}

func assertDecisions(t *testing.T, e *Enforcer, want map[string]bool) {
	t.Helper()
	got := captureDecisions(t, e)
	for key, expected := range want {
		if got[key] != expected {
			t.Errorf("decision for %q = %v, want %v", key, got[key], expected)
		}
	}
}

func assertDecisionBaseline(t *testing.T, e *Enforcer) map[string]bool {
	t.Helper()
	baseline := make(map[string]bool, len(migrationRequests))
	for _, req := range migrationRequests {
		baseline[strings.Join(toStrings(req.args), "/")] = req.want
	}
	assertDecisions(t, e, baseline)
	return baseline
}

// ruleIdentity drops the leading priority field so rules can be compared
// across the implicit/explicit shapes.
func ruleIdentity(rule []string) []string {
	return append([]string(nil), rule[1:]...)
}

func assertPriorities(t *testing.T, e *Enforcer, ptype string, want []int) {
	t.Helper()
	rules, err := e.GetNamedPolicy(ptype)
	if err != nil {
		t.Fatalf("GetNamedPolicy: %v", err)
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rules), len(want))
	}
	for i, rule := range rules {
		if rule[0] != strconv.Itoa(want[i]) {
			t.Errorf("rule %d priority = %q, want %d; full rule: %v", i, rule[0], want[i], rule)
		}
	}
}

// implicitBaselineEnforcer builds the order-based enforcer whose decisions
// are the reference that migration must never change.
func implicitBaselineEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e, err := NewEnforcer("examples/priority_model.conf", "examples/priority_policy.csv")
	if err != nil {
		t.Fatalf("baseline NewEnforcer: %v", err)
	}
	return e
}

// TestMigrateImplicitPriority_ExplicitEquivalence covers the main contract:
// empty-priority rules receive stable unique priorities, rule order and every
// allow/deny decision stay identical to the implicit-order policy, and a
// reloaded enforcer reads the same order from storage.
func TestMigrateImplicitPriority_ExplicitEquivalence(t *testing.T) {
	baselineEnforcer := implicitBaselineEnforcer(t)
	baseline := captureDecisions(t, baselineEnforcer)
	implicitRules, _ := baselineEnforcer.GetNamedPolicy("p")

	fixture := writeExplicitPriorityFixture(t, 0, nil)
	e, err := NewEnforcer("examples/priority_model_explicit.conf", fixture)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	res, err := e.MigrateImplicitPriority("p")
	if err != nil {
		t.Fatalf("MigrateImplicitPriority: %v", err)
	}
	if res.Total != len(implicitRules) || res.Migrated != len(implicitRules) || res.Skipped != 0 {
		t.Errorf("result = %+v, want all %d rules migrated", res, len(implicitRules))
	}
	wantPriorities := make([]int, len(implicitRules))
	for i := range wantPriorities {
		wantPriorities[i] = i + 1
	}
	assertPriorities(t, e, "p", wantPriorities)

	after, _ := e.GetNamedPolicy("p")
	if len(after) != len(implicitRules) {
		t.Fatalf("rule count changed: %d -> %d", len(implicitRules), len(after))
	}
	for i := range implicitRules {
		if strings.Join(implicitRules[i], ",") != strings.Join(ruleIdentity(after[i]), ",") {
			t.Errorf("rule order/identity changed at %d: %v -> %v", i, implicitRules[i], after[i])
		}
	}
	assertDecisions(t, e, baseline)

	// Storage must carry the same priorities and order.
	reloaded, err := NewEnforcer("examples/priority_model_explicit.conf", fixture)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	assertPriorities(t, reloaded, "p", wantPriorities)
	assertDecisions(t, reloaded, baseline)
	reloadedRules, _ := reloaded.GetNamedPolicy("p")
	for i := range after {
		if strings.Join(after[i], ",") != strings.Join(reloadedRules[i], ",") {
			t.Errorf("stored order differs at %d: %v vs %v", i, after[i], reloadedRules[i])
		}
	}
}

// TestMigrateImplicitPriority_Idempotent verifies that re-running the
// migration never renumbers an already migrated rule and never rewrites
// storage.
func TestMigrateImplicitPriority_Idempotent(t *testing.T) {
	baseline := captureDecisions(t, implicitBaselineEnforcer(t))
	fixture := writeExplicitPriorityFixture(t, 0, nil)
	e, err := NewEnforcer("examples/priority_model_explicit.conf", fixture)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	if _, err := e.MigrateImplicitPriority("p"); err != nil {
		t.Fatalf("first migration: %v", err)
	}
	firstBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read storage: %v", err)
	}
	firstRules, _ := e.GetNamedPolicy("p")

	res, err := e.MigrateImplicitPriority("p")
	if err != nil {
		t.Fatalf("second migration: %v", err)
	}
	if res.Migrated != 0 || res.Skipped != len(firstRules) {
		t.Errorf("re-run changed rules: %+v", res)
	}
	secondBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read storage: %v", err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Errorf("storage was rewritten on an idempotent re-run")
	}
	secondRules, _ := e.GetNamedPolicy("p")
	for i := range firstRules {
		if strings.Join(firstRules[i], ",") != strings.Join(secondRules[i], ",") {
			t.Errorf("rule %d renumbered: %v -> %v", i, firstRules[i], secondRules[i])
		}
	}
	assertDecisions(t, e, baseline)
}

// TestMigrateImplicitPriority_Resume simulates a process killed after the
// first three rules were persisted: restarted migration must keep their
// numbers and finish the remaining rules so the final order and decisions
// match a one-shot migration.
func TestMigrateImplicitPriority_Resume(t *testing.T) {
	partial := writeExplicitPriorityFixture(t, 3, nil)
	e, err := NewEnforcer("examples/priority_model_explicit.conf", partial)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	res, err := e.MigrateImplicitPriority("p")
	if err != nil {
		t.Fatalf("resumed migration: %v", err)
	}
	if res.Migrated != 4 || res.Skipped != 3 || res.Total != 7 {
		t.Errorf("unexpected resume result: %+v", res)
	}
	assertPriorities(t, e, "p", []int{1, 2, 3, 4, 5, 6, 7})
	assertDecisionBaseline(t, e)

	// Anchors must keep their original identities.
	rules, _ := e.GetNamedPolicy("p")
	wantIdentities := [][]string{
		{"alice", "data1", "read", "allow"},
		{"data1_deny_group", "data1", "read", "deny"},
		{"data1_deny_group", "data1", "write", "deny"},
		{"alice", "data1", "write", "allow"},
		{"data2_allow_group", "data2", "read", "allow"},
		{"bob", "data2", "read", "deny"},
		{"bob", "data2", "write", "deny"},
	}
	for i, want := range wantIdentities {
		if strings.Join(ruleIdentity(rules[i]), ",") != strings.Join(want, ",") {
			t.Errorf("rule %d identity = %v, want %v", i, rules[i], want)
		}
	}

	// Restarting again from the checkpointed storage leaves everything stable.
	reloaded, err := NewEnforcer("examples/priority_model_explicit.conf", partial)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	again, err := reloaded.MigrateImplicitPriority("p")
	if err != nil {
		t.Fatalf("migration after restart: %v", err)
	}
	if again.Migrated != 0 {
		t.Errorf("restarted migration reassigned priorities: %+v", again)
	}
	assertPriorities(t, reloaded, "p", []int{1, 2, 3, 4, 5, 6, 7})
	assertDecisionBaseline(t, reloaded)
}

// TestMigrateImplicitPriority_FromImplicitModel covers an enforcer that still
// runs the order-based model: the definition gains the priority token in
// place, storage is converted, and decisions never change.
func TestMigrateImplicitPriority_FromImplicitModel(t *testing.T) {
	fixture := copyFixture(t, "examples/priority_policy.csv")
	e, err := NewEnforcer("examples/priority_model.conf", fixture)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	baseline := assertDecisionBaseline(t, e)
	before, _ := e.GetNamedPolicy("p")

	res, err := e.MigrateImplicitPriority("p")
	if err != nil {
		t.Fatalf("MigrateImplicitPriority: %v", err)
	}
	if res.Migrated != len(before) {
		t.Errorf("migrated %d rules, want %d", res.Migrated, len(before))
	}
	assertPriorities(t, e, "p", []int{1, 2, 3, 4, 5, 6, 7})
	assertDecisions(t, e, baseline)

	// The explicit-model enforcer built from the same storage must decide
	// identically and read the rules in the same order.
	explicit, err := NewEnforcer("examples/priority_model_explicit.conf", fixture)
	if err != nil {
		t.Fatalf("explicit reload: %v", err)
	}
	assertDecisionBaseline(t, explicit)
	explicitRules, _ := explicit.GetNamedPolicy("p")
	migratedRules, _ := e.GetNamedPolicy("p")
	for i := range explicitRules {
		if strings.Join(explicitRules[i], ",") != strings.Join(migratedRules[i], ",") {
			t.Errorf("order mismatch at %d: %v vs %v", i, explicitRules[i], migratedRules[i])
		}
	}

	// On the explicit enforcer the migration is now a no-op.
	again, err := explicit.MigrateImplicitPriority("p")
	if err != nil {
		t.Fatalf("idempotent re-run: %v", err)
	}
	if again.Migrated != 0 {
		t.Errorf("re-run renumbered rules: %+v", again)
	}
}

// TestMigrateImplicitPriority_UnmappableRule verifies that a non-numeric
// priority produces a locatable error and leaves model and storage untouched.
func TestMigrateImplicitPriority_UnmappableRule(t *testing.T) {
	fixture := writeExplicitPriorityFixture(t, 0, func(index int, fields []string) []string {
		if index == 2 {
			fields[0] = "high"
		}
		return fields
	})
	beforeBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read storage: %v", err)
	}
	e, err := NewEnforcer("examples/priority_model_explicit.conf", fixture)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	before, _ := e.GetNamedPolicy("p")

	_, err = e.MigrateImplicitPriority("p")
	if err == nil {
		t.Fatal("expected an error for an unmappable rule")
	}
	if !errors.Is(err, casbinerr.ErrRuleNotMappable) {
		t.Errorf("error %v does not wrap ErrRuleNotMappable", err)
	}
	var locatable *casbinerr.PriorityMigrationError
	if !errors.As(err, &locatable) || locatable.Index != 2 {
		t.Errorf("error must locate rule index 2, got %v", err)
	}
	if locatable != nil && len(locatable.Rule) == 0 {
		t.Errorf("locatable error must carry the offending rule")
	}

	after, _ := e.GetNamedPolicy("p")
	if strings.Join(flatten(before), "|") != strings.Join(flatten(after), "|") {
		t.Errorf("in-memory policy changed on failed migration")
	}
	afterBytes, _ := os.ReadFile(fixture)
	if string(beforeBytes) != string(afterBytes) {
		t.Errorf("storage changed on failed migration")
	}
}

// TestMigrateImplicitPriority_DuplicatePriority verifies the duplicate
// priority guard and full rollback.
func TestMigrateImplicitPriority_DuplicatePriority(t *testing.T) {
	fixture := writeExplicitPriorityFixture(t, 0, func(index int, fields []string) []string {
		if index == 1 || index == 3 {
			fields[0] = "2"
		}
		return fields
	})
	beforeBytes, _ := os.ReadFile(fixture)
	e, err := NewEnforcer("examples/priority_model_explicit.conf", fixture)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	before, _ := e.GetNamedPolicy("p")

	_, err = e.MigrateImplicitPriority("p")
	if err == nil {
		t.Fatal("expected a duplicate priority error")
	}
	if !errors.Is(err, casbinerr.ErrDuplicatePriority) {
		t.Errorf("error %v does not wrap ErrDuplicatePriority", err)
	}
	var locatable *casbinerr.PriorityMigrationError
	if !errors.As(err, &locatable) || locatable.Index != 3 {
		t.Errorf("error must locate the second duplicate at index 3, got %v", err)
	}

	after, _ := e.GetNamedPolicy("p")
	if strings.Join(flatten(before), "|") != strings.Join(flatten(after), "|") {
		t.Errorf("in-memory policy changed on failed migration")
	}
	afterBytes, _ := os.ReadFile(fixture)
	if string(beforeBytes) != string(afterBytes) {
		t.Errorf("storage changed on failed migration")
	}
}

// failingUpdateAdapter makes AdapterMock satisfy persist.UpdatableAdapter
// (the mock lacks UpdateFilteredPolicies) while every update fails.
type failingUpdateAdapter struct {
	*fileadapter.AdapterMock
}

func (f *failingUpdateAdapter) UpdateFilteredPolicies(sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return nil, f.GetMockErr()
}

// TestMigrateImplicitPriority_UpdatablePersistFailure verifies rollback when
// a targeted adapter update fails.
func TestMigrateImplicitPriority_UpdatablePersistFailure(t *testing.T) {
	fixture := writeExplicitPriorityFixture(t, 0, nil)
	mock := fileadapter.NewAdapterMock(fixture)
	mock.SetMockErr("mock storage outage")
	adapter := &failingUpdateAdapter{AdapterMock: mock}
	e, err := NewEnforcer("examples/priority_model_explicit.conf", adapter)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	before, _ := e.GetNamedPolicy("p")

	_, err = e.MigrateImplicitPriority("p")
	if err == nil {
		t.Fatal("expected a persistence error")
	}
	if !errors.Is(err, casbinerr.ErrPriorityPersist) {
		t.Errorf("error %v does not wrap ErrPriorityPersist", err)
	}
	after, _ := e.GetNamedPolicy("p")
	if strings.Join(flatten(before), "|") != strings.Join(flatten(after), "|") {
		t.Errorf("in-memory policy was not rolled back: before=%v after=%v", before, after)
	}
	for _, rule := range after {
		if rule[0] != "" {
			t.Errorf("rolled-back rule still carries priority %q: %v", rule[0], rule)
		}
	}
}

// saveFailAdapter fails the first SavePolicy call (simulating a storage
// outage) and succeeds on the rollback call.
type saveFailAdapter struct {
	*fileadapter.Adapter
	failed bool
}

func (s *saveFailAdapter) SavePolicy(m model.Model) error {
	if !s.failed {
		s.failed = true
		return errors.New("disk full")
	}
	return s.Adapter.SavePolicy(m)
}

// TestMigrateImplicitPriority_SavePolicyFailure verifies the SavePolicy
// fallback path and the storage restore.
func TestMigrateImplicitPriority_SavePolicyFailure(t *testing.T) {
	fixture := writeExplicitPriorityFixture(t, 0, nil)

	adapter := &saveFailAdapter{Adapter: fileadapter.NewAdapter(fixture)}
	e, err := NewEnforcer("examples/priority_model_explicit.conf", adapter)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	before, _ := e.GetNamedPolicy("p")

	_, err = e.MigrateImplicitPriority("p")
	if err == nil {
		t.Fatal("expected a persistence error")
	}
	if !errors.Is(err, casbinerr.ErrPriorityPersist) {
		t.Errorf("error %v does not wrap ErrPriorityPersist", err)
	}
	after, _ := e.GetNamedPolicy("p")
	if strings.Join(flatten(before), "|") != strings.Join(flatten(after), "|") {
		t.Errorf("in-memory policy was not rolled back")
	}

	// The rollback SavePolicy rewrote the storage from the pre-run snapshot:
	// every rule must be back to its empty (pending) priority, and a fresh
	// enforcer must see the same rule set as before the failed run.
	reloaded, err := NewEnforcer("examples/priority_model_explicit.conf", fixture)
	if err != nil {
		t.Fatalf("reload restored storage: %v", err)
	}
	reloadedRules, _ := reloaded.GetNamedPolicy("p")
	if len(reloadedRules) != len(before) {
		t.Fatalf("restored storage has %d rules, want %d", len(reloadedRules), len(before))
	}
	for _, rule := range reloadedRules {
		if rule[0] != "" {
			t.Errorf("restored rule still carries priority %q: %v", rule[0], rule)
		}
	}
}

// TestMigrateImplicitPriority_SyncedEnforcer ensures the synced enforcer
// exposes the same migration contract.
func TestMigrateImplicitPriority_SyncedEnforcer(t *testing.T) {
	baseline := captureDecisions(t, implicitBaselineEnforcer(t))
	fixture := writeExplicitPriorityFixture(t, 0, nil)
	e, err := NewSyncedEnforcer("examples/priority_model_explicit.conf", fixture)
	if err != nil {
		t.Fatalf("NewSyncedEnforcer: %v", err)
	}

	res, err := e.MigrateImplicitPriority("p")
	if err != nil {
		t.Fatalf("MigrateImplicitPriority: %v", err)
	}
	if res.Migrated != 7 {
		t.Errorf("Migrated = %d, want 7", res.Migrated)
	}
	assertDecisions(t, e.Enforcer, baseline)
	assertPriorities(t, e.Enforcer, "p", []int{1, 2, 3, 4, 5, 6, 7})
}

// TestMigrateImplicitPriority_ImplicitModelPersistFailure verifies that a
// shape-conversion checkpoint failure on an order-based enforcer leaves the
// implicit model and storage completely untouched.
func TestMigrateImplicitPriority_ImplicitModelPersistFailure(t *testing.T) {
	fixture := copyFixture(t, "examples/priority_policy.csv")
	adapter := &saveFailAdapter{Adapter: fileadapter.NewAdapter(fixture)}
	e, err := NewEnforcer("examples/priority_model.conf", adapter)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	baseline := captureDecisions(t, e)
	before, _ := e.GetNamedPolicy("p")

	_, err = e.MigrateImplicitPriority("p")
	if err == nil {
		t.Fatal("expected a persistence error")
	}
	if !errors.Is(err, casbinerr.ErrPriorityPersist) {
		t.Fatalf("error %v does not wrap ErrPriorityPersist", err)
	}

	after, _ := e.GetNamedPolicy("p")
	if strings.Join(flatten(before), "|") != strings.Join(flatten(after), "|") {
		t.Errorf("implicit policy changed after failed migration")
	}
	for _, rule := range after {
		if len(rule) != len(before[0]) {
			t.Errorf("rule shape changed: %v", rule)
		}
	}
	assertDecisions(t, e, baseline)

	reloaded, err := NewEnforcer("examples/priority_model.conf", fixture)
	if err != nil {
		t.Fatalf("storage no longer loads with the implicit model: %v", err)
	}
	assertDecisions(t, reloaded, baseline)
}

// TestMigrateImplicitPriority_UnknownPType checks that an unknown policy type
// returns a locatable error instead of panicking.
func TestMigrateImplicitPriority_UnknownPType(t *testing.T) {
	fixture := writeExplicitPriorityFixture(t, 0, nil)
	e, err := NewEnforcer("examples/priority_model_explicit.conf", fixture)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	if _, err := e.MigrateImplicitPriority("does-not-exist"); err == nil {
		t.Fatal("expected an error for an unknown ptype")
	} else if !errors.Is(err, casbinerr.ErrPriorityMigration) {
		t.Errorf("error %v does not wrap ErrPriorityMigration", err)
	}
}

func flatten(rules [][]string) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, strings.Join(rule, ","))
	}
	return out
}

// recordingAdapter is an in-memory UpdatableAdapter that records every
// UpdatePolicies batch (and reverse rollback batches) and can fail a chosen
// batch. Its rule store mirrors what a database would contain.
type recordingAdapter struct {
	*fileadapter.Adapter
	store          map[string][]string
	forwardBatches []int
	reverseBatches []int
	failBatch      int
}

func newRecordingAdapter(t *testing.T, fixture string, initial [][]string, failBatch int) *recordingAdapter {
	t.Helper()
	store := make(map[string][]string, len(initial))
	for _, rule := range initial {
		store[strings.Join(rule, ",")] = append([]string(nil), rule...)
	}
	return &recordingAdapter{
		Adapter:   fileadapter.NewAdapter(fixture),
		store:     store,
		failBatch: failBatch,
	}
}

var errInjectedUpdate = errors.New("injected update outage")

func (r *recordingAdapter) UpdatePolicy(_ string, _ string, oldRule, newRule []string) error {
	return r.apply([][]string{oldRule}, [][]string{newRule}, false)
}

func (r *recordingAdapter) UpdatePolicies(_ string, _ string, oldRules, newRules [][]string) error {
	isReverse := len(r.reverseBatches) > 0 || r.failedForward()
	if isReverse {
		r.reverseBatches = append(r.reverseBatches, len(oldRules))
	} else {
		r.forwardBatches = append(r.forwardBatches, len(oldRules))
	}
	return r.apply(oldRules, newRules, !isReverse)
}

func (r *recordingAdapter) failedForward() bool {
	return len(r.forwardBatches) > r.failBatch && r.failBatch >= 0
}

func (r *recordingAdapter) apply(oldRules, newRules [][]string, countForward bool) error {
	if countForward && r.failBatch == len(r.forwardBatches)-1 {
		return errInjectedUpdate
	}
	for i, oldRule := range oldRules {
		key := strings.Join(oldRule, ",")
		if _, ok := r.store[key]; !ok {
			return fmt.Errorf("unexpected old rule %v", oldRule)
		}
		delete(r.store, key)
		newRule := newRules[i]
		r.store[strings.Join(newRule, ",")] = append([]string(nil), newRule...)
	}
	return nil
}

func (r *recordingAdapter) UpdateFilteredPolicies(_ string, _ string, newRules [][]string, _ int, _ ...string) ([][]string, error) {
	return nil, nil
}

func (r *recordingAdapter) storeKeys() []string {
	keys := make([]string, 0, len(r.store))
	for key := range r.store {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeLargeExplicitFixture(t *testing.T, n int) (string, [][]string) {
	t.Helper()
	var lines []string
	rules := make([][]string, 0, n)
	for i := 0; i < n; i++ {
		rule := []string{"", "alice", "data" + strconv.Itoa(i), "read", "allow"}
		rules = append(rules, rule)
		lines = append(lines, "p, "+strings.Join(rule, ", "))
	}
	path := filepath.Join(t.TempDir(), "large_priority.csv")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path, rules
}

// TestMigrateImplicitPriority_BatchedCheckpoints verifies that large policies
// are persisted in resumable batches and end up with dense unique priorities
// preserving the storage order.
func TestMigrateImplicitPriority_BatchedCheckpoints(t *testing.T) {
	const n = 250
	fixture, initial := writeLargeExplicitFixture(t, n)
	adapter := newRecordingAdapter(t, fixture, initial, -1)
	e, err := NewEnforcer("examples/priority_model_explicit.conf", adapter)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	res, err := e.MigrateImplicitPriority("p")
	if err != nil {
		t.Fatalf("MigrateImplicitPriority: %v", err)
	}
	if res.Migrated != n {
		t.Errorf("Migrated = %d, want %d", res.Migrated, n)
	}
	wantBatches := []int{migrationBatchSize, migrationBatchSize, n - 2*migrationBatchSize}
	if strings.Join(intSlice(adapter.forwardBatches), ",") != strings.Join(intSlice(wantBatches), ",") {
		t.Errorf("forward batches = %v, want %v", adapter.forwardBatches, wantBatches)
	}

	assertPriorities(t, e, "p", sequence(n))
	rules, _ := e.GetNamedPolicy("p")
	for i := 0; i < n; i++ {
		if rules[i][2] != "data"+strconv.Itoa(i) {
			t.Fatalf("rule order changed at %d: %v", i, rules[i])
		}
	}
	if ok, _ := e.Enforce("alice", "data42", "read"); !ok {
		t.Errorf("allow decision changed for data42")
	}
	if ok, _ := e.Enforce("alice", "data42", "write"); ok {
		t.Errorf("default deny decision changed for data42 write")
	}

	// The adapter store (the "database") must hold the same dense priorities.
	for i := 0; i < n; i++ {
		key := strings.Join([]string{strconv.Itoa(i + 1), "alice", "data" + strconv.Itoa(i), "read", "allow"}, ",")
		if _, ok := adapter.store[key]; !ok {
			t.Errorf("adapter store missing migrated rule %q", key)
		}
	}
}

// TestMigrateImplicitPriority_MidBatchRollback verifies that a failure on a
// later batch triggers a reverse update of every applied batch and leaves the
// adapter store and the in-memory model at their pre-run state.
func TestMigrateImplicitPriority_MidBatchRollback(t *testing.T) {
	const n = 250
	fixture, initial := writeLargeExplicitFixture(t, n)
	adapter := newRecordingAdapter(t, fixture, initial, 1) // second batch fails
	e, err := NewEnforcer("examples/priority_model_explicit.conf", adapter)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	originalKeys := adapter.storeKeys()

	_, err = e.MigrateImplicitPriority("p")
	if err == nil {
		t.Fatal("expected a persistence error")
	}
	if !errors.Is(err, casbinerr.ErrPriorityPersist) {
		t.Fatalf("error %v does not wrap ErrPriorityPersist", err)
	}
	if len(adapter.reverseBatches) != 1 || adapter.reverseBatches[0] != migrationBatchSize {
		t.Errorf("reverse batches = %v, want one batch of %d", adapter.reverseBatches, migrationBatchSize)
	}
	if strings.Join(adapter.storeKeys(), "|") != strings.Join(originalKeys, "|") {
		t.Errorf("adapter store was not restored to its pre-run state")
	}
	after, _ := e.GetNamedPolicy("p")
	for _, rule := range after {
		if rule[0] != "" {
			t.Errorf("in-memory rule still carries priority %q after rollback: %v", rule[0], rule)
		}
	}
}

// TestMigrateImplicitPriority_InMemoryAdapter covers a file-less enforcer
// backed by the in-memory string adapter: migration still assigns dense
// priorities through the SavePolicy path, persists them and stays idempotent.
func TestMigrateImplicitPriority_InMemoryAdapter(t *testing.T) {
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, "p, , alice, data"+strconv.Itoa(i)+", read, allow")
	}
	adapter := stringadapter.NewAdapter(strings.Join(lines, "\n"))
	e, err := NewEnforcer("examples/priority_model_explicit.conf", adapter)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	res, err := e.MigrateImplicitPriority("p")
	if err != nil {
		t.Fatalf("MigrateImplicitPriority: %v", err)
	}
	if res.Migrated != 5 {
		t.Errorf("Migrated = %d, want 5", res.Migrated)
	}
	assertPriorities(t, e, "p", []int{1, 2, 3, 4, 5})
	if !strings.Contains(adapter.Line, "p, 1, alice, data0, read, allow") ||
		!strings.Contains(adapter.Line, "p, 5, alice, data4, read, allow") {
		t.Errorf("migrated priorities were not persisted to the in-memory adapter:\n%s", adapter.Line)
	}

	again, err := e.MigrateImplicitPriority("p")
	if err != nil {
		t.Fatalf("idempotent re-run: %v", err)
	}
	if again.Migrated != 0 {
		t.Errorf("re-run renumbered rules: %+v", again)
	}
	assertPriorities(t, e, "p", []int{1, 2, 3, 4, 5})
}

func sequence(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i + 1
	}
	return out
}

func intSlice(values []int) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strconv.Itoa(v)
	}
	return out
}
