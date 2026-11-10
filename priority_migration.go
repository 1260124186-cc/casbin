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
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v3/constant"
	casbinerr "github.com/casbin/casbin/v3/errors"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// migrationBatchSize bounds how many rule updates are persisted in one
// checkpoint when the adapter supports targeted updates.
const migrationBatchSize = 100

// MigratePriorityResult summarizes one MigrateImplicitPriority run for a
// single named policy.
type MigratePriorityResult struct {
	// PType is the named policy type that was migrated, e.g. "p".
	PType string
	// Total is the number of rules inspected.
	Total int
	// Migrated is the number of rules that received a priority in this run.
	Migrated int
	// Skipped is the number of rules already carrying an explicit priority.
	Skipped int
	// Priorities holds the final priority of every rule in final policy order.
	Priorities []int
	// Rules holds every rule in the same order as GetNamedPolicy returns
	// after the migration, so callers can verify that enforcement and rule
	// reads share one order.
	Rules [][]string
}

// MigrateImplicitPriority converts policies whose priority is implicit
// (encoded solely by rule order) into explicit numeric "priority" field
// values.
//
// The priorities are stable and unique: every rule keeps the relative order
// it had before the migration, so no allow/deny decision changes and
// GetNamedPolicy returns the rules in the same order as before.
//
// The operation is idempotent: rules that already carry an explicit priority
// are never renumbered. It is also resumable: a process killed halfway
// through leaves the processed rules durably persisted, and a restarted run
// fills the remaining rules without touching the existing numbers.
//
// A rule that cannot be mapped, a duplicate priority or a persistence
// failure aborts the whole run for that policy type, restores both the
// in-memory model and the storage to their pre-run state, and returns a
// locatable *errors.PriorityMigrationError.
//
// An empty ptype migrates every named policy in section "p".
func (e *Enforcer) MigrateImplicitPriority(ptype string) (*MigratePriorityResult, error) {
	if e.model == nil || e.model["p"] == nil {
		return nil, casbinerr.NewPriorityMigrationError("map", ptype, -1, nil,
			"enforcer has no policy section", nil)
	}

	ptypes, err := resolveMigrationPTypes(e.model, ptype)
	if err != nil {
		return nil, err
	}
	if len(ptypes) > 1 {
		return e.migrateAllImplicitPriorities(ptypes)
	}
	return e.migrateOneImplicitPriority(ptypes[0])
}

func (e *Enforcer) migrateAllImplicitPriorities(ptypes []string) (*MigratePriorityResult, error) {
	var aggregated *MigratePriorityResult
	for _, named := range ptypes {
		res, err := e.migrateOneImplicitPriority(named)
		if err != nil {
			return nil, err
		}
		if aggregated == nil {
			aggregated = &MigratePriorityResult{PType: ""}
		}
		aggregated.Total += res.Total
		aggregated.Migrated += res.Migrated
		aggregated.Skipped += res.Skipped
		aggregated.Priorities = append(aggregated.Priorities, res.Priorities...)
		aggregated.Rules = append(aggregated.Rules, res.Rules...)
	}
	if aggregated == nil {
		aggregated = &MigratePriorityResult{PType: ""}
	}
	return aggregated, nil
}

func (e *Enforcer) migrateOneImplicitPriority(ptype string) (*MigratePriorityResult, error) {
	ast, err := e.model.GetAssertion("p", ptype)
	if err != nil {
		return nil, casbinerr.NewPriorityMigrationError("map", ptype, -1, nil, err.Error(), err)
	}

	if _, err := e.model.GetFieldIndex(ptype, constant.PriorityIndex); err != nil {
		return e.migrateImplicitShapedPolicy(ptype, ast)
	}
	return e.migrateExplicitShapedPolicy(ptype, ast)
}

// migrateImplicitShapedPolicy handles an enforcer whose policy definition has
// no priority token yet. It first converts every rule to the explicit shape
// with an empty pending priority, checkpoints that shape conversion, and then
// delegates to the explicit-shape migration. On failure the original
// implicit model and storage are restored.
func (e *Enforcer) migrateImplicitShapedPolicy(ptype string, ast *model.Assertion) (*MigratePriorityResult, error) {
	snapshot := e.model.Copy()

	pendingRules := make([][]string, 0, len(ast.Policy))
	for i, rule := range ast.Policy {
		if len(rule) != len(ast.Tokens) {
			return nil, casbinerr.NewPriorityMigrationError("map", ptype, i, rule,
				fmt.Sprintf("rule size %d does not match policy definition %d", len(rule), len(ast.Tokens)), nil)
		}
		explicitRule := make([]string, 0, len(rule)+1)
		explicitRule = append(explicitRule, "")
		explicitRule = append(explicitRule, rule...)
		pendingRules = append(pendingRules, explicitRule)
	}

	originalTokens := append([]string(nil), ast.Tokens...)
	originalValue := ast.Value

	ast.Tokens = append([]string{ptype + "_" + constant.PriorityIndex}, originalTokens...)
	ast.Value = constant.PriorityIndex + ", " + originalValue
	ast.Policy = pendingRules
	ast.PolicyMap = make(map[string]int, len(pendingRules))
	for i, rule := range pendingRules {
		ast.PolicyMap[strings.Join(rule, model.DefaultSep)] = i
	}
	ast.FieldIndexMutex.Lock()
	ast.FieldIndexMap = map[string]int{constant.PriorityIndex: 0}
	ast.FieldIndexMutex.Unlock()
	ast.PolicyVersion++

	if e.shouldPersist() {
		if err := e.adapter.SavePolicy(e.model); err != nil {
			e.restoreModel(snapshot)
			return nil, casbinerr.NewPriorityMigrationError("persist", ptype, -1, nil,
				"shape conversion checkpoint could not be persisted", err)
		}
	}

	res, err := e.migrateExplicitShapedPolicy(ptype, ast)
	if err != nil {
		// Roll back the shape conversion as well so the whole run keeps the
		// original implicit state.
		e.restoreModel(snapshot)
		if e.shouldPersist() {
			if restoreErr := e.adapter.SavePolicy(snapshot); restoreErr != nil {
				return nil, casbinerr.NewPriorityMigrationError("persist", ptype, -1, nil,
					"migration failed and restoring the original policy failed as well",
					fmt.Errorf("%w | restore error: %v", err, restoreErr))
			}
		}
		return nil, err
	}
	return res, nil
}

// ruleChange is one old -> new rule pair that still needs persisting.
type ruleChange struct {
	old []string
	new []string
}

// migrateExplicitShapedPolicy fills empty priority fields of an explicit
// priority model without ever renumbering rules that are already numeric.
func (e *Enforcer) migrateExplicitShapedPolicy(ptype string, ast *model.Assertion) (*MigratePriorityResult, error) {
	priorityIndex, err := e.model.GetFieldIndex(ptype, constant.PriorityIndex)
	if err != nil {
		return nil, casbinerr.NewPriorityMigrationError("map", ptype, -1, nil, err.Error(), err)
	}

	snapshot := e.model.Copy()

	// The in-memory policy may have been reordered by SortPoliciesByPriority
	// (empty priorities sort inconsistently), so the authoritative migration
	// order is always re-read from storage, unsorted, when an adapter exists.
	orderedRules, err := e.loadAuthoritativeOrder(ptype, ast)
	if err != nil {
		return nil, err
	}
	if err := assertRulesMappable(ptype, ast, orderedRules); err != nil {
		return nil, err
	}

	result := &MigratePriorityResult{PType: ptype, Total: len(orderedRules)}

	// A fully numeric policy has nothing implicit left to migrate: re-running
	// the migration is a no-op and must never renumber anything.
	if !hasPendingRule(orderedRules, priorityIndex) {
		for i, rule := range orderedRules {
			if _, atoiErr := strconv.Atoi(rule[priorityIndex]); atoiErr != nil {
				return nil, casbinerr.NewPriorityMigrationError("map", ptype, i, rule,
					fmt.Sprintf("priority field %q is not numeric", rule[priorityIndex]), atoiErr)
			}
		}
		result.Skipped = len(orderedRules)
		result.Priorities, result.Rules = readFinalState(ast)
		return result, nil
	}

	newOrdered := make([][]string, len(orderedRules))
	changes := make([]ruleChange, 0, len(orderedRules))
	anchors := 0
	pending := 0
	for i, rule := range orderedRules {
		if len(rule) != len(ast.Tokens) {
			return nil, casbinerr.NewPriorityMigrationError("map", ptype, i, rule,
				fmt.Sprintf("rule size %d does not match policy definition %d", len(rule), len(ast.Tokens)), nil)
		}
		target := i + 1
		newRule := cloneRule(rule)
		raw := rule[priorityIndex]
		if raw == "" {
			pending++
		} else {
			value, atoiErr := strconv.Atoi(raw)
			if atoiErr != nil {
				return nil, casbinerr.NewPriorityMigrationError("map", ptype, i, rule,
					fmt.Sprintf("priority field %q is not numeric", raw), atoiErr)
			}
			// Every already-numbered anchor must sit at exactly the storage
			// position its priority claims, otherwise filling the pending
			// rules could change the effective rule order.
			if value != target {
				return nil, casbinerr.NewPriorityMigrationError("duplicate", ptype, i, rule,
					fmt.Sprintf("existing priority %d does not match storage position %d; "+
						"preserving the original rule order cannot be guaranteed", value, target), nil)
			}
			anchors++
		}
		newRule[priorityIndex] = strconv.Itoa(target)
		newOrdered[i] = newRule
		if raw != strconv.Itoa(target) {
			changes = append(changes, ruleChange{old: cloneRule(rule), new: newRule})
		}
	}

	// Install the rules in authoritative storage order. Sorting by the newly
	// assigned dense priorities would reproduce exactly this order.
	ast.Policy = newOrdered
	ast.PolicyMap = make(map[string]int, len(newOrdered))
	for i, rule := range ast.Policy {
		ast.PolicyMap[strings.Join(rule, model.DefaultSep)] = i
	}
	ast.PolicyVersion++

	if err := validateFinalOrder(ptype, ast, priorityIndex); err != nil {
		e.restoreModel(snapshot)
		return nil, err
	}

	if err := e.checkpointMigration(ptype, snapshot, changes); err != nil {
		e.restoreModel(snapshot)
		return nil, err
	}

	e.resetPolicyCaches()
	e.bumpPolicyVersion()
	result.Migrated = pending
	result.Skipped = anchors
	result.Priorities, result.Rules = readFinalState(ast)
	return result, nil
}

// loadAuthoritativeOrder returns the policy rules in the order that currently
// determines implicit priority: the raw storage order when an adapter is
// available, or the in-memory policy order for adapter-less enforcers.
func (e *Enforcer) loadAuthoritativeOrder(ptype string, ast *model.Assertion) ([][]string, error) {
	if e.adapter == nil {
		return cloneRules(ast.Policy), nil
	}
	shadow := e.model.Copy()
	for _, shadowAst := range shadow["p"] {
		shadowAst.Policy = nil
		shadowAst.PolicyMap = map[string]int{}
	}
	if err := e.adapter.LoadPolicy(shadow); err != nil {
		return nil, casbinerr.NewPriorityMigrationError("map", ptype, -1, nil,
			"could not re-read rules from storage to determine their original order", err)
	}
	shadowAst, err := shadow.GetAssertion("p", ptype)
	if err != nil {
		return nil, casbinerr.NewPriorityMigrationError("map", ptype, -1, nil, err.Error(), err)
	}
	return cloneRules(shadowAst.Policy), nil
}

// assertRulesMappable ensures every rule loaded from storage exists in the
// live model and vice versa, so each rule can be mapped to exactly one
// storage position.
func assertRulesMappable(ptype string, ast *model.Assertion, orderedRules [][]string) error {
	liveKeys := make(map[string]struct{}, len(ast.Policy))
	for _, rule := range ast.Policy {
		liveKeys[strings.Join(rule, model.DefaultSep)] = struct{}{}
	}
	seen := make(map[string]int, len(orderedRules))
	for i, rule := range orderedRules {
		key := strings.Join(rule, model.DefaultSep)
		if first, ok := seen[key]; ok {
			return casbinerr.NewPriorityMigrationError("map", ptype, i, rule,
				fmt.Sprintf("rule is duplicated in storage at index %d", first), nil)
		}
		seen[key] = i
		if _, ok := liveKeys[key]; !ok {
			return casbinerr.NewPriorityMigrationError("map", ptype, i, rule,
				"rule exists in storage but not in the enforcer model", nil)
		}
	}
	if len(seen) != len(ast.Policy) {
		return casbinerr.NewPriorityMigrationError("map", ptype, -1, nil,
			fmt.Sprintf("enforcer model has %d rules but storage has %d; the rule sets do not match",
				len(ast.Policy), len(seen)), nil)
	}
	return nil
}

func hasPendingRule(rules [][]string, priorityIndex int) bool {
	for _, rule := range rules {
		if rule[priorityIndex] == "" {
			return true
		}
	}
	return false
}

// checkpointMigration durably persists the migrated rules. Updatable adapters
// receive batched UpdatePolicies calls so every batch is a resumable
// checkpoint; other adapters persist the whole policy once via SavePolicy.
// Any failure rolls the storage back to snapshot before returning.
func (e *Enforcer) checkpointMigration(ptype string, snapshot model.Model, changes []ruleChange) error {
	if !e.shouldPersist() || len(changes) == 0 {
		return nil
	}

	oldRules := make([][]string, 0, len(changes))
	newRules := make([][]string, 0, len(changes))
	for _, change := range changes {
		oldRules = append(oldRules, change.old)
		newRules = append(newRules, change.new)
	}

	if updater, ok := e.adapter.(persist.UpdatableAdapter); ok {
		appliedOld := make([][]string, 0, len(oldRules))
		appliedNew := make([][]string, 0, len(newRules))
		for start := 0; start < len(oldRules); start += migrationBatchSize {
			end := start + migrationBatchSize
			if end > len(oldRules) {
				end = len(oldRules)
			}
			batchOld, batchNew := oldRules[start:end], newRules[start:end]
			if err := updater.UpdatePolicies("p", ptype, batchOld, batchNew); err != nil {
				if err.Error() == notImplemented {
					break // fall back to SavePolicy below
				}
				if len(appliedOld) > 0 {
					if reverseErr := updater.UpdatePolicies("p", ptype, appliedNew, appliedOld); reverseErr != nil &&
						reverseErr.Error() != notImplemented {
						return casbinerr.NewPriorityMigrationError("persist", ptype, start, batchOld[0],
							"persistence failed and rolling back the applied batches failed as well",
							fmt.Errorf("%w | rollback error: %v", err, reverseErr))
					}
				}
				return casbinerr.NewPriorityMigrationError("persist", ptype, start, batchOld[0],
					"persistence failed; applied batches have been rolled back", err)
			}
			appliedOld = append(appliedOld, batchOld...)
			appliedNew = append(appliedNew, batchNew...)
		}
		if len(appliedOld) == len(oldRules) {
			return nil
		}
	}

	if err := e.adapter.SavePolicy(e.model); err != nil {
		if restoreErr := e.adapter.SavePolicy(snapshot); restoreErr != nil {
			return casbinerr.NewPriorityMigrationError("persist", ptype, -1, nil,
				"SavePolicy failed and restoring the original policy failed as well",
				fmt.Errorf("%w | rollback error: %v", err, restoreErr))
		}
		return casbinerr.NewPriorityMigrationError("persist", ptype, -1, nil,
			"SavePolicy failed; the original policy has been restored", err)
	}
	return nil
}

func (e *Enforcer) restoreModel(snapshot model.Model) {
	e.model = snapshot
	e.invalidateMatcherMap()
	e.resetPolicyCaches()
}

func resolveMigrationPTypes(m model.Model, ptype string) ([]string, error) {
	if ptype != "" {
		if _, err := m.GetAssertion("p", ptype); err != nil {
			return nil, casbinerr.NewPriorityMigrationError("map", ptype, -1, nil, err.Error(), err)
		}
		return []string{ptype}, nil
	}
	names := make([]string, 0, len(m["p"]))
	for name := range m["p"] {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func validateFinalOrder(ptype string, ast *model.Assertion, priorityIndex int) error {
	seen := make(map[int]int, len(ast.Policy))
	for i, rule := range ast.Policy {
		value, err := strconv.Atoi(rule[priorityIndex])
		if err != nil {
			return casbinerr.NewPriorityMigrationError("map", ptype, i, rule,
				fmt.Sprintf("priority field %q is not numeric", rule[priorityIndex]), err)
		}
		if first, ok := seen[value]; ok {
			return casbinerr.NewPriorityMigrationError("duplicate", ptype, i, rule,
				fmt.Sprintf("priority %d is already used by rule at index %d", value, first), nil)
		}
		seen[value] = i
		// Migration output must be the dense sequence 1..N: unique, gap-free
		// and strictly increasing, so sorting by priority reproduces exactly
		// the original rule order.
		if value != i+1 {
			return casbinerr.NewPriorityMigrationError("duplicate", ptype, i, rule,
				fmt.Sprintf("priority %d breaks the dense sequence 1..%d at index %d", value, len(ast.Policy), i), nil)
		}
	}
	return nil
}

func readFinalState(ast *model.Assertion) ([]int, [][]string) {
	ast.FieldIndexMutex.RLock()
	priorityIndex := ast.FieldIndexMap[constant.PriorityIndex]
	ast.FieldIndexMutex.RUnlock()
	priorities := make([]int, 0, len(ast.Policy))
	rules := make([][]string, 0, len(ast.Policy))
	for _, rule := range ast.Policy {
		rules = append(rules, cloneRule(rule))
		if priorityIndex >= 0 && priorityIndex < len(rule) {
			if value, err := strconv.Atoi(rule[priorityIndex]); err == nil {
				priorities = append(priorities, value)
			}
		}
	}
	return priorities, rules
}

func cloneRules(rules [][]string) [][]string {
	cloned := make([][]string, len(rules))
	for i, rule := range rules {
		cloned[i] = cloneRule(rule)
	}
	return cloned
}

func cloneRule(rule []string) []string {
	return append([]string(nil), rule...)
}
