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

package persist

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/casbin/casbin/v3/model"
)

// MemoryAdapterOperation names the operations reported to MemoryAdapter.ErrorHook.
const (
	MemoryOpAddPolicy              = "AddPolicy"
	MemoryOpAddPolicies            = "AddPolicies"
	MemoryOpRemovePolicy           = "RemovePolicy"
	MemoryOpRemovePolicies         = "RemovePolicies"
	MemoryOpRemoveFilteredPolicy   = "RemoveFilteredPolicy"
	MemoryOpUpdatePolicy           = "UpdatePolicy"
	MemoryOpUpdatePolicies         = "UpdatePolicies"
	MemoryOpUpdateFilteredPolicies = "UpdateFilteredPolicies"
	MemoryOpSavePolicy             = "SavePolicy"
	MemoryOpReplaceManagedPolicy   = "ReplaceManagedPolicy"
	MemoryOpTransactionCommit      = "Commit"
)

// MemoryAdapter is an in-memory Adapter implementation. It supports batch
// operations, updates, transactions and managed-policy ownership records,
// which makes it usable as a transactional backend for
// ReconcileDomainPolicySnapshot without any external dependency.
//
// A transaction works on a deep-copied shadow of the committed state: writes
// done through the transaction scoped adapter are only visible to that
// transaction and are published to the root adapter on Commit, or discarded
// on Rollback. A zero-value MemoryAdapter is ready to use.
type MemoryAdapter struct {
	// ErrorHook, when non-nil, is invoked before every mutating operation.
	// Returning an error aborts the operation and leaves the stored state
	// untouched. It is meant for failure injection during testing.
	ErrorHook func(operation string) error

	mu       sync.Mutex
	policies map[string][][]string // key: section + "\x00" + policy type
	managed  map[string][][]string // key: domain
	parent   *MemoryAdapter        // set on transaction shadows
	finished bool                  // transaction shadow already committed or rolled back
}

// NewMemoryAdapter creates an empty in-memory adapter.
func NewMemoryAdapter() *MemoryAdapter {
	return &MemoryAdapter{
		policies: map[string][][]string{},
		managed:  map[string][][]string{},
	}
}

type memoryTransaction struct {
	shadow *MemoryAdapter
}

func bucketKey(sec, ptype string) string {
	return sec + "\x00" + ptype
}

func cloneRules(rules [][]string) [][]string {
	cloned := make([][]string, len(rules))
	for i, rule := range rules {
		cloned[i] = append([]string(nil), rule...)
	}
	return cloned
}

func ruleKey(rule []string) string {
	return strings.Join(rule, ",")
}

func (a *MemoryAdapter) hook(operation string) error {
	if a.ErrorHook != nil {
		return a.ErrorHook(operation)
	}
	return nil
}

func (a *MemoryAdapter) checkFinished() error {
	if a.finished {
		return errors.New("transaction has already been committed or rolled back")
	}
	return nil
}

// LoadPolicy loads all stored policy rules into the model.
func (a *MemoryAdapter) LoadPolicy(m model.Model) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for key, rules := range a.policies {
		parts := strings.SplitN(key, "\x00", 2)
		sec, ptype := parts[0], parts[1]
		for _, rule := range rules {
			if err := m.AddPolicy(sec, ptype, append([]string(nil), rule...)); err != nil {
				return err
			}
		}
	}
	return nil
}

// SavePolicy replaces the whole stored policy with the content of the model.
func (a *MemoryAdapter) SavePolicy(m model.Model) error {
	if err := a.hook(MemoryOpSavePolicy); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	next := make(map[string][][]string)
	for sec, assertions := range m {
		if sec != "p" && sec != "g" {
			continue
		}
		for ptype, ast := range assertions {
			next[bucketKey(sec, ptype)] = cloneRules(ast.Policy)
		}
	}
	a.policies = next
	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *MemoryAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	if err := a.hook(MemoryOpAddPolicy); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkFinished(); err != nil {
		return err
	}
	return a.addPolicyLocked(sec, ptype, rule)
}

func (a *MemoryAdapter) addPolicyLocked(sec, ptype string, rule []string) error {
	key := bucketKey(sec, ptype)
	for _, existing := range a.policies[key] {
		if ruleKey(existing) == ruleKey(rule) {
			return nil
		}
	}
	a.policies[key] = append(a.policies[key], append([]string(nil), rule...))
	return nil
}

// AddPolicies adds policy rules to the storage.
func (a *MemoryAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	if err := a.hook(MemoryOpAddPolicies); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkFinished(); err != nil {
		return err
	}
	for _, rule := range rules {
		if err := a.addPolicyLocked(sec, ptype, rule); err != nil {
			return err
		}
	}
	return nil
}

// RemovePolicy removes a policy rule from the storage.
func (a *MemoryAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	if err := a.hook(MemoryOpRemovePolicy); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkFinished(); err != nil {
		return err
	}
	a.removePoliciesLocked(sec, ptype, [][]string{rule})
	return nil
}

// RemovePolicies removes policy rules from the storage.
func (a *MemoryAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	if err := a.hook(MemoryOpRemovePolicies); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkFinished(); err != nil {
		return err
	}
	a.removePoliciesLocked(sec, ptype, rules)
	return nil
}

func (a *MemoryAdapter) removePoliciesLocked(sec, ptype string, rules [][]string) {
	key := bucketKey(sec, ptype)
	existing := a.policies[key]
	if len(existing) == 0 {
		return
	}

	removeSet := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		removeSet[ruleKey(rule)] = struct{}{}
	}

	kept := existing[:0]
	for _, rule := range existing {
		if _, drop := removeSet[ruleKey(rule)]; drop {
			continue
		}
		kept = append(kept, rule)
	}
	a.policies[key] = kept
}

// RemoveFilteredPolicy removes policy rules matching the filter.
// An empty string in fieldValues matches any value for that field.
func (a *MemoryAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	if err := a.hook(MemoryOpRemoveFilteredPolicy); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkFinished(); err != nil {
		return err
	}

	key := bucketKey(sec, ptype)
	existing := a.policies[key]
	kept := existing[:0]
	for _, rule := range existing {
		matched := true
		for i, fieldValue := range fieldValues {
			if fieldValue != "" && (fieldIndex+i >= len(rule) || rule[fieldIndex+i] != fieldValue) {
				matched = false
				break
			}
		}
		if !matched {
			kept = append(kept, rule)
		}
	}
	a.policies[key] = kept
	return nil
}

// UpdatePolicy updates a policy rule in the storage.
func (a *MemoryAdapter) UpdatePolicy(sec string, ptype string, oldRule, newRule []string) error {
	if err := a.hook(MemoryOpUpdatePolicy); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkFinished(); err != nil {
		return err
	}
	return a.updatePoliciesLocked(sec, ptype, [][]string{oldRule}, [][]string{newRule})
}

// UpdatePolicies updates policy rules in the storage.
func (a *MemoryAdapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	if err := a.hook(MemoryOpUpdatePolicies); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkFinished(); err != nil {
		return err
	}
	return a.updatePoliciesLocked(sec, ptype, oldRules, newRules)
}

func (a *MemoryAdapter) updatePoliciesLocked(sec, ptype string, oldRules, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return errors.New("the length of oldRules should be equal to the length of newRules")
	}

	key := bucketKey(sec, ptype)
	indexByKey := make(map[string]int, len(a.policies[key]))
	for i, rule := range a.policies[key] {
		indexByKey[ruleKey(rule)] = i
	}

	indexes := make([]int, len(oldRules))
	for i, oldRule := range oldRules {
		index, ok := indexByKey[ruleKey(oldRule)]
		if !ok {
			return errors.New("policy rule does not exist")
		}
		indexes[i] = index
	}
	for i, newRule := range newRules {
		if _, ok := indexByKey[ruleKey(newRule)]; ok {
			return errors.New("new policy rule already exists")
		}
		a.policies[key][indexes[i]] = append([]string(nil), newRule...)
	}
	return nil
}

// UpdateFilteredPolicies replaces the rules matching the filter with newRules.
func (a *MemoryAdapter) UpdateFilteredPolicies(sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	if err := a.hook(MemoryOpUpdateFilteredPolicies); err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkFinished(); err != nil {
		return nil, err
	}

	key := bucketKey(sec, ptype)
	var oldRules [][]string
	kept := make([][]string, 0, len(a.policies[key]))
	for _, rule := range a.policies[key] {
		matched := true
		for i, fieldValue := range fieldValues {
			if fieldValue != "" && (fieldIndex+i >= len(rule) || rule[fieldIndex+i] != fieldValue) {
				matched = false
				break
			}
		}
		if matched {
			oldRules = append(oldRules, rule)
			continue
		}
		kept = append(kept, rule)
	}
	for _, newRule := range newRules {
		kept = append(kept, append([]string(nil), newRule...))
	}
	a.policies[key] = kept
	return oldRules, nil
}

// LoadManagedPolicy loads the rule tuples owned by the management console in
// the given domain.
func (a *MemoryAdapter) LoadManagedPolicy(domain string) ([][]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return cloneRules(a.managed[domain]), nil
}

// ReplaceManagedPolicy replaces the ownership record of the given domain.
func (a *MemoryAdapter) ReplaceManagedPolicy(domain string, rules [][]string) error {
	if err := a.hook(MemoryOpReplaceManagedPolicy); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkFinished(); err != nil {
		return err
	}
	if len(rules) == 0 {
		delete(a.managed, domain)
		return nil
	}
	a.managed[domain] = cloneRules(rules)
	return nil
}

// BeginTransaction starts a transaction over a shadow copy of the state.
func (a *MemoryAdapter) BeginTransaction(_ context.Context) (TransactionContext, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkFinished(); err != nil {
		return nil, err
	}

	shadow := &MemoryAdapter{
		ErrorHook: a.ErrorHook,
		policies:  make(map[string][][]string, len(a.policies)),
		managed:   make(map[string][][]string, len(a.managed)),
		parent:    a,
	}
	for key, rules := range a.policies {
		shadow.policies[key] = cloneRules(rules)
	}
	for domain, rules := range a.managed {
		shadow.managed[domain] = cloneRules(rules)
	}
	return &memoryTransaction{shadow: shadow}, nil
}

// Commit publishes the transaction shadow to the root adapter.
func (tx *memoryTransaction) Commit() error {
	shadow := tx.shadow
	root := shadow.parent

	shadow.mu.Lock()
	if shadow.finished {
		shadow.mu.Unlock()
		return errors.New("transaction has already been committed or rolled back")
	}
	if err := shadow.hook(MemoryOpTransactionCommit); err != nil {
		shadow.mu.Unlock()
		return err
	}
	shadow.finished = true

	committedPolicies := make(map[string][][]string, len(shadow.policies))
	for key, rules := range shadow.policies {
		committedPolicies[key] = cloneRules(rules)
	}
	committedManaged := make(map[string][][]string, len(shadow.managed))
	for domain, rules := range shadow.managed {
		committedManaged[domain] = cloneRules(rules)
	}
	shadow.mu.Unlock()

	root.mu.Lock()
	defer root.mu.Unlock()
	root.policies = committedPolicies
	root.managed = committedManaged
	return nil
}

// Rollback discards the transaction shadow.
func (tx *memoryTransaction) Rollback() error {
	shadow := tx.shadow
	shadow.mu.Lock()
	defer shadow.mu.Unlock()
	if shadow.finished {
		return errors.New("transaction has already been committed or rolled back")
	}
	shadow.finished = true
	return nil
}

// GetAdapter returns the transaction scoped adapter that operates on the
// shadow state.
func (tx *memoryTransaction) GetAdapter() Adapter {
	return tx.shadow
}

// Compile-time interface satisfaction checks.
var (
	_ Adapter              = (*MemoryAdapter)(nil)
	_ BatchAdapter         = (*MemoryAdapter)(nil)
	_ UpdatableAdapter     = (*MemoryAdapter)(nil)
	_ TransactionalAdapter = (*MemoryAdapter)(nil)
	_ ManagedPolicyAdapter = (*MemoryAdapter)(nil)
)
