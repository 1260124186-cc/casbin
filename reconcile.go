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
	"strings"

	"github.com/casbin/casbin/v3/constant"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// Sentinel errors returned by ReconcileDomainPolicySnapshot. Callers can use
// errors.Is to distinguish the different failure classes.
var (
	// ErrReconcileUnsupportedAdapter is returned when the enforcer adapter
	// cannot provide transactional managed-policy storage.
	ErrReconcileUnsupportedAdapter = errors.New("reconcile requires a transactional adapter with managed policy ownership support")

	// ErrReconcileInvalidSnapshot is returned when the snapshot itself is
	// malformed (empty domain or rule tuples that do not fit the model).
	ErrReconcileInvalidSnapshot = errors.New("invalid domain policy snapshot")

	// ErrReconcileDuplicateRule is returned when the same rule tuple appears
	// more than once in a snapshot.
	ErrReconcileDuplicateRule = errors.New("duplicate rule in domain policy snapshot")

	// ErrReconcileConflictingRule is returned when a snapshot rule targets a
	// different domain than the snapshot domain.
	ErrReconcileConflictingRule = errors.New("conflicting rule in domain policy snapshot")

	// ErrReconcileOwnershipCorrupt is returned when persisted ownership
	// records cannot be interpreted.
	ErrReconcileOwnershipCorrupt = errors.New("corrupted managed policy ownership record")
)

// DomainPolicySnapshot is the full desired state of the rules a management
// console owns inside one domain. ReconcileDomainPolicySnapshot makes the
// stored and loaded policy converge to it without touching manual rules,
// other domains or role inheritance rules.
type DomainPolicySnapshot struct {
	// Domain is the domain this snapshot applies to. It must be non-empty.
	Domain string
	// Rules are the complete authorization policy rules (section "p") owned
	// by the console in Domain. Every rule must carry Domain at the model's
	// domain field. An empty Rules slice means the console owns no rule in
	// the domain anymore, so every previously owned rule is revoked.
	Rules [][]string
}

// prepareReconcile verifies the adapter capabilities, the domain-aware model
// and the snapshot content. It returns the expected rule arity, the domain
// field index, the validated desired rule set and the transactional adapter.
func (e *Enforcer) prepareReconcile(snapshot DomainPolicySnapshot) (int, int, [][]string, persist.TransactionalAdapter, error) {
	transactionalAdapter, ok := e.adapter.(persist.TransactionalAdapter)
	if !ok {
		return 0, 0, nil, nil, fmt.Errorf("%w: adapter does not implement persist.TransactionalAdapter", ErrReconcileUnsupportedAdapter)
	}

	assertion, err := e.model.GetAssertion("p", "p")
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("%w: %v", ErrReconcileInvalidSnapshot, err)
	}
	domainIndex, err := e.model.GetFieldIndex("p", constant.DomainIndex)
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("%w: model has no domain field: %v", ErrReconcileInvalidSnapshot, err)
	}

	desired, err := validateDomainPolicySnapshot(snapshot, len(assertion.Tokens), domainIndex)
	if err != nil {
		return 0, 0, nil, nil, err
	}
	return len(assertion.Tokens), domainIndex, desired, transactionalAdapter, nil
}

// ReconcileDomainPolicySnapshot reconciles the authorization rules of one
// domain against a management console snapshot.
//
// Only rules previously delivered by the console (tracked through the
// adapter's ManagedPolicyAdapter ownership records) are added, changed or
// revoked: manual rules of the same domain, rules of other domains and the
// role inheritance (section "g") are never modified. The policy changes and
// the ownership record are written in a single adapter transaction, and the
// in-memory model is swapped only after the transaction commits, so a failed
// reconciliation leaves the domain in its pre-call state. Re-applying the
// same snapshot is a no-op, and re-running the reconciliation after a crash
// before commit converges to the same result.
func (e *Enforcer) ReconcileDomainPolicySnapshot(snapshot DomainPolicySnapshot) error {
	tokenCount, domainIndex, desired, transactionalAdapter, err := e.prepareReconcile(snapshot)
	if err != nil {
		return err
	}

	txContext, err := transactionalAdapter.BeginTransaction(context.Background())
	if err != nil {
		return fmt.Errorf("failed to begin reconcile transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = txContext.Rollback()
		}
	}()

	txAdapter := txContext.GetAdapter()
	managedAdapter, ok := txAdapter.(persist.ManagedPolicyAdapter)
	if !ok {
		return fmt.Errorf("%w: transaction adapter does not implement persist.ManagedPolicyAdapter", ErrReconcileUnsupportedAdapter)
	}

	owned, err := managedAdapter.LoadManagedPolicy(snapshot.Domain)
	if err != nil {
		return fmt.Errorf("failed to load managed policy ownership: %w", err)
	}
	if corruptErr := validateOwnershipRecords(snapshot.Domain, owned, tokenCount, domainIndex); corruptErr != nil {
		return corruptErr
	}

	currentDomainRules, err := e.model.GetFilteredPolicy("p", "p", domainIndex, snapshot.Domain)
	if err != nil {
		return err
	}

	toAdd, toRemove := diffDomainRules(desired, owned, currentDomainRules)
	ownershipChanged := !sameRuleSet(owned, desired)

	// Nothing to converge: re-running an already applied snapshot is a no-op.
	if len(toAdd) == 0 && len(toRemove) == 0 && !ownershipChanged {
		if commitErr := txContext.Commit(); commitErr != nil {
			return fmt.Errorf("failed to commit reconcile transaction: %w", commitErr)
		}
		committed = true
		return nil
	}

	if err = persistReconcileChanges(txAdapter, managedAdapter, snapshot.Domain, desired, toAdd, toRemove, ownershipChanged); err != nil {
		return err
	}

	if err = txContext.Commit(); err != nil {
		return fmt.Errorf("failed to commit reconcile transaction: %w", err)
	}
	committed = true

	// The storage is committed. Swap the in-memory model on a copy so a
	// failure here never leaves the live model half-mutated; section "g" is
	// untouched and role managers are shared, so role inheritance stays valid.
	newModel := e.model.Copy()
	if err = applyReconcileToModel(newModel, toAdd, toRemove); err != nil {
		return fmt.Errorf("critical error: reconcile committed but model update failed: %w", err)
	}
	e.model = newModel
	e.resetPolicyCaches()
	e.invalidateMatcherMap()

	e.notifyReconcileWatcher(toAdd, toRemove)
	return nil
}

// persistReconcileChanges writes the reconciled policy diff and the new
// ownership record through the transaction scoped adapter.
func persistReconcileChanges(txAdapter persist.Adapter, managedAdapter persist.ManagedPolicyAdapter,
	domain string, desired, toAdd, toRemove [][]string, ownershipChanged bool) error {
	if err := removeReconcileRules(txAdapter, toRemove); err != nil {
		return err
	}
	if err := addReconcileRules(txAdapter, toAdd); err != nil {
		return err
	}
	if ownershipChanged {
		if err := managedAdapter.ReplaceManagedPolicy(domain, desired); err != nil {
			return fmt.Errorf("failed to persist managed policy ownership: %w", err)
		}
	}
	return nil
}

// removeReconcileRules revokes rules through the adapter, preferring the batch
// interface when the adapter supports it.
func removeReconcileRules(adapter persist.Adapter, rules [][]string) error {
	if len(rules) == 0 {
		return nil
	}
	if batchAdapter, isBatch := adapter.(persist.BatchAdapter); isBatch {
		if err := batchAdapter.RemovePolicies("p", "p", rules); err != nil {
			return fmt.Errorf("failed to revoke managed policies: %w", err)
		}
		return nil
	}
	for _, rule := range rules {
		if err := adapter.RemovePolicy("p", "p", rule); err != nil {
			return fmt.Errorf("failed to revoke managed policy: %w", err)
		}
	}
	return nil
}

// addReconcileRules stores rules through the adapter, preferring the batch
// interface when the adapter supports it.
func addReconcileRules(adapter persist.Adapter, rules [][]string) error {
	if len(rules) == 0 {
		return nil
	}
	if batchAdapter, isBatch := adapter.(persist.BatchAdapter); isBatch {
		if err := batchAdapter.AddPolicies("p", "p", rules); err != nil {
			return fmt.Errorf("failed to persist managed policies: %w", err)
		}
		return nil
	}
	for _, rule := range rules {
		if err := adapter.AddPolicy("p", "p", rule); err != nil {
			return fmt.Errorf("failed to persist managed policy: %w", err)
		}
	}
	return nil
}

// applyReconcileToModel applies the reconciled policy diff to a model copy.
func applyReconcileToModel(target model.Model, toAdd, toRemove [][]string) error {
	if len(toRemove) > 0 {
		if _, err := target.RemovePoliciesWithAffected("p", "p", toRemove); err != nil {
			return err
		}
	}
	if len(toAdd) > 0 {
		if err := target.AddPolicies("p", "p", toAdd); err != nil {
			return err
		}
	}
	return nil
}

// notifyReconcileWatcher emits the policy changes to the watcher, mirroring
// the behavior of the non-transactional management API.
func (e *Enforcer) notifyReconcileWatcher(toAdd, toRemove [][]string) {
	if !e.shouldNotify() {
		return
	}

	watcherEx, isWatcherEx := e.watcher.(persist.WatcherEx)
	if !isWatcherEx {
		_ = e.watcher.Update()
		return
	}
	if len(toRemove) > 0 {
		_ = watcherEx.UpdateForRemovePolicies("p", "p", toRemove...)
	}
	if len(toAdd) > 0 {
		_ = watcherEx.UpdateForAddPolicies("p", "p", toAdd...)
	}
}

// validateDomainPolicySnapshot normalizes and validates the incoming snapshot
// and returns a defensively copied slice of the desired rules.
func validateDomainPolicySnapshot(snapshot DomainPolicySnapshot, tokenCount, domainIndex int) ([][]string, error) {
	if snapshot.Domain == "" {
		return nil, fmt.Errorf("%w: domain must not be empty", ErrReconcileInvalidSnapshot)
	}

	desired := make([][]string, 0, len(snapshot.Rules))
	seen := make(map[string]struct{}, len(snapshot.Rules))
	for _, rule := range snapshot.Rules {
		if len(rule) != tokenCount {
			return nil, fmt.Errorf("%w: rule %v has %d fields, model expects %d", ErrReconcileInvalidSnapshot, rule, len(rule), tokenCount)
		}
		if domainIndex >= len(rule) || rule[domainIndex] != snapshot.Domain {
			return nil, fmt.Errorf("%w: rule %v does not belong to domain %q", ErrReconcileConflictingRule, rule, snapshot.Domain)
		}

		key := ruleIdentity(rule)
		if _, duplicated := seen[key]; duplicated {
			return nil, fmt.Errorf("%w: %v", ErrReconcileDuplicateRule, rule)
		}
		seen[key] = struct{}{}
		desired = append(desired, append([]string(nil), rule...))
	}
	return desired, nil
}

// validateOwnershipRecords makes sure every persisted ownership tuple is
// well-formed, belongs to the reconciled domain and is unique.
func validateOwnershipRecords(domain string, owned [][]string, tokenCount, domainIndex int) error {
	seen := make(map[string]struct{}, len(owned))
	for _, rule := range owned {
		if len(rule) != tokenCount {
			return fmt.Errorf("%w: owned rule %v has %d fields, model expects %d", ErrReconcileOwnershipCorrupt, rule, len(rule), tokenCount)
		}
		if domainIndex >= len(rule) || rule[domainIndex] != domain {
			return fmt.Errorf("%w: owned rule %v does not belong to domain %q", ErrReconcileOwnershipCorrupt, rule, domain)
		}
		key := ruleIdentity(rule)
		if _, duplicated := seen[key]; duplicated {
			return fmt.Errorf("%w: duplicate owned rule %v", ErrReconcileOwnershipCorrupt, rule)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// diffDomainRules computes the rules that must be added and the currently
// present owned rules that must be removed to converge to the desired set.
// Rules existing in the model but not owned by the console (manual rules) are
// never returned for removal.
func diffDomainRules(desired, owned, currentDomainRules [][]string) (toAdd [][]string, toRemove [][]string) {
	current := make(map[string]struct{}, len(currentDomainRules))
	for _, rule := range currentDomainRules {
		current[ruleIdentity(rule)] = struct{}{}
	}

	desiredSet := make(map[string]struct{}, len(desired))
	for _, rule := range desired {
		desiredSet[ruleIdentity(rule)] = struct{}{}
		if _, exists := current[ruleIdentity(rule)]; !exists {
			toAdd = append(toAdd, rule)
		}
	}

	removedSeen := make(map[string]struct{})
	for _, rule := range owned {
		key := ruleIdentity(rule)
		if _, stillDesired := desiredSet[key]; stillDesired {
			continue
		}
		if _, present := current[key]; !present {
			continue
		}
		if _, duplicated := removedSeen[key]; duplicated {
			continue
		}
		removedSeen[key] = struct{}{}
		toRemove = append(toRemove, append([]string(nil), rule...))
	}
	return toAdd, toRemove
}

// sameRuleSet reports whether two rule slices contain the same rule tuples,
// regardless of order.
func sameRuleSet(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, rule := range a {
		seen[ruleIdentity(rule)]++
	}
	for _, rule := range b {
		seen[ruleIdentity(rule)]--
		if seen[ruleIdentity(rule)] < 0 {
			return false
		}
	}
	return true
}

// ruleIdentity is the stable identity of a rule tuple. It matches the key
// scheme used by model.Assertion.PolicyMap.
func ruleIdentity(rule []string) string {
	return strings.Join(rule, model.DefaultSep)
}
