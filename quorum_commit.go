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
	"fmt"
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/google/uuid"
)

// CommitPolicyQuorum turns one batch of policy operations into a persistent
// commit record and applies it backend by backend. The active policy version
// only advances once the configured quorum accepted the commit. When the
// quorum is not reached the active version stays unchanged and the pending
// record keeps the per-backend diagnostics for recovery or repair.
func (q *PolicyQuorum) CommitPolicyQuorum(ctx context.Context, operations []persist.PolicyOperation) (*PolicyCommit, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(operations) == 0 {
		return nil, fmt.Errorf("casbin: cannot commit an empty policy change")
	}
	pending, err := q.findPendingCommit(ctx)
	if err != nil {
		return nil, err
	}
	if pending != nil {
		return nil, fmt.Errorf("%w: version %d", ErrPendingCommitExists, pending.Version)
	}

	commit := q.newCommitRecord(ctx, operations)
	if createErr := q.store.CreateCommit(ctx, commit); createErr != nil {
		return nil, createErr
	}

	backendErrors := q.applyEverywhere(ctx, commit)
	if len(commit.AppliedBackends) >= q.quorum {
		return q.finalizeCommitted(ctx, commit)
	}
	return commit, q.quorumFailure(ctx, commit, backendErrors)
}

// newCommitRecord allocates the next monotonic version and the WAL record.
func (q *PolicyQuorum) newCommitRecord(ctx context.Context, operations []persist.PolicyOperation) *PolicyCommit {
	now := time.Now().Unix()
	version := q.activeVersion + 1
	commits, err := q.store.ListCommits(ctx)
	if err == nil && len(commits) > 0 {
		version = commits[len(commits)-1].Version + 1
	}
	return &PolicyCommit{
		ID:              uuid.New().String(),
		Version:         version,
		BaseVersion:     q.activeVersion,
		Operations:      cloneOperations(operations),
		Status:          CommitPending,
		AppliedBackends: map[string]bool{},
		BackendErrors:   map[string]string{},
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// applyEverywhere applies the commit to every backend once and records the
// failures. It stops scheduling new backends after context cancellation, but
// backends already applied keep their durable markers.
func (q *PolicyQuorum) applyEverywhere(ctx context.Context, commit *PolicyCommit) map[string]error {
	backendErrors := map[string]error{}
	for _, name := range q.backendNames() {
		if ctx.Err() != nil {
			backendErrors[name] = ctx.Err()
			continue
		}
		backend, ok := q.backend(name)
		if !ok {
			continue
		}
		if err := q.applyCommitToBackend(ctx, backend, commit); err != nil {
			backendErrors[name] = err
		}
	}
	return backendErrors
}

// finalizeCommitted marks the quorum as reached, advances the active version
// and gives the remaining backends one best-effort chance to catch up.
func (q *PolicyQuorum) finalizeCommitted(ctx context.Context, commit *PolicyCommit) (*PolicyCommit, error) {
	commit.Status = CommitCommitted
	commit.UpdatedAt = time.Now().Unix()
	if err := q.store.UpdateCommit(ctx, commit); err != nil {
		return nil, err
	}
	if err := q.store.SaveActiveVersion(ctx, commit.Version); err != nil {
		return nil, err
	}
	q.activeVersion = commit.Version

	if err := q.applyOperationsToEnforcer(commit.Operations); err != nil {
		return nil, err
	}

	q.convergeLaggards(ctx, commit)
	return commit, nil
}

// convergeLaggards retries backends that missed the quorum round so that a
// healthy cluster converges immediately; persistent failures stay diagnosable
// and are left for Repair.
func (q *PolicyQuorum) convergeLaggards(ctx context.Context, commit *PolicyCommit) {
	for _, name := range q.backendNames() {
		if commit.AppliedBackends[name] {
			continue
		}
		backend, ok := q.backend(name)
		if !ok {
			continue
		}
		_ = q.applyCommitToBackend(ctx, backend, commit)
	}
}

// quorumFailure persists the diagnostic state and builds the returned error.
func (q *PolicyQuorum) quorumFailure(ctx context.Context, commit *PolicyCommit, backendErrors map[string]error) error {
	commit.UpdatedAt = time.Now().Unix()
	_ = q.store.UpdateCommit(ctx, commit)
	return &QuorumUnavailableError{
		CommitID:      commit.ID,
		Version:       commit.Version,
		Applied:       len(commit.AppliedBackends),
		Quorum:        q.quorum,
		BackendErrors: backendErrors,
	}
}

// applyCommitToBackend idempotently applies one commit to one backend.
// Replaying the same commit never duplicates rules: the durable marker skips
// finished backends, and every write is diffed against the rules currently
// stored in the backend itself. Bookkeeping writes use a detached context:
// adapter calls are not cancellable anyway, so a canceled repair or recover
// only stops between commit units and never loses the marker of a unit that
// already finished.
func (q *PolicyQuorum) applyCommitToBackend(ctx context.Context, backend *QuorumBackend, commit *PolicyCommit) error {
	bookkeeping := context.Background()
	state, err := q.store.GetBackendState(bookkeeping, backend.Name)
	if err != nil {
		return err
	}
	if state != nil && state.AppliedVersion >= commit.Version {
		commit.AppliedBackends[backend.Name] = true
		return nil
	}

	if err := q.writeOperationsToBackend(backend, commit.Operations, false); err != nil {
		_ = q.recordBackendError(bookkeeping, backend.Name, state, err)
		commit.BackendErrors[backend.Name] = err.Error()
		commit.UpdatedAt = time.Now().Unix()
		_ = q.store.UpdateCommit(bookkeeping, commit)
		return err
	}

	commit.AppliedBackends[backend.Name] = true
	delete(commit.BackendErrors, backend.Name)
	commit.UpdatedAt = time.Now().Unix()
	if err := q.store.UpdateCommit(bookkeeping, commit); err != nil {
		return err
	}
	return q.store.SaveBackendState(bookkeeping, &BackendState{
		Name:           backend.Name,
		AppliedVersion: commit.Version,
		UpdatedAt:      time.Now().Unix(),
	})
}

// recordBackendError keeps the backend marker but attaches the latest error.
func (q *PolicyQuorum) recordBackendError(ctx context.Context, name string, state *BackendState, cause error) error {
	appliedVersion := int64(0)
	if state != nil {
		appliedVersion = state.AppliedVersion
	}
	return q.store.SaveBackendState(ctx, &BackendState{
		Name:           name,
		AppliedVersion: appliedVersion,
		LastError:      cause.Error(),
		UpdatedAt:      time.Now().Unix(),
	})
}

// writeOperationsToBackend diffs the operations against the rules physically
// stored in the backend and only writes the missing delta. When inverse is
// true the operations are reverted, which is used by abort recovery.
func (q *PolicyQuorum) writeOperationsToBackend(backend *QuorumBackend, operations []persist.PolicyOperation, inverse bool) error {
	current := q.freshModel()
	if err := backend.Adapter.LoadPolicy(current); err != nil {
		return err
	}
	for _, op := range operations {
		effective := op
		if inverse {
			effective = inverseOperation(op)
		}
		if err := q.writeOneOperation(backend.Adapter, current, effective); err != nil {
			return err
		}
	}
	return nil
}

// writeOneOperation applies a single operation using only the delta that is
// not already reflected in the backend's loaded model.
func (q *PolicyQuorum) writeOneOperation(adapter persist.Adapter, current model.Model, op persist.PolicyOperation) error {
	switch op.Type {
	case persist.OperationAdd:
		return q.writeAdd(adapter, current, op)
	case persist.OperationRemove:
		return q.writeRemove(adapter, current, op)
	case persist.OperationUpdate:
		return q.writeUpdate(adapter, current, op)
	default:
		return fmt.Errorf("casbin: unknown policy operation type %d", op.Type)
	}
}

// writeAdd adds only the rules that are absent from the backend.
func (q *PolicyQuorum) writeAdd(adapter persist.Adapter, current model.Model, op persist.PolicyOperation) error {
	missing := make([][]string, 0, len(op.Rules))
	for _, rule := range op.Rules {
		has, err := current.HasPolicy(op.Section, op.PolicyType, rule)
		if err != nil {
			return err
		}
		if !has {
			missing = append(missing, rule)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return adapterAddPolicies(adapter, op.Section, op.PolicyType, missing)
}

// writeRemove removes only the rules still present in the backend.
func (q *PolicyQuorum) writeRemove(adapter persist.Adapter, current model.Model, op persist.PolicyOperation) error {
	present := make([][]string, 0, len(op.Rules))
	for _, rule := range op.Rules {
		has, err := current.HasPolicy(op.Section, op.PolicyType, rule)
		if err != nil {
			return err
		}
		if has {
			present = append(present, rule)
		}
	}
	if len(present) == 0 {
		return nil
	}
	return adapterRemovePolicies(adapter, op.Section, op.PolicyType, present)
}

// writeUpdate applies only the update pairs whose old rule is still present
// and whose new rule is not present yet.
func (q *PolicyQuorum) writeUpdate(adapter persist.Adapter, current model.Model, op persist.PolicyOperation) error {
	oldPending := make([][]string, 0, len(op.OldRules))
	newPending := make([][]string, 0, len(op.Rules))
	for i, oldRule := range op.OldRules {
		hasOld, err := current.HasPolicy(op.Section, op.PolicyType, oldRule)
		if err != nil {
			return err
		}
		hasNew, err := current.HasPolicy(op.Section, op.PolicyType, op.Rules[i])
		if err != nil {
			return err
		}
		if hasOld && !hasNew {
			oldPending = append(oldPending, oldRule)
			newPending = append(newPending, op.Rules[i])
		}
	}
	if len(oldPending) == 0 {
		return nil
	}
	return adapterUpdatePolicies(adapter, op.Section, op.PolicyType, oldPending, newPending)
}

// applyOperationsToEnforcer advances the in-memory model of the enforcer to
// the newly active version and rebuilds role links for grouping changes.
func (q *PolicyQuorum) applyOperationsToEnforcer(operations []persist.PolicyOperation) error {
	enforcerModel := q.enforcer.GetModel()
	needRoleRebuild := false
	for _, op := range operations {
		if op.Section == "g" {
			needRoleRebuild = true
		}
		if err := applyOperationToModel(enforcerModel, op); err != nil {
			return err
		}
	}
	q.enforcer.invalidateMatcherMap()
	if needRoleRebuild && q.enforcer.autoBuildRoleLinks {
		return q.enforcer.BuildRoleLinks()
	}
	return nil
}

// applyOperationToModel applies one operation to an in-memory model.
func applyOperationToModel(enforcerModel model.Model, op persist.PolicyOperation) error {
	switch op.Type {
	case persist.OperationAdd:
		for _, rule := range op.Rules {
			if err := enforcerModel.AddPolicy(op.Section, op.PolicyType, rule); err != nil {
				return err
			}
		}
	case persist.OperationRemove:
		for _, rule := range op.Rules {
			if _, err := enforcerModel.RemovePolicy(op.Section, op.PolicyType, rule); err != nil {
				return err
			}
		}
	case persist.OperationUpdate:
		for i, oldRule := range op.OldRules {
			if _, err := enforcerModel.RemovePolicy(op.Section, op.PolicyType, oldRule); err != nil {
				return err
			}
			if err := enforcerModel.AddPolicy(op.Section, op.PolicyType, op.Rules[i]); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("casbin: unknown policy operation type %d", op.Type)
	}
	return nil
}

// inverseOperation returns the operation that undoes op.
func inverseOperation(op persist.PolicyOperation) persist.PolicyOperation {
	switch op.Type {
	case persist.OperationAdd:
		return NewRemovePolicyOperation(op.Section, op.PolicyType, op.Rules)
	case persist.OperationRemove:
		return NewAddPolicyOperation(op.Section, op.PolicyType, op.Rules)
	case persist.OperationUpdate:
		return NewUpdatePolicyOperation(op.Section, op.PolicyType, op.Rules, op.OldRules)
	default:
		return NewUpdatePolicyOperation(op.Section, op.PolicyType, op.Rules, op.OldRules)
	}
}

// cloneOperations returns a deep copy of buffered operations.
func cloneOperations(operations []persist.PolicyOperation) []persist.PolicyOperation {
	cloned := make([]persist.PolicyOperation, len(operations))
	for i, op := range operations {
		cloned[i] = persist.PolicyOperation{
			Type:       op.Type,
			Section:    op.Section,
			PolicyType: op.PolicyType,
			Rules:      cloneRules(op.Rules),
			OldRules:   cloneRules(op.OldRules),
		}
	}
	return cloned
}

// adapterAddPolicies writes adds through the batch API when available.
func adapterAddPolicies(adapter persist.Adapter, sec string, ptype string, rules [][]string) error {
	if batchAdapter, ok := adapter.(persist.BatchAdapter); ok {
		return batchAdapter.AddPolicies(sec, ptype, rules)
	}
	for _, rule := range rules {
		if err := adapter.AddPolicy(sec, ptype, rule); err != nil {
			return err
		}
	}
	return nil
}

// adapterRemovePolicies writes removes through the batch API when available.
func adapterRemovePolicies(adapter persist.Adapter, sec string, ptype string, rules [][]string) error {
	if batchAdapter, ok := adapter.(persist.BatchAdapter); ok {
		return batchAdapter.RemovePolicies(sec, ptype, rules)
	}
	for _, rule := range rules {
		if err := adapter.RemovePolicy(sec, ptype, rule); err != nil {
			return err
		}
	}
	return nil
}

// adapterUpdatePolicies writes updates through the updater API when available
// and falls back to remove plus add for plain adapters.
func adapterUpdatePolicies(adapter persist.Adapter, sec string, ptype string, oldRules [][]string, newRules [][]string) error {
	if updateAdapter, ok := adapter.(persist.UpdatableAdapter); ok {
		return updateAdapter.UpdatePolicies(sec, ptype, oldRules, newRules)
	}
	for i, oldRule := range oldRules {
		if err := adapter.RemovePolicy(sec, ptype, oldRule); err != nil {
			return err
		}
		if err := adapter.AddPolicy(sec, ptype, newRules[i]); err != nil {
			return err
		}
	}
	return nil
}
