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
)

// Recover reconciles the durable commit log with the backends after a process
// restart. Committed records are replayed to lagging backends; the pending
// record is completed when its quorum is now reachable, otherwise every
// partial application is rolled back to the old version. Finally the
// in-memory enforcer is rebuilt from a backend holding the active version, so
// the three backends can never serve different permissions.
func (q *PolicyQuorum) Recover(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	commits, err := q.store.ListCommits(ctx)
	if err != nil {
		return err
	}
	for _, commit := range commits {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		switch commit.Status {
		case CommitCommitted:
			if replayErr := q.replayCommitted(ctx, commit); replayErr != nil {
				return replayErr
			}
		case CommitPending:
			if resolveErr := q.resolvePending(ctx, commit); resolveErr != nil {
				return resolveErr
			}
		case CommitAborted:
			// Aborted records already converged every backend to the base version.
		}
	}

	activeVersion, err := q.store.GetActiveVersion(ctx)
	if err != nil {
		return err
	}
	q.activeVersion = activeVersion
	return q.rebuildEnforcerModel(ctx)
}

// findPendingCommit returns the record still waiting for its quorum, if any.
func (q *PolicyQuorum) findPendingCommit(ctx context.Context) (*PolicyCommit, error) {
	commits, err := q.store.ListCommits(ctx)
	if err != nil {
		return nil, err
	}
	for i := len(commits) - 1; i >= 0; i-- {
		if commits[i].Status == CommitPending {
			return commits[i], nil
		}
	}
	return nil, nil
}

// replayCommitted ensures every backend carries a committed record.
func (q *PolicyQuorum) replayCommitted(ctx context.Context, commit *PolicyCommit) error {
	for _, name := range q.backendNames() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		state, stateErr := q.store.GetBackendState(ctx, name)
		if stateErr != nil {
			return stateErr
		}
		if state != nil && state.AppliedVersion >= commit.Version {
			continue
		}
		backend, ok := q.backend(name)
		if !ok {
			continue
		}
		if applyErr := q.applyCommitToBackend(ctx, backend, commit); applyErr != nil {
			return applyErr
		}
	}
	return nil
}

// resolvePending finishes a pending commit when the quorum is reachable and
// rolls the partial backends back to the base version otherwise.
func (q *PolicyQuorum) resolvePending(ctx context.Context, commit *PolicyCommit) error {
	q.applyEverywhere(ctx, commit)
	if len(commit.AppliedBackends) >= q.quorum {
		_, err := q.finalizeCommitted(ctx, commit)
		return err
	}
	return q.abortPending(ctx, commit)
}

// abortPending reverts the pending commit from every backend that had applied
// it and marks the record aborted. The active version never moved, so the
// remaining backends are already at the correct old version.
func (q *PolicyQuorum) abortPending(ctx context.Context, commit *PolicyCommit) error {
	for _, name := range q.backendNames() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		state, stateErr := q.store.GetBackendState(ctx, name)
		if stateErr != nil {
			return stateErr
		}
		if state == nil || state.AppliedVersion < commit.Version {
			continue
		}
		backend, ok := q.backend(name)
		if !ok {
			continue
		}
		if writeErr := q.writeOperationsToBackend(backend, commit.Operations, true); writeErr != nil {
			return writeErr
		}
		delete(commit.AppliedBackends, name)
		delete(commit.BackendErrors, name)
		marker := &BackendState{
			Name:           name,
			AppliedVersion: commit.BaseVersion,
			UpdatedAt:      time.Now().Unix(),
		}
		if saveErr := q.store.SaveBackendState(ctx, marker); saveErr != nil {
			return saveErr
		}
	}
	commit.Status = CommitAborted
	commit.AbortReason = fmt.Sprintf(
		"quorum %d not reached, %d backend(s) applied and were rolled back",
		q.quorum, len(commit.BackendErrors))
	commit.UpdatedAt = time.Now().Unix()
	return q.store.UpdateCommit(ctx, commit)
}

// rebuildEnforcerModel reloads the in-memory model from a backend that holds
// the active version, guaranteeing enforcement matches the committed rules.
func (q *PolicyQuorum) rebuildEnforcerModel(ctx context.Context) error {
	if q.activeVersion == 0 {
		empty := q.freshModel()
		q.enforcer.SetModel(empty)
		return nil
	}
	for _, name := range q.backendNames() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		state, stateErr := q.store.GetBackendState(ctx, name)
		if stateErr != nil {
			return stateErr
		}
		if state == nil || state.AppliedVersion != q.activeVersion {
			continue
		}
		backend, ok := q.backend(name)
		if !ok {
			continue
		}
		m := q.freshModel()
		if loadErr := backend.Adapter.LoadPolicy(m); loadErr != nil {
			return loadErr
		}
		q.enforcer.SetModel(m)
		return q.enforcer.BuildRoleLinks()
	}
	return ErrNoHealthyBackend
}
