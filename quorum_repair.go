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
)

// BackendRepairResult summarizes one repair run for one backend.
type BackendRepairResult struct {
	// Name is the repaired backend name.
	Name string
	// FromVersion is the version the backend started the run at.
	FromVersion int64
	// ToVersion is the version the backend reached, equal to FromVersion on failure.
	ToVersion int64
	// ReplayedCommits lists the commit versions applied during the run.
	ReplayedCommits []int64
	// Error holds the failure message, empty when the backend is up to date.
	Error string
}

// RepairReport is the outcome of a Repair run.
type RepairReport struct {
	// ActiveVersion is the version every backend converges to.
	ActiveVersion int64
	// Results contains one entry per backend.
	Results []BackendRepairResult
	// RemainingLagging lists backends that did not reach the active version.
	RemainingLagging []string
	// Interrupted is true when the run stopped because the context was canceled.
	Interrupted bool
}

// Repair brings lagging backends back to the active version by replaying the
// already committed records in order. Every applied commit is marked durably,
// so canceling the context and running Repair again simply resumes where the
// previous run stopped; replaying a commit twice never changes rules twice.
func (q *PolicyQuorum) Repair(ctx context.Context) (*RepairReport, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	activeVersion, err := q.store.GetActiveVersion(ctx)
	if err != nil {
		return nil, err
	}
	commits, err := q.committedCommitsUntil(ctx, activeVersion)
	if err != nil {
		return nil, err
	}

	report := &RepairReport{ActiveVersion: activeVersion}
	for _, name := range q.backendNames() {
		result := q.repairBackend(ctx, name, commits)
		report.Results = append(report.Results, result)
		if result.ToVersion < activeVersion {
			report.RemainingLagging = append(report.RemainingLagging, name)
		}
		if ctx.Err() != nil {
			report.Interrupted = true
			return report, ctx.Err()
		}
	}
	return report, nil
}

// committedCommitsUntil returns the committed records up to and including the
// active version, ordered for sequential replay.
func (q *PolicyQuorum) committedCommitsUntil(ctx context.Context, activeVersion int64) ([]*PolicyCommit, error) {
	all, err := q.store.ListCommits(ctx)
	if err != nil {
		return nil, err
	}
	commits := make([]*PolicyCommit, 0, len(all))
	for _, commit := range all {
		if commit.Status == CommitCommitted && commit.Version <= activeVersion {
			commits = append(commits, commit)
		}
	}
	return commits, nil
}

// repairBackend replays the missing commits of one backend and returns the
// per-backend result. Context cancellation stops the replay but keeps every
// already applied commit durable.
func (q *PolicyQuorum) repairBackend(ctx context.Context, name string, commits []*PolicyCommit) BackendRepairResult {
	state, stateErr := q.store.GetBackendState(ctx, name)
	result := BackendRepairResult{Name: name}
	if stateErr != nil {
		result.Error = stateErr.Error()
		return result
	}
	if state != nil {
		result.FromVersion = state.AppliedVersion
	}
	result.ToVersion = result.FromVersion

	backend, ok := q.backend(name)
	if !ok {
		result.Error = ErrInvalidQuorumConfig.Error()
		return result
	}
	for _, commit := range commits {
		if commit.Version <= result.ToVersion {
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			result.Error = ctxErr.Error()
			return result
		}
		if applyErr := q.applyCommitToBackend(ctx, backend, commit); applyErr != nil {
			result.Error = applyErr.Error()
			return result
		}
		result.ReplayedCommits = append(result.ReplayedCommits, commit.Version)
		result.ToVersion = commit.Version
	}
	return result
}
