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
	"sync"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// Sentinel errors returned by the quorum commit machinery.
var (
	// ErrQuorumNotReached is returned when fewer backends than required
	// applied a commit, so the active policy version must stay unchanged.
	ErrQuorumNotReached = errors.New("casbin: policy commit quorum not reached")
	// ErrPendingCommitExists is returned when a new commit is requested while
	// an earlier commit is still waiting for its quorum.
	ErrPendingCommitExists = errors.New("casbin: a pending policy commit already exists")
	// ErrCommitNotFound is returned when a commit record cannot be located.
	ErrCommitNotFound = errors.New("casbin: policy commit not found")
	// ErrCommitAlreadyExists is returned when a commit ID or version is already recorded.
	ErrCommitAlreadyExists = errors.New("casbin: policy commit already exists")
	// ErrNoHealthyBackend is returned when no backend can serve the active
	// policy version, for example while rebuilding the in-memory model.
	ErrNoHealthyBackend = errors.New("casbin: no backend holds the active policy version")
	// ErrInvalidQuorumConfig is returned when the quorum configuration is invalid.
	ErrInvalidQuorumConfig = errors.New("casbin: invalid quorum configuration")
)

// CommitStatus is the lifecycle state of a persistent policy commit record.
type CommitStatus int

const (
	// CommitPending means the record is persisted but its quorum is not reached yet.
	CommitPending CommitStatus = iota
	// CommitCommitted means the quorum was reached and the active version advanced.
	CommitCommitted
	// CommitAborted means the quorum could never be reached and every partial
	// application was rolled back to the commit's base version.
	CommitAborted
)

// QuorumBackend is one named policy backend taking part in the quorum,
// for example the online, mirror or disaster recovery adapter.
type QuorumBackend struct {
	// Name uniquely identifies the backend inside one PolicyQuorum.
	Name string
	// Adapter stores the policy rules of this backend.
	Adapter persist.Adapter
}

// PolicyCommit is the durable record of one policy change.
// The same record drives the initial application, crash recovery, replay and
// repair, therefore it must never be mutated once the quorum is reached.
type PolicyCommit struct {
	// ID is the unique identifier of the commit.
	ID string
	// Version is the monotonically increasing policy version created by the commit.
	Version int64
	// BaseVersion is the active version the commit is based on.
	BaseVersion int64
	// Operations are the add, remove and update rule changes of the commit.
	Operations []persist.PolicyOperation
	// Status is the current lifecycle state of the commit.
	Status CommitStatus
	// AppliedBackends records the backends that durably applied this commit.
	AppliedBackends map[string]bool
	// BackendErrors keeps the latest diagnostic error per backend, if any.
	BackendErrors map[string]string
	// AbortReason explains why the commit was aborted, empty otherwise.
	AbortReason string
	// CreatedAt is when the record was first persisted.
	CreatedAt int64
	// UpdatedAt is when the record was last persisted.
	UpdatedAt int64
}

// BackendState is the durable per-backend progress marker.
type BackendState struct {
	// Name is the backend name.
	Name string
	// AppliedVersion is the highest commit version durably applied by the backend.
	AppliedVersion int64
	// LastError is the latest error seen while applying a commit, empty on success.
	LastError string
	// UpdatedAt is when the marker was last persisted, as a unix timestamp.
	UpdatedAt int64
}

// BackendStatusView is one backend row of the quorum status snapshot.
type BackendStatusView struct {
	// Name is the backend name.
	Name string
	// AppliedVersion is the version currently applied on the backend.
	AppliedVersion int64
	// UpToDate reports whether the backend matches the active version.
	UpToDate bool
	// LastError is the latest recorded diagnostic error.
	LastError string
}

// QuorumStatus is a diagnostic snapshot of the whole quorum.
type QuorumStatus struct {
	// ActiveVersion is the version currently served by the enforcer.
	ActiveVersion int64
	// Quorum is the number of backends required to advance the active version.
	Quorum int
	// BackendCount is the total number of configured backends.
	BackendCount int
	// Backends reports the applied version of every backend.
	Backends []BackendStatusView
	// Pending is the commit still waiting for its quorum, or nil when there is none.
	Pending *PolicyCommit
}

// PolicyQuorum coordinates policy commits across several independent adapters.
// A commit is durably recorded first, applied backend by backend and only
// advances the active policy version once a majority of backends accepted it.
type PolicyQuorum struct {
	enforcer      *Enforcer
	backends      map[string]*QuorumBackend
	backendOrder  []string
	store         CommitStore
	quorum        int
	activeVersion int64
	mu            sync.RWMutex
}

// NewPolicyQuorum creates a quorum manager for the given model and backends.
// The commit records and backend markers are read from and written to store.
// Call Recover after construction so crash leftovers are completed or rolled
// back before the enforcer serves traffic.
func NewPolicyQuorum(modelPath string, backends []QuorumBackend, store CommitStore) (*PolicyQuorum, error) {
	if store == nil {
		return nil, errors.New("casbin: commit store must not be nil")
	}
	if len(backends) == 0 {
		return nil, ErrInvalidQuorumConfig
	}

	backendMap := make(map[string]*QuorumBackend, len(backends))
	order := make([]string, 0, len(backends))
	for _, backend := range backends {
		if backend.Name == "" {
			return nil, ErrInvalidQuorumConfig
		}
		if backend.Adapter == nil {
			return nil, ErrInvalidQuorumConfig
		}
		if _, exists := backendMap[backend.Name]; exists {
			return nil, ErrInvalidQuorumConfig
		}
		backendCopy := backend
		backendMap[backend.Name] = &backendCopy
		order = append(order, backend.Name)
	}

	m, err := model.NewModelFromFile(modelPath)
	if err != nil {
		return nil, err
	}
	enforcer, err := NewEnforcer(m)
	if err != nil {
		return nil, err
	}

	activeVersion, err := store.GetActiveVersion(context.Background())
	if err != nil {
		return nil, err
	}

	return &PolicyQuorum{
		enforcer:      enforcer,
		backends:      backendMap,
		backendOrder:  order,
		store:         store,
		quorum:        len(backends)/2 + 1,
		activeVersion: activeVersion,
	}, nil
}

// Enforcer returns the enforcer serving the active policy version.
func (q *PolicyQuorum) Enforcer() *Enforcer {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.enforcer
}

// Enforce is a convenience proxy to the enforcer of the active version.
func (q *PolicyQuorum) Enforce(rvals ...interface{}) (bool, error) {
	q.mu.RLock()
	enforcer := q.enforcer
	q.mu.RUnlock()
	return enforcer.Enforce(rvals...)
}

// ActiveVersion returns the policy version currently served by the enforcer.
func (q *PolicyQuorum) ActiveVersion() int64 {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.activeVersion
}

// Quorum returns the number of backends required to commit a new version.
func (q *PolicyQuorum) Quorum() int {
	return q.quorum
}

// Status returns a diagnostic snapshot containing the active version, every
// backend's applied version and the pending commit when one exists.
func (q *PolicyQuorum) Status(ctx context.Context) (*QuorumStatus, error) {
	q.mu.RLock()
	status := &QuorumStatus{
		ActiveVersion: q.activeVersion,
		Quorum:        q.quorum,
		BackendCount:  len(q.backendOrder),
		Backends:      make([]BackendStatusView, 0, len(q.backendOrder)),
	}
	q.mu.RUnlock()

	for _, name := range q.backendNames() {
		state, err := q.store.GetBackendState(ctx, name)
		if err != nil {
			return nil, err
		}
		view := BackendStatusView{Name: name, UpToDate: true}
		if state != nil {
			view.AppliedVersion = state.AppliedVersion
			view.LastError = state.LastError
			view.UpToDate = state.AppliedVersion == status.ActiveVersion
		} else {
			view.UpToDate = status.ActiveVersion == 0
		}
		status.Backends = append(status.Backends, view)
	}

	commits, err := q.store.ListCommits(ctx)
	if err != nil {
		return nil, err
	}
	for _, commit := range commits {
		if commit.Status == CommitPending {
			status.Pending = commit
			break
		}
	}

	return status, nil
}

// backendNames returns the configured backend names in their stable order.
// The backend set is immutable after construction, so no lock is needed and
// the helper is safe to call while the commit or recover lock is held.
func (q *PolicyQuorum) backendNames() []string {
	return q.backendOrder
}

// backend looks up a configured backend by name. The map is immutable after
// construction, so no lock is needed.
func (q *PolicyQuorum) backend(name string) (*QuorumBackend, bool) {
	backend, ok := q.backends[name]
	return backend, ok
}

// freshModel returns a rule-free copy of the current model definition,
// used to inspect the rules actually stored in an individual backend.
func (q *PolicyQuorum) freshModel() model.Model {
	m := q.enforcer.GetModel().Copy()
	m.ClearPolicy()
	return m
}

// NewAddPolicyOperation builds an add operation for a commit record.
func NewAddPolicyOperation(sec string, ptype string, rules [][]string) persist.PolicyOperation {
	return persist.PolicyOperation{
		Type:       persist.OperationAdd,
		Section:    sec,
		PolicyType: ptype,
		Rules:      cloneRules(rules),
	}
}

// NewRemovePolicyOperation builds a remove operation for a commit record.
func NewRemovePolicyOperation(sec string, ptype string, rules [][]string) persist.PolicyOperation {
	return persist.PolicyOperation{
		Type:       persist.OperationRemove,
		Section:    sec,
		PolicyType: ptype,
		Rules:      cloneRules(rules),
	}
}

// NewUpdatePolicyOperation builds an update operation for a commit record.
func NewUpdatePolicyOperation(sec string, ptype string, oldRules [][]string, newRules [][]string) persist.PolicyOperation {
	return persist.PolicyOperation{
		Type:       persist.OperationUpdate,
		Section:    sec,
		PolicyType: ptype,
		Rules:      cloneRules(newRules),
		OldRules:   cloneRules(oldRules),
	}
}

// cloneRules returns a deep copy of policy rules so commit records stay
// independent of caller-owned slices.
func cloneRules(rules [][]string) [][]string {
	cloned := make([][]string, len(rules))
	for i, rule := range rules {
		cloned[i] = append([]string(nil), rule...)
	}
	return cloned
}

// QuorumUnavailableError wraps the per-backend failures of a commit that did
// not reach its quorum. It matches ErrQuorumNotReached through errors.Is.
type QuorumUnavailableError struct {
	// CommitID is the pending commit that failed to reach its quorum.
	CommitID string
	// Version is the version the pending commit would have produced.
	Version int64
	// Applied is the number of backends that applied the commit.
	Applied int
	// Quorum is the number of backends that were required.
	Quorum int
	// BackendErrors contains the failure reason of every failed backend.
	BackendErrors map[string]error
}

// Error implements the error interface.
func (e *QuorumUnavailableError) Error() string {
	return ErrQuorumNotReached.Error()
}

// Is lets errors.Is match ErrQuorumNotReached.
func (e *QuorumUnavailableError) Is(target error) bool {
	return target == ErrQuorumNotReached
}
