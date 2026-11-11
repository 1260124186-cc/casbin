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
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/casbin/casbin/v3/persist"
)

// CommitStore persists policy commit records, per-backend progress markers
// and the active policy version. Implementations must be durable: once a
// method returns nil, the change has to survive a process crash.
type CommitStore interface {
	// CreateCommit persists a brand new commit record. It fails when the
	// commit ID or version already exists.
	CreateCommit(ctx context.Context, commit *PolicyCommit) error
	// UpdateCommit persists a change to an existing commit record.
	UpdateCommit(ctx context.Context, commit *PolicyCommit) error
	// GetCommit returns the commit with the given ID, or nil when it is absent.
	GetCommit(ctx context.Context, id string) (*PolicyCommit, error)
	// GetCommitByVersion returns the commit at the given version, or nil when absent.
	GetCommitByVersion(ctx context.Context, version int64) (*PolicyCommit, error)
	// ListCommits returns every commit ordered by ascending version.
	ListCommits(ctx context.Context) ([]*PolicyCommit, error)
	// GetBackendState returns the marker of one backend, or nil when absent.
	GetBackendState(ctx context.Context, name string) (*BackendState, error)
	// ListBackendStates returns every backend marker ordered by backend name.
	ListBackendStates(ctx context.Context) ([]*BackendState, error)
	// SaveBackendState creates or replaces a backend progress marker.
	SaveBackendState(ctx context.Context, state *BackendState) error
	// GetActiveVersion returns the durably recorded active version, zero initially.
	GetActiveVersion(ctx context.Context) (int64, error)
	// SaveActiveVersion persists the active policy version.
	SaveActiveVersion(ctx context.Context, version int64) error
}

// cloneCommit returns a deep copy so callers cannot mutate stored records.
func cloneCommit(commit *PolicyCommit) *PolicyCommit {
	if commit == nil {
		return nil
	}
	cloned := &PolicyCommit{
		ID:              commit.ID,
		Version:         commit.Version,
		BaseVersion:     commit.BaseVersion,
		Status:          commit.Status,
		AbortReason:     commit.AbortReason,
		CreatedAt:       commit.CreatedAt,
		UpdatedAt:       commit.UpdatedAt,
		AppliedBackends: cloneBoolMap(commit.AppliedBackends),
		BackendErrors:   cloneStringMap(commit.BackendErrors),
	}
	if commit.Operations != nil {
		cloned.Operations = make([]persist.PolicyOperation, 0, len(commit.Operations))
		for _, op := range commit.Operations {
			cloned.Operations = append(cloned.Operations, persist.PolicyOperation{
				Type:       op.Type,
				Section:    op.Section,
				PolicyType: op.PolicyType,
				Rules:      cloneRules(op.Rules),
				OldRules:   cloneRules(op.OldRules),
			})
		}
	}
	return cloned
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	if in == nil {
		return nil
	}
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// MemoryCommitStore is an in-process CommitStore. It is concurrency safe and
// intended for tests and embeddings that provide their own durability.
type MemoryCommitStore struct {
	mu            sync.RWMutex
	commitsByID   map[string]*PolicyCommit
	commits       []*PolicyCommit
	backendStates map[string]*BackendState
	activeVersion int64
}

// NewMemoryCommitStore creates an empty in-memory commit store.
func NewMemoryCommitStore() *MemoryCommitStore {
	return &MemoryCommitStore{
		commitsByID:   map[string]*PolicyCommit{},
		backendStates: map[string]*BackendState{},
	}
}

// CreateCommit implements CommitStore.
func (s *MemoryCommitStore) CreateCommit(ctx context.Context, commit *PolicyCommit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.commitsByID[commit.ID]; exists {
		return ErrCommitAlreadyExists
	}
	for _, existing := range s.commits {
		if existing.Version == commit.Version {
			return ErrCommitAlreadyExists
		}
	}
	stored := cloneCommit(commit)
	s.commitsByID[commit.ID] = stored
	s.commits = append(s.commits, stored)
	return nil
}

// UpdateCommit implements CommitStore.
func (s *MemoryCommitStore) UpdateCommit(ctx context.Context, commit *PolicyCommit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.commitsByID[commit.ID]; !exists {
		return ErrCommitNotFound
	}
	stored := cloneCommit(commit)
	s.commitsByID[commit.ID] = stored
	for i, existing := range s.commits {
		if existing.ID == commit.ID {
			s.commits[i] = stored
			break
		}
	}
	return nil
}

// GetCommit implements CommitStore.
func (s *MemoryCommitStore) GetCommit(ctx context.Context, id string) (*PolicyCommit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCommit(s.commitsByID[id]), nil
}

// GetCommitByVersion implements CommitStore.
func (s *MemoryCommitStore) GetCommitByVersion(ctx context.Context, version int64) (*PolicyCommit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, commit := range s.commits {
		if commit.Version == version {
			return cloneCommit(commit), nil
		}
	}
	return nil, nil
}

// ListCommits implements CommitStore.
func (s *MemoryCommitStore) ListCommits(ctx context.Context) ([]*PolicyCommit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*PolicyCommit, 0, len(s.commits))
	for _, commit := range s.commits {
		out = append(out, cloneCommit(commit))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// GetBackendState implements CommitStore.
func (s *MemoryCommitStore) GetBackendState(ctx context.Context, name string) (*BackendState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.backendStates[name]
	if state == nil {
		return nil, nil
	}
	cloned := *state
	return &cloned, nil
}

// ListBackendStates implements CommitStore.
func (s *MemoryCommitStore) ListBackendStates(ctx context.Context) ([]*BackendState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*BackendState, 0, len(s.backendStates))
	for _, state := range s.backendStates {
		cloned := *state
		out = append(out, &cloned)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// SaveBackendState implements CommitStore.
func (s *MemoryCommitStore) SaveBackendState(ctx context.Context, state *BackendState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := *state
	s.backendStates[state.Name] = &cloned
	return nil
}

// GetActiveVersion implements CommitStore.
func (s *MemoryCommitStore) GetActiveVersion(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeVersion, nil
}

// SaveActiveVersion implements CommitStore.
func (s *MemoryCommitStore) SaveActiveVersion(ctx context.Context, version int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeVersion = version
	return nil
}

// fileOperationDTO is the tagged on-disk representation of one operation.
type fileOperationDTO struct {
	Type       int        `json:"type"`
	Section    string     `json:"section"`
	PolicyType string     `json:"policy_type"`
	Rules      [][]string `json:"rules"`
	OldRules   [][]string `json:"old_rules,omitempty"`
}

// fileCommitDTO is the tagged on-disk representation of a commit record.
type fileCommitDTO struct {
	ID              string             `json:"id"`
	Version         int64              `json:"version"`
	BaseVersion     int64              `json:"base_version"`
	Operations      []fileOperationDTO `json:"operations"`
	Status          int                `json:"status"`
	AppliedBackends map[string]bool    `json:"applied_backends"`
	BackendErrors   map[string]string  `json:"backend_errors,omitempty"`
	AbortReason     string             `json:"abort_reason,omitempty"`
	CreatedAt       int64              `json:"created_at"`
	UpdatedAt       int64              `json:"updated_at"`
}

// fileBackendStateDTO is the tagged on-disk representation of a marker.
type fileBackendStateDTO struct {
	Name           string `json:"name"`
	AppliedVersion int64  `json:"applied_version"`
	LastError      string `json:"last_error,omitempty"`
	UpdatedAt      int64  `json:"updated_at"`
}

// fileStoreData is the single atomically rewritten JSON document.
type fileStoreData struct {
	ActiveVersion int64                          `json:"active_version"`
	Commits       []fileCommitDTO                `json:"commits"`
	BackendStates map[string]fileBackendStateDTO `json:"backend_states"`
}

func toFileCommit(commit *PolicyCommit) fileCommitDTO {
	operations := make([]fileOperationDTO, 0, len(commit.Operations))
	for _, op := range commit.Operations {
		operations = append(operations, fileOperationDTO{
			Type:       int(op.Type),
			Section:    op.Section,
			PolicyType: op.PolicyType,
			Rules:      cloneRules(op.Rules),
			OldRules:   cloneRules(op.OldRules),
		})
	}
	return fileCommitDTO{
		ID:              commit.ID,
		Version:         commit.Version,
		BaseVersion:     commit.BaseVersion,
		Operations:      operations,
		Status:          int(commit.Status),
		AppliedBackends: cloneBoolMap(commit.AppliedBackends),
		BackendErrors:   cloneStringMap(commit.BackendErrors),
		AbortReason:     commit.AbortReason,
		CreatedAt:       commit.CreatedAt,
		UpdatedAt:       commit.UpdatedAt,
	}
}

func fromFileCommit(dto fileCommitDTO) *PolicyCommit {
	operations := make([]persist.PolicyOperation, 0, len(dto.Operations))
	for _, op := range dto.Operations {
		operations = append(operations, persist.PolicyOperation{
			Type:       persist.OperationType(op.Type),
			Section:    op.Section,
			PolicyType: op.PolicyType,
			Rules:      cloneRules(op.Rules),
			OldRules:   cloneRules(op.OldRules),
		})
	}
	return &PolicyCommit{
		ID:              dto.ID,
		Version:         dto.Version,
		BaseVersion:     dto.BaseVersion,
		Operations:      operations,
		Status:          CommitStatus(dto.Status),
		AppliedBackends: cloneBoolMap(dto.AppliedBackends),
		BackendErrors:   cloneStringMap(dto.BackendErrors),
		AbortReason:     dto.AbortReason,
		CreatedAt:       dto.CreatedAt,
		UpdatedAt:       dto.UpdatedAt,
	}
}

// FileCommitStore persists commit records as one JSON document that is
// rewritten atomically (temp file plus rename), so a crash never leaves a
// torn document behind.
type FileCommitStore struct {
	path string
	mu   sync.Mutex
}

// NewFileCommitStore opens or creates the JSON-backed store at path.
func NewFileCommitStore(path string) (*FileCommitStore, error) {
	store := &FileCommitStore{path: path}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		empty := &fileStoreData{Commits: []fileCommitDTO{}, BackendStates: map[string]fileBackendStateDTO{}}
		if persistErr := store.persist(context.Background(), empty); persistErr != nil {
			return nil, persistErr
		}
	} else if err != nil {
		return nil, err
	}
	return store, nil
}

// load reads and decodes the store document.
func (s *FileCommitStore) load(ctx context.Context) (*fileStoreData, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	data := &fileStoreData{BackendStates: map[string]fileBackendStateDTO{}}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, data); err != nil {
			return nil, err
		}
	}
	if data.BackendStates == nil {
		data.BackendStates = map[string]fileBackendStateDTO{}
	}
	return data, nil
}

// persist encodes and atomically replaces the store document.
func (s *FileCommitStore) persist(ctx context.Context, data *fileStoreData) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.path)
}

// CreateCommit implements CommitStore.
func (s *FileCommitStore) CreateCommit(ctx context.Context, commit *PolicyCommit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load(ctx)
	if err != nil {
		return err
	}
	for _, existing := range data.Commits {
		if existing.ID == commit.ID || existing.Version == commit.Version {
			return ErrCommitAlreadyExists
		}
	}
	data.Commits = append(data.Commits, toFileCommit(commit))
	return s.persist(ctx, data)
}

// UpdateCommit implements CommitStore.
func (s *FileCommitStore) UpdateCommit(ctx context.Context, commit *PolicyCommit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load(ctx)
	if err != nil {
		return err
	}
	for i, existing := range data.Commits {
		if existing.ID == commit.ID {
			data.Commits[i] = toFileCommit(commit)
			return s.persist(ctx, data)
		}
	}
	return ErrCommitNotFound
}

// GetCommit implements CommitStore.
func (s *FileCommitStore) GetCommit(ctx context.Context, id string) (*PolicyCommit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	for _, commit := range data.Commits {
		if commit.ID == id {
			return fromFileCommit(commit), nil
		}
	}
	return nil, nil
}

// GetCommitByVersion implements CommitStore.
func (s *FileCommitStore) GetCommitByVersion(ctx context.Context, version int64) (*PolicyCommit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	for _, commit := range data.Commits {
		if commit.Version == version {
			return fromFileCommit(commit), nil
		}
	}
	return nil, nil
}

// ListCommits implements CommitStore.
func (s *FileCommitStore) ListCommits(ctx context.Context) ([]*PolicyCommit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*PolicyCommit, 0, len(data.Commits))
	for _, commit := range data.Commits {
		out = append(out, fromFileCommit(commit))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// GetBackendState implements CommitStore.
func (s *FileCommitStore) GetBackendState(ctx context.Context, name string) (*BackendState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	dto, ok := data.BackendStates[name]
	if !ok {
		return nil, nil
	}
	return &BackendState{
		Name:           dto.Name,
		AppliedVersion: dto.AppliedVersion,
		LastError:      dto.LastError,
		UpdatedAt:      dto.UpdatedAt,
	}, nil
}

// ListBackendStates implements CommitStore.
func (s *FileCommitStore) ListBackendStates(ctx context.Context) ([]*BackendState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*BackendState, 0, len(data.BackendStates))
	for _, dto := range data.BackendStates {
		out = append(out, &BackendState{
			Name:           dto.Name,
			AppliedVersion: dto.AppliedVersion,
			LastError:      dto.LastError,
			UpdatedAt:      dto.UpdatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// SaveBackendState implements CommitStore.
func (s *FileCommitStore) SaveBackendState(ctx context.Context, state *BackendState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load(ctx)
	if err != nil {
		return err
	}
	data.BackendStates[state.Name] = fileBackendStateDTO{
		Name:           state.Name,
		AppliedVersion: state.AppliedVersion,
		LastError:      state.LastError,
		UpdatedAt:      state.UpdatedAt,
	}
	return s.persist(ctx, data)
}

// GetActiveVersion implements CommitStore.
func (s *FileCommitStore) GetActiveVersion(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load(ctx)
	if err != nil {
		return 0, err
	}
	return data.ActiveVersion, nil
}

// SaveActiveVersion implements CommitStore.
func (s *FileCommitStore) SaveActiveVersion(ctx context.Context, version int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load(ctx)
	if err != nil {
		return err
	}
	data.ActiveVersion = version
	return s.persist(ctx, data)
}
