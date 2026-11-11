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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casbin/casbin/v3/model"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	stringadapter "github.com/casbin/casbin/v3/persist/string-adapter"
)

const (
	genOne = "gen-1"
	genTwo = "gen-2"
)

func newBootstrapEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e, err := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewEnforcer bootstrap: %v", err)
	}
	return e
}

func newRbacModel(t *testing.T) model.Model {
	t.Helper()
	m, err := model.NewModelFromFile("examples/rbac_model.conf")
	if err != nil {
		t.Fatalf("NewModelFromFile rbac: %v", err)
	}
	return m
}

func newBasicModel(t *testing.T) model.Model {
	t.Helper()
	m, err := model.NewModelFromFile("examples/basic_model.conf")
	if err != nil {
		t.Fatalf("NewModelFromFile basic: %v", err)
	}
	return m
}

func newFileCutover(t *testing.T) (*StageModelPolicyCutover, *FileGenerationStore) {
	t.Helper()
	store := NewFileGenerationStore(t.TempDir())
	c, err := NewStageModelPolicyCutover(store, genOne, newBootstrapEnforcer(t))
	if err != nil {
		t.Fatalf("NewStageModelPolicyCutover: %v", err)
	}
	return c, store
}

func reopenCutover(t *testing.T, store GenerationStore) *StageModelPolicyCutover {
	t.Helper()
	c, err := NewStageModelPolicyCutover(store, "", nil)
	if err != nil {
		t.Fatalf("reopen cutover: %v", err)
	}
	return c
}

func assertEnforce(t *testing.T, c *StageModelPolicyCutover, want bool, rvals ...interface{}) {
	t.Helper()
	got, err := c.Enforce(rvals...)
	if err != nil {
		t.Fatalf("Enforce(%v): %v", rvals, err)
	}
	if got != want {
		t.Fatalf("Enforce(%v) = %v, want %v", rvals, got, want)
	}
}

func TestStageModelPolicyCutoverHappyPath(t *testing.T) {
	c, _ := newFileCutover(t)

	assertEnforce(t, c, true, "alice", "data1", "read")
	assertEnforce(t, c, false, "alice", "data2", "write")

	if err := c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if c.ActiveGeneration() != genOne {
		t.Fatalf("active generation = %s, want %s before commit", c.ActiveGeneration(), genOne)
	}
	staged, ok := c.StagedGeneration()
	if !ok || staged != genTwo {
		t.Fatalf("staged generation = %q (%v), want %s", staged, ok, genTwo)
	}
	// Staging must not move traffic: the old generation still serves requests.
	assertEnforce(t, c, false, "alice", "data2", "write")

	if err := c.Commit(genTwo); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if c.ActiveGeneration() != genTwo {
		t.Fatalf("active generation = %s, want %s", c.ActiveGeneration(), genTwo)
	}
	// The RBAC generation lets alice inherit data2_admin permissions.
	assertEnforce(t, c, true, "alice", "data2", "write")
	assertEnforce(t, c, true, "alice", "data1", "read")

	previous, ok := c.PreviousGeneration()
	if !ok || previous != genOne {
		t.Fatalf("previous generation = %q (%v), want %s", previous, ok, genOne)
	}
	// The old generation stays readable and evaluates with its own semantics.
	oldEnforcer, err := c.GenerationEnforcer(genOne)
	if err != nil {
		t.Fatalf("GenerationEnforcer(%s): %v", genOne, err)
	}
	allowed, err := oldEnforcer.Enforce("alice", "data2", "write")
	if err != nil {
		t.Fatalf("old generation Enforce: %v", err)
	}
	if allowed {
		t.Fatal("old generation unexpectedly allows alice data2 write")
	}

	if err := c.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if c.ActiveGeneration() != genOne {
		t.Fatalf("active generation after rollback = %s, want %s", c.ActiveGeneration(), genOne)
	}
	assertEnforce(t, c, false, "alice", "data2", "write")
}

func TestStageModelPolicyCutoverIdempotent(t *testing.T) {
	store := newMemStore()
	c, err := NewStageModelPolicyCutover(store, genOne, newBootstrapEnforcer(t))
	if err != nil {
		t.Fatalf("NewStageModelPolicyCutover: %v", err)
	}

	if err := c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	firstSaves := store.saveGenCalls()
	// Re-applying the same staged generation is a no-op.
	if err := c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv")); err != nil {
		t.Fatalf("re-stage same generation: %v", err)
	}
	if store.saveGenCalls() != firstSaves {
		t.Fatal("re-staging the same generation persisted it again")
	}
	// Staging the active generation is rejected and never triggers a switch.
	if err := c.Stage(genOne, newBasicModel(t), fileadapter.NewAdapter("examples/basic_policy.csv")); !errors.Is(err, ErrGenerationAlreadyActive) {
		t.Fatalf("stage active generation err = %v, want ErrGenerationAlreadyActive", err)
	}

	if err := c.Commit(genTwo); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := c.Commit(genTwo); !errors.Is(err, ErrGenerationAlreadyActive) {
		t.Fatalf("re-commit err = %v, want ErrGenerationAlreadyActive", err)
	}
	if c.ActiveGeneration() != genTwo {
		t.Fatalf("active generation = %s, want %s", c.ActiveGeneration(), genTwo)
	}
}

func TestStageModelPolicyCutoverRuleLengthMismatch(t *testing.T) {
	c, store := newFileCutover(t)
	adapter := stringadapter.NewAdapter("p, alice, data1")

	err := c.Stage(genTwo, newBasicModel(t), adapter)
	if !errors.Is(err, ErrPolicyRuleLengthMismatch) {
		t.Fatalf("Stage err = %v, want ErrPolicyRuleLengthMismatch", err)
	}
	if c.ActiveGeneration() != genOne {
		t.Fatalf("active generation = %s, want %s", c.ActiveGeneration(), genOne)
	}
	if _, ok := c.StagedGeneration(); ok {
		t.Fatal("failed stage must not leave a staged pointer")
	}
	ids, err := store.ListGenerations()
	if err != nil {
		t.Fatalf("ListGenerations: %v", err)
	}
	if len(ids) != 1 || ids[0] != genOne {
		t.Fatalf("generations = %v, want only %s", ids, genOne)
	}
	assertEnforce(t, c, true, "alice", "data1", "read")
}

func TestStageModelPolicyCutoverModelPolicyMismatch(t *testing.T) {
	c, _ := newFileCutover(t)
	// p2 is not declared in the basic model.
	adapter := stringadapter.NewAdapter("p2, alice, data1, read")

	err := c.Stage(genTwo, newBasicModel(t), adapter)
	if !errors.Is(err, ErrModelPolicyMismatch) {
		t.Fatalf("Stage err = %v, want ErrModelPolicyMismatch", err)
	}
	if c.ActiveGeneration() != genOne {
		t.Fatalf("active generation = %s, want %s", c.ActiveGeneration(), genOne)
	}
}

func TestStageModelPolicyCutoverInvalidMatcher(t *testing.T) {
	c, _ := newFileCutover(t)
	text := `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p_eft == allow))
[matchers]
m = r.sub ==
`
	m, err := model.NewModelFromString(text)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	if err := c.Stage(genTwo, m, nil); !errors.Is(err, ErrGenerationNotLoadable) {
		t.Fatalf("Stage err = %v, want ErrGenerationNotLoadable", err)
	}
}

func TestStageModelPolicyCutoverValidationInputs(t *testing.T) {
	c, _ := newFileCutover(t)

	if err := c.Stage(genTwo, nil, nil); !errors.Is(err, ErrNilModel) {
		t.Fatalf("nil model err = %v, want ErrNilModel", err)
	}
	if err := c.Stage("bad/id", newBasicModel(t), nil); !errors.Is(err, ErrInvalidGenerationID) {
		t.Fatalf("invalid id err = %v, want ErrInvalidGenerationID", err)
	}
	if _, err := NewStageModelPolicyCutover(nil, genOne, newBootstrapEnforcer(t)); !errors.Is(err, ErrNilStore) {
		t.Fatalf("nil store err = %v, want ErrNilStore", err)
	}
	store := NewFileGenerationStore(t.TempDir())
	if _, err := NewStageModelPolicyCutover(store, "", nil); !errors.Is(err, ErrBootstrapRequired) {
		t.Fatalf("missing bootstrap err = %v, want ErrBootstrapRequired", err)
	}
	if err := c.Commit("never-staged"); !errors.Is(err, ErrNoStagedGeneration) {
		t.Fatalf("commit without stage err = %v, want ErrNoStagedGeneration", err)
	}
}

func TestStageModelPolicyCutoverEmptyPolicy(t *testing.T) {
	c, _ := newFileCutover(t)
	if err := c.Stage(genTwo, newBasicModel(t), nil); err != nil {
		t.Fatalf("Stage without adapter: %v", err)
	}
	if err := c.Commit(genTwo); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	assertEnforce(t, c, false, "alice", "data1", "read")
}

func TestStageModelPolicyCutoverReadGenerationRoundTrip(t *testing.T) {
	c, _ := newFileCutover(t)
	if err := c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	modelText, policyText, err := c.ReadGeneration(genTwo)
	if err != nil {
		t.Fatalf("ReadGeneration: %v", err)
	}
	if !strings.Contains(modelText, "[matchers]") || !strings.Contains(modelText, "g(r.sub, p.sub)") {
		t.Fatalf("model text round trip lost content: %q", modelText)
	}
	if !strings.Contains(policyText, "alice, data2_admin") || !strings.Contains(policyText, "p, bob, data2, write") {
		t.Fatalf("policy text round trip lost content: %q", policyText)
	}
}

func TestStageModelPolicyCutoverPersistenceFailureKeepsActiveGeneration(t *testing.T) {
	store := newMemStore()
	c, err := NewStageModelPolicyCutover(store, genOne, newBootstrapEnforcer(t))
	if err != nil {
		t.Fatalf("NewStageModelPolicyCutover: %v", err)
	}

	store.failSaveGen = true
	err = c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv"))
	if !errors.Is(err, ErrPersistenceFailed) {
		t.Fatalf("Stage with failing generation save err = %v, want ErrPersistenceFailed", err)
	}
	store.failSaveGen = false
	if c.ActiveGeneration() != genOne {
		t.Fatalf("active generation = %s, want %s", c.ActiveGeneration(), genOne)
	}

	if err := c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	store.failSaveState = true
	if err := c.Commit(genTwo); !errors.Is(err, ErrPersistenceFailed) {
		t.Fatalf("Commit with failing state save err = %v, want ErrPersistenceFailed", err)
	}
	store.failSaveState = false
	if c.ActiveGeneration() != genOne {
		t.Fatalf("active generation after failed commit = %s, want %s", c.ActiveGeneration(), genOne)
	}
	assertEnforce(t, c, true, "alice", "data1", "read")

	if err := c.Commit(genTwo); err != nil {
		t.Fatalf("retry Commit: %v", err)
	}
	if c.ActiveGeneration() != genTwo {
		t.Fatalf("active generation = %s, want %s", c.ActiveGeneration(), genTwo)
	}
	assertEnforce(t, c, true, "alice", "data2", "write")
}

func TestStageModelPolicyCutoverRestartAfterStage(t *testing.T) {
	dir := t.TempDir()
	store := NewFileGenerationStore(dir)
	c, err := NewStageModelPolicyCutover(store, genOne, newBootstrapEnforcer(t))
	if err != nil {
		t.Fatalf("NewStageModelPolicyCutover: %v", err)
	}
	if err := c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv")); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	// Simulate a process exit before the cutover takes effect.
	reopened := reopenCutover(t, store)
	if reopened.ActiveGeneration() != genOne {
		t.Fatalf("active generation after restart = %s, want %s", reopened.ActiveGeneration(), genOne)
	}
	staged, ok := reopened.StagedGeneration()
	if !ok || staged != genTwo {
		t.Fatalf("staged generation after restart = %q (%v)", staged, ok)
	}
	assertEnforce(t, reopened, true, "alice", "data1", "read")
	if err := reopened.Commit(genTwo); err != nil {
		t.Fatalf("Commit after restart: %v", err)
	}
	if reopened.ActiveGeneration() != genTwo {
		t.Fatalf("active generation = %s, want %s", reopened.ActiveGeneration(), genTwo)
	}
}

func TestStageModelPolicyCutoverRestartAfterCommit(t *testing.T) {
	dir := t.TempDir()
	store := NewFileGenerationStore(dir)
	c, err := NewStageModelPolicyCutover(store, genOne, newBootstrapEnforcer(t))
	if err != nil {
		t.Fatalf("NewStageModelPolicyCutover: %v", err)
	}
	if err := c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := c.Commit(genTwo); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Simulate a process exit after the new generation took effect.
	reopened := reopenCutover(t, store)
	if reopened.ActiveGeneration() != genTwo {
		t.Fatalf("active generation after restart = %s, want %s", reopened.ActiveGeneration(), genTwo)
	}
	assertEnforce(t, reopened, true, "alice", "data2", "write")
	if _, err := reopened.GenerationEnforcer(genOne); err != nil {
		t.Fatalf("old generation not readable after restart: %v", err)
	}
	if err := reopened.Rollback(); err != nil {
		t.Fatalf("Rollback after restart: %v", err)
	}
	if reopened.ActiveGeneration() != genOne {
		t.Fatalf("active generation after rollback = %s, want %s", reopened.ActiveGeneration(), genOne)
	}
	assertEnforce(t, reopened, false, "alice", "data2", "write")
}

func TestStageModelPolicyCutoverRecoversPreviousGeneration(t *testing.T) {
	dir := t.TempDir()
	store := NewFileGenerationStore(dir)
	c, err := NewStageModelPolicyCutover(store, genOne, newBootstrapEnforcer(t))
	if err != nil {
		t.Fatalf("NewStageModelPolicyCutover: %v", err)
	}
	if err := c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := c.Commit(genTwo); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Corrupt the active generation on disk after the cutover.
	if err := store.DeleteGeneration(genTwo); err != nil {
		t.Fatalf("DeleteGeneration: %v", err)
	}

	reopened := reopenCutover(t, store)
	if reopened.ActiveGeneration() != genOne {
		t.Fatalf("active generation = %s, want fallback %s", reopened.ActiveGeneration(), genOne)
	}
	if previous, ok := reopened.PreviousGeneration(); ok || previous != "" {
		t.Fatalf("previous generation = %q (%v), want cleared pointer", previous, ok)
	}
	assertEnforce(t, reopened, true, "alice", "data1", "read")
}

func TestStageModelPolicyCutoverRetire(t *testing.T) {
	c, store := newFileCutover(t)
	if err := c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv")); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := c.Commit(genTwo); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if err := c.Retire(genTwo); !errors.Is(err, ErrCannotRetireActiveGeneration) {
		t.Fatalf("Retire active err = %v, want ErrCannotRetireActiveGeneration", err)
	}
	if err := c.Retire("missing-gen"); !errors.Is(err, ErrGenerationNotFound) {
		t.Fatalf("Retire unknown err = %v, want ErrGenerationNotFound", err)
	}
	if err := c.Retire(genOne); err != nil {
		t.Fatalf("Retire previous: %v", err)
	}
	if _, ok := c.PreviousGeneration(); ok {
		t.Fatal("previous pointer must be cleared after retire")
	}
	if err := c.Rollback(); !errors.Is(err, ErrNoPreviousGeneration) {
		t.Fatalf("Rollback after retire err = %v, want ErrNoPreviousGeneration", err)
	}
	if _, _, err := store.LoadGeneration(genOne); !errors.Is(err, ErrGenerationNotFound) {
		t.Fatalf("LoadGeneration retired err = %v, want ErrGenerationNotFound", err)
	}
}

func TestStageModelPolicyCutoverConcurrentEnforcement(t *testing.T) {
	c, _ := newFileCutover(t)
	if err := c.Stage(genTwo, newRbacModel(t), fileadapter.NewAdapter("examples/rbac_policy.csv")); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	var allowed int64
	var denied int64
	var failures int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					ok, err := c.Enforce("alice", "data2", "write")
					if err != nil {
						atomic.AddInt64(&failures, 1)
						continue
					}
					if ok {
						atomic.AddInt64(&allowed, 1)
					} else {
						atomic.AddInt64(&denied, 1)
					}
				}
			}
		}()
	}

	// Let traffic run against the old generation, then cut over.
	time.Sleep(20 * time.Millisecond)
	if err := c.Commit(genTwo); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()

	if atomic.LoadInt64(&failures) != 0 {
		t.Fatalf("enforcement failures during cutover: %d", failures)
	}
	if atomic.LoadInt64(&denied) == 0 || atomic.LoadInt64(&allowed) == 0 {
		t.Fatalf("expected decisions on both generations, allowed = %d denied = %d", allowed, denied)
	}
	assertEnforce(t, c, true, "alice", "data2", "write")
}

// memGeneration is one persisted generation in the in-memory test store.
type memGeneration struct {
	modelText  string
	policyText string
}

// memStore is a GenerationStore with failure injection for persistence tests.
type memStore struct {
	mu               sync.Mutex
	generations      map[GenerationID]memGeneration
	state            *CutoverState
	failSaveGen      bool
	failSaveState    bool
	saveGenCallCount int
}

func newMemStore() *memStore {
	return &memStore{generations: map[GenerationID]memGeneration{}}
}

func (s *memStore) SaveGeneration(id GenerationID, modelText, policyText string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveGenCallCount++
	if s.failSaveGen {
		return fmt.Errorf("%w: injected SaveGeneration failure", ErrPersistenceFailed)
	}
	s.generations[id] = memGeneration{modelText: modelText, policyText: policyText}
	return nil
}

func (s *memStore) LoadGeneration(id GenerationID) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	gen, ok := s.generations[id]
	if !ok {
		return "", "", fmt.Errorf("%w: generation %s missing", ErrGenerationNotFound, id)
	}
	return gen.modelText, gen.policyText, nil
}

func (s *memStore) ListGenerations() ([]GenerationID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]GenerationID, 0, len(s.generations))
	for id := range s.generations {
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *memStore) DeleteGeneration(id GenerationID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.generations[id]; !ok {
		return fmt.Errorf("%w: generation %s missing", ErrGenerationNotFound, id)
	}
	delete(s.generations, id)
	return nil
}

func (s *memStore) SaveState(state *CutoverState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSaveState {
		return fmt.Errorf("%w: injected SaveState failure", ErrPersistenceFailed)
	}
	copyState := *state
	s.state = &copyState
	return nil
}

func (s *memStore) LoadState() (*CutoverState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, ErrStateNotFound
	}
	copyState := *s.state
	return &copyState, nil
}

func (s *memStore) saveGenCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveGenCallCount
}
