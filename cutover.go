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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/govaluate"
)

// activeSlot pairs a generation ID with the enforcer that serves it.
type activeSlot struct {
	id       GenerationID
	enforcer *Enforcer
}

// StageModelPolicyCutover switches the authorization model and its policy
// without interrupting enforcement.
//
// The workflow is generation based:
//
//  1. Stage validates that a candidate model and policy form a loadable
//     generation, persists the generation and records it as staged while the
//     active generation keeps serving traffic.
//  2. Commit re-loads the staged generation from the store and, only after the
//     durable state has been flipped, atomically moves new enforcement requests
//     to it. The previous generation stays readable and can be rolled back to.
//
// Re-applying the active generation is a no-op, and every state transition is
// persisted before it takes effect in memory, so a process exit before or after
// the cutover leaves the restart clearly on one usable generation.
type StageModelPolicyCutover struct {
	store GenerationStore

	// mu serializes Stage, Commit, Rollback, Retire and cached reader builds.
	// Enforcement itself never takes this lock.
	mu      sync.Mutex
	current atomic.Value // *activeSlot
	readers map[GenerationID]*Enforcer
	state   CutoverState
}

// NewStageModelPolicyCutover opens a cutover manager.
//
// When the store has no persisted state yet, bootstrapID and bootstrap are
// persisted as the first active generation and are required. When state
// already exists, the manager recovers the active generation from the store
// and bootstrap may be nil; if the active artifacts are unreadable it falls
// back to the previous generation instead of starting on a broken one.
func NewStageModelPolicyCutover(store GenerationStore, bootstrapID GenerationID, bootstrap *Enforcer) (*StageModelPolicyCutover, error) {
	if store == nil {
		return nil, ErrNilStore
	}
	c := &StageModelPolicyCutover{store: store, readers: map[GenerationID]*Enforcer{}}

	state, err := store.LoadState()
	if errors.Is(err, ErrStateNotFound) {
		return c.bootstrap(bootstrapID, bootstrap)
	}
	if err != nil {
		return nil, err
	}
	return c.recoverFromStore(state)
}

func (c *StageModelPolicyCutover) bootstrap(id GenerationID, e *Enforcer) (*StageModelPolicyCutover, error) {
	if e == nil || id == "" {
		return nil, ErrBootstrapRequired
	}
	if err := validateGenerationID(id); err != nil {
		return nil, err
	}
	policyText, err := serializePolicy(e.GetModel())
	if err != nil {
		return nil, err
	}
	if storeErr := c.store.SaveGeneration(id, e.GetModel().ToText(), policyText); storeErr != nil {
		return nil, storeErr
	}
	state := &CutoverState{Active: id, UpdatedAt: time.Now()}
	if stateErr := c.store.SaveState(state); stateErr != nil {
		return nil, stateErr
	}
	slot, err := c.buildSlot(id)
	if err != nil {
		return nil, err
	}
	c.current.Store(slot)
	c.state = *state
	return c, nil
}

func (c *StageModelPolicyCutover) recoverFromStore(state *CutoverState) (*StageModelPolicyCutover, error) {
	slot, err := c.buildSlot(state.Active)
	if err != nil {
		slot, err = c.recoverPrevious(state)
		if err != nil {
			return nil, err
		}
	}
	c.repairStagedPointer(state)
	c.current.Store(slot)
	c.state = *state
	return c, nil
}

func (c *StageModelPolicyCutover) recoverPrevious(state *CutoverState) (*activeSlot, error) {
	if state.Previous == "" {
		return nil, fmt.Errorf("%w: generation %s cannot be loaded", ErrInvalidStoredGeneration, state.Active)
	}
	slot, err := c.buildSlot(state.Previous)
	if err != nil {
		return nil, fmt.Errorf("%w: active %s and previous %s are both unloadable",
			ErrInvalidStoredGeneration, state.Active, state.Previous)
	}
	state.Active, state.Previous = state.Previous, ""
	state.Staged = ""
	if stateErr := c.store.SaveState(state); stateErr != nil {
		return nil, stateErr
	}
	return slot, nil
}

func (c *StageModelPolicyCutover) repairStagedPointer(state *CutoverState) {
	if state.Staged == "" {
		return
	}
	if _, _, err := c.store.LoadGeneration(state.Staged); err == nil {
		return
	}
	state.Staged = ""
	_ = c.store.SaveState(state)
}

// Stage validates the candidate model and adapter-loaded policy as a loadable
// generation and persists it without touching the active generation. It fails
// closed on model/policy mismatch, rule length mismatch or persistence errors.
func (c *StageModelPolicyCutover) Stage(id GenerationID, m model.Model, adapter persist.Adapter) error {
	if err := validateGenerationID(id); err != nil {
		return err
	}
	if m == nil {
		return ErrNilModel
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if id == c.state.Active {
		return ErrGenerationAlreadyActive
	}
	// Re-staging the same generation is a safe no-op: no re-validation, no
	// overwrite and no second cutover can be triggered from it.
	if id == c.state.Staged {
		return nil
	}

	candidate, err := buildCandidateModel(m, adapter)
	if err != nil {
		return err
	}
	if validateErr := validateLoadedModel(candidate); validateErr != nil {
		return validateErr
	}
	if _, probeErr := newEnforcerFromModel(candidate); probeErr != nil {
		return probeErr
	}

	policyText, err := serializePolicy(candidate)
	if err != nil {
		return err
	}
	if storeErr := c.store.SaveGeneration(id, candidate.ToText(), policyText); storeErr != nil {
		return storeErr
	}

	next := c.state
	next.Staged = id
	next.UpdatedAt = time.Now()
	if stateErr := c.store.SaveState(&next); stateErr != nil {
		return stateErr
	}
	c.state = next
	return nil
}

// Commit cuts new enforcement requests over to a previously staged generation.
// The state document is persisted before the in-memory swap, so a crash after
// a successful Commit always restarts on the new generation.
func (c *StageModelPolicyCutover) Commit(id GenerationID) error {
	if err := validateGenerationID(id); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if id == c.state.Active {
		return ErrGenerationAlreadyActive
	}
	if id != c.state.Staged {
		return fmt.Errorf("%w: %s", ErrNoStagedGeneration, id)
	}

	slot, err := c.buildSlot(id)
	if err != nil {
		return err
	}

	next := c.state
	next.Previous = c.state.Active
	next.Active = id
	next.Staged = ""
	next.UpdatedAt = time.Now()
	if stateErr := c.store.SaveState(&next); stateErr != nil {
		return stateErr
	}

	c.current.Store(slot)
	c.state = next
	return nil
}

// Rollback moves traffic back to the retained previous generation. The two
// generations swap roles, so rolling back again restores the newer one.
func (c *StageModelPolicyCutover) Rollback() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state.Previous == "" {
		return ErrNoPreviousGeneration
	}
	slot, err := c.buildSlot(c.state.Previous)
	if err != nil {
		return err
	}

	next := c.state
	next.Active, next.Previous = c.state.Previous, c.state.Active
	next.UpdatedAt = time.Now()
	if stateErr := c.store.SaveState(&next); stateErr != nil {
		return stateErr
	}

	c.current.Store(slot)
	c.state = next
	return nil
}

// Retire permanently removes a non-active generation from the store. The
// active generation can never be retired.
func (c *StageModelPolicyCutover) Retire(id GenerationID) error {
	if err := validateGenerationID(id); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if id == c.state.Active {
		return ErrCannotRetireActiveGeneration
	}
	if deleteErr := c.store.DeleteGeneration(id); deleteErr != nil {
		return deleteErr
	}
	delete(c.readers, id)

	next := c.state
	changed := false
	if next.Previous == id {
		next.Previous = ""
		changed = true
	}
	if next.Staged == id {
		next.Staged = ""
		changed = true
	}
	if !changed {
		return nil
	}
	next.UpdatedAt = time.Now()
	if stateErr := c.store.SaveState(&next); stateErr != nil {
		return stateErr
	}
	c.state = next
	return nil
}

// Enforce evaluates a request against the currently active generation. The
// active pointer is read atomically, so calls in flight during a cutover keep
// running against the generation they started with and never fail.
func (c *StageModelPolicyCutover) Enforce(rvals ...interface{}) (bool, error) {
	return c.active().enforcer.Enforce(rvals...)
}

// ActiveGeneration returns the ID of the generation serving new requests.
func (c *StageModelPolicyCutover) ActiveGeneration() GenerationID {
	return c.active().id
}

// CurrentEnforcer returns the enforcer backing the active generation.
func (c *StageModelPolicyCutover) CurrentEnforcer() *Enforcer {
	return c.active().enforcer
}

// StagedGeneration returns the staged generation ID and whether one exists.
func (c *StageModelPolicyCutover) StagedGeneration() (GenerationID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Staged, c.state.Staged != ""
}

// PreviousGeneration returns the retained previous generation ID and whether
// one exists.
func (c *StageModelPolicyCutover) PreviousGeneration() (GenerationID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Previous, c.state.Previous != ""
}

// State returns a copy of the durable cutover state.
func (c *StageModelPolicyCutover) State() CutoverState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// ListGenerations lists every generation persisted in the store.
func (c *StageModelPolicyCutover) ListGenerations() ([]GenerationID, error) {
	return c.store.ListGenerations()
}

// ReadGeneration returns the persisted model and policy text of any generation,
// including retired-from-service generations kept for rollback or inspection.
func (c *StageModelPolicyCutover) ReadGeneration(id GenerationID) (string, string, error) {
	if err := validateGenerationID(id); err != nil {
		return "", "", err
	}
	return c.store.LoadGeneration(id)
}

// GenerationEnforcer builds a read-only enforcer for any persisted generation.
// Old generations stay readable after a cutover; built enforcers are cached.
func (c *StageModelPolicyCutover) GenerationEnforcer(id GenerationID) (*Enforcer, error) {
	if err := validateGenerationID(id); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if id == c.state.Active {
		return c.active().enforcer, nil
	}
	if enforcer, ok := c.readers[id]; ok {
		return enforcer, nil
	}
	slot, err := c.buildSlot(id)
	if err != nil {
		return nil, err
	}
	c.readers[id] = slot.enforcer
	return slot.enforcer, nil
}

func (c *StageModelPolicyCutover) active() *activeSlot {
	return c.current.Load().(*activeSlot)
}

func (c *StageModelPolicyCutover) buildSlot(id GenerationID) (*activeSlot, error) {
	modelText, policyText, err := c.store.LoadGeneration(id)
	if err != nil {
		return nil, err
	}
	enforcer, err := newGenerationEnforcer(modelText, policyText)
	if err != nil {
		return nil, err
	}
	return &activeSlot{id: id, enforcer: enforcer}, nil
}

// newGenerationEnforcer reconstructs a fully working enforcer from the durable
// model and policy text. Recovery paths use it to prove that the generation
// they are about to serve is actually loadable.
func newGenerationEnforcer(modelText, policyText string) (*Enforcer, error) {
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, fmt.Errorf("%w: model text: %v", ErrInvalidStoredGeneration, err)
	}

	var adapter persist.Adapter
	if strings.TrimSpace(policyText) != "" {
		adapter = &inlinePolicyAdapter{policyText: policyText}
	}
	candidate, err := buildCandidateModel(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidStoredGeneration, err)
	}
	if validateErr := validateLoadedModel(candidate); validateErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidStoredGeneration, validateErr)
	}
	enforcer, err := newEnforcerFromModel(candidate)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidStoredGeneration, err)
	}
	return enforcer, nil
}

// buildCandidateModel loads the adapter policy into a detached copy of the
// candidate model, mirroring the enforcer load path without touching the
// caller's model.
func buildCandidateModel(m model.Model, adapter persist.Adapter) (model.Model, error) {
	candidate := m.Copy()
	candidate.ClearPolicy()

	if adapter != nil {
		if err := adapter.LoadPolicy(candidate); err != nil && !isEmptyPolicyStorageError(err) {
			return nil, classifyPolicyLoadError(err)
		}
	}
	if err := candidate.SortPoliciesBySubjectHierarchy(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGenerationNotLoadable, err)
	}
	if err := candidate.SortPoliciesByPriority(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGenerationNotLoadable, err)
	}
	return candidate, nil
}

func newEnforcerFromModel(m model.Model) (*Enforcer, error) {
	enforcer, err := NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGenerationNotLoadable, err)
	}
	if err := enforcer.BuildRoleLinks(); err != nil {
		return nil, fmt.Errorf("%w: role links: %v", ErrGenerationNotLoadable, err)
	}
	if err := enforcer.RunDetections(); err != nil {
		return nil, fmt.Errorf("%w: detectors: %v", ErrGenerationNotLoadable, err)
	}
	return enforcer, nil
}

func validateLoadedModel(m model.Model) error {
	if err := validateRuleLengths(m); err != nil {
		return err
	}
	return validateMatchers(m)
}

func validateRuleLengths(m model.Model) error {
	for ptype, ast := range m["p"] {
		for _, rule := range ast.Policy {
			if len(rule) != len(ast.Tokens) {
				return fmt.Errorf("%w: ptype %s expects %d fields, got %d: %v",
					ErrPolicyRuleLengthMismatch, ptype, len(ast.Tokens), len(rule), rule)
			}
		}
	}
	for ptype, ast := range m["g"] {
		for _, rule := range ast.Policy {
			if len(rule) < len(ast.Tokens) {
				return fmt.Errorf("%w: grouping ptype %s expects at least %d fields, got %d: %v",
					ErrPolicyRuleLengthMismatch, ptype, len(ast.Tokens), len(rule), rule)
			}
		}
	}
	return nil
}

func validateMatchers(m model.Model) error {
	functionMap := model.LoadFunctionMap()
	functions := functionMap.GetFunctions()
	// The enforce path injects one g function per role definition before
	// parsing. Register placeholders here as well so matcher parsing follows
	// the same contract; role-link semantics are validated separately.
	for ptype := range m["g"] {
		if _, exists := functions[ptype]; !exists {
			functions[ptype] = func(...interface{}) (interface{}, error) {
				return false, nil
			}
		}
	}
	for matcherType, ast := range m["m"] {
		if _, err := govaluate.NewEvaluableExpressionWithFunctions(ast.Value, functions); err != nil {
			return fmt.Errorf("%w: matcher %s: %v", ErrGenerationNotLoadable, matcherType, err)
		}
	}
	return nil
}

func classifyPolicyLoadError(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "invalid policy rule size"):
		return fmt.Errorf("%w: %v", ErrPolicyRuleLengthMismatch, err)
	case strings.Contains(message, "missing required definition"),
		strings.Contains(message, "missing required section"):
		return fmt.Errorf("%w: %v", ErrModelPolicyMismatch, err)
	default:
		return fmt.Errorf("%w: %v", ErrGenerationNotLoadable, err)
	}
}

func isEmptyPolicyStorageError(err error) bool {
	message := err.Error()
	return strings.Contains(message, "invalid file path, file path cannot be empty") ||
		strings.Contains(message, "invalid line, line cannot be empty")
}

// inlinePolicyAdapter feeds persisted policy text back into a model. It keeps
// the root package independent of the string-adapter subpackage, whose tests
// import the root package and would otherwise form an import cycle.
type inlinePolicyAdapter struct {
	policyText string
}

// LoadPolicy implements persist.Adapter.
func (a *inlinePolicyAdapter) LoadPolicy(m model.Model) error {
	for _, line := range strings.Split(a.policyText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := persist.LoadPolicyLine(line, m); err != nil {
			return err
		}
	}
	return nil
}

// SavePolicy implements persist.Adapter. Stored text is immutable.
func (a *inlinePolicyAdapter) SavePolicy(model.Model) error {
	return errors.New("casbin: inline cutover adapter is read-only")
}

// AddPolicy implements persist.Adapter.
func (a *inlinePolicyAdapter) AddPolicy(string, string, []string) error {
	return errors.New("casbin: inline cutover adapter is read-only")
}

// RemovePolicy implements persist.Adapter.
func (a *inlinePolicyAdapter) RemovePolicy(string, string, []string) error {
	return errors.New("casbin: inline cutover adapter is read-only")
}

// RemoveFilteredPolicy implements persist.Adapter.
func (a *inlinePolicyAdapter) RemoveFilteredPolicy(string, string, int, ...string) error {
	return errors.New("casbin: inline cutover adapter is read-only")
}

// serializePolicy renders the model policy back into the same line format that
// persist.LoadPolicyLine understands. Ptypes are sorted so the same generation
// always produces identical bytes.
func serializePolicy(m model.Model) (string, error) {
	var builder strings.Builder
	for _, section := range []string{"p", "g"} {
		ptypes := make([]string, 0, len(m[section]))
		for ptype := range m[section] {
			ptypes = append(ptypes, ptype)
		}
		sort.Strings(ptypes)
		for _, ptype := range ptypes {
			for _, rule := range m[section][ptype].Policy {
				line, err := persist.PolicyLineToCsv(ptype, rule)
				if err != nil {
					return "", fmt.Errorf("%w: %v", ErrGenerationNotLoadable, err)
				}
				builder.WriteString(line)
				builder.WriteByte('\n')
			}
		}
	}
	return strings.TrimRight(builder.String(), "\n"), nil
}
