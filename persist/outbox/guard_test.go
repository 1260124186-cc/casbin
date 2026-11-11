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

package outbox

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/casbin/casbin/v3/persist"
)

var errFakeApply = errors.New("simulated apply failure")

// memCursorStore is an in-memory CursorStore for guard tests.
type memCursorStore struct {
	mu      sync.Mutex
	cursor  *AppliedCursor
	saveErr error
}

func (s *memCursorStore) LoadCursor(_ context.Context) (*AppliedCursor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cursor == nil {
		return &AppliedCursor{BatchIDs: make([]string, 0)}, nil
	}
	copied := *s.cursor
	return &copied, nil
}

func (s *memCursorStore) SaveCursor(_ context.Context, cursor *AppliedCursor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	copied := *cursor
	s.cursor = &copied
	return nil
}

func (s *memCursorStore) Close() error {
	return nil
}

func newTestGuard(t *testing.T, store CursorStore) *Guard {
	t.Helper()
	guard, err := NewGuard(context.Background(), store)
	if err != nil {
		t.Fatalf("create guard: %v", err)
	}
	return guard
}

func TestGuardDuplicateBatchAppliedOnce(t *testing.T) {
	guard := newTestGuard(t, &memCursorStore{})
	batch := makeBatch(1, "batch-1")

	applied := 0
	apply := func() error {
		applied++
		return nil
	}

	ok, err := guard.Accept(context.Background(), batch, apply)
	if err != nil || !ok {
		t.Fatalf("first accept = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = guard.Accept(context.Background(), batch, apply)
	if err != nil || ok {
		t.Fatalf("duplicate accept = (%v, %v), want (false, nil)", ok, err)
	}
	if applied != 1 {
		t.Fatalf("apply invoked %d times, want 1", applied)
	}
}

func TestGuardRejectsStaleAndOutOfOrderBatches(t *testing.T) {
	guard := newTestGuard(t, &memCursorStore{})

	ok, err := guard.Accept(context.Background(), makeBatch(3, "batch-3"), nil)
	if err != nil || !ok {
		t.Fatalf("accept sequence 3 = (%v, %v)", ok, err)
	}
	for _, sequence := range []uint64{1, 2, 3} {
		ok, err = guard.Accept(context.Background(), makeBatch(sequence, "batch-"+string(rune('0'+sequence))), nil)
		if err != nil || ok {
			t.Fatalf("stale sequence %d accepted = (%v, %v)", sequence, ok, err)
		}
	}
	if guard.LastSequence() != 3 {
		t.Fatalf("last sequence = %d, want 3", guard.LastSequence())
	}

	// A later, in-order batch must still go through.
	ok, err = guard.Accept(context.Background(), makeBatch(4, "batch-4"), nil)
	if err != nil || !ok {
		t.Fatalf("accept sequence 4 = (%v, %v)", ok, err)
	}
}

func TestGuardRestoresPositionAfterRestart(t *testing.T) {
	ctx := context.Background()
	store := &memCursorStore{}
	guard := newTestGuard(t, store)

	for sequence := uint64(1); sequence <= 3; sequence++ {
		ok, err := guard.Accept(ctx, makeBatch(sequence, "batch-"+string(rune('0'+sequence))), nil)
		if err != nil || !ok {
			t.Fatalf("accept sequence %d = (%v, %v)", sequence, ok, err)
		}
	}

	restored := newTestGuard(t, store)
	if restored.LastSequence() != 3 {
		t.Fatalf("restored sequence = %d, want 3", restored.LastSequence())
	}
	ok, err := restored.Accept(ctx, makeBatch(2, "batch-2"), nil)
	if err != nil || ok {
		t.Fatalf("duplicate after restart = (%v, %v), want (false, nil)", ok, err)
	}
	ok, err = restored.Accept(ctx, makeBatch(4, "batch-4"), nil)
	if err != nil || !ok {
		t.Fatalf("new batch after restart = (%v, %v)", ok, err)
	}
}

func TestGuardApplyFailureKeepsPosition(t *testing.T) {
	guard := newTestGuard(t, &memCursorStore{})
	attempts := 0
	apply := func() error {
		attempts++
		if attempts == 1 {
			return errFakeApply
		}
		return nil
	}

	ok, err := guard.Accept(context.Background(), makeBatch(1, "batch-1"), apply)
	if !errors.Is(err, errFakeApply) || ok {
		t.Fatalf("failing accept = (%v, %v), want errFakeApply", ok, err)
	}
	if guard.LastSequence() != 0 {
		t.Fatalf("sequence advanced after failed apply: %d", guard.LastSequence())
	}

	ok, err = guard.Accept(context.Background(), makeBatch(1, "batch-1"), apply)
	if err != nil || !ok {
		t.Fatalf("retried accept = (%v, %v), want (true, nil)", ok, err)
	}
	if attempts != 2 {
		t.Fatalf("apply attempts = %d, want 2", attempts)
	}
}

func TestGuardCursorPersistenceFailureLeavesPositionUntouched(t *testing.T) {
	store := &memCursorStore{saveErr: errFakeApply}
	guard := newTestGuard(t, store)

	ok, err := guard.Accept(context.Background(), makeBatch(1, "batch-1"), nil)
	if !errors.Is(err, errFakeApply) || ok {
		t.Fatalf("accept with broken cursor = (%v, %v)", ok, err)
	}
	if guard.LastSequence() != 0 {
		t.Fatalf("sequence = %d, want 0 after cursor failure", guard.LastSequence())
	}
}

func TestGuardTrimsDedupeWindowButKeepsSequenceProtection(t *testing.T) {
	guard := newTestGuard(t, &memCursorStore{})
	guard.limit = 3

	for sequence := uint64(1); sequence <= 5; sequence++ {
		ok, err := guard.Accept(context.Background(), makeBatch(sequence, "batch-"+string(rune('0'+sequence))), nil)
		if err != nil || !ok {
			t.Fatalf("accept sequence %d = (%v, %v)", sequence, ok, err)
		}
	}
	if len(guard.recent) != 3 {
		t.Fatalf("tracked window size = %d, want 3", len(guard.recent))
	}

	// The evicted identifier is still blocked by the sequence check.
	ok, err := guard.Accept(context.Background(), makeBatch(1, "batch-1"), nil)
	if err != nil || ok {
		t.Fatalf("evicted stale batch accepted = (%v, %v)", ok, err)
	}
}

// fakePolicyReceiver records the granular calls issued by EnforcerApplier.
type fakePolicyReceiver struct {
	mu             sync.Mutex
	adds           int
	removes        int
	updates        int
	groupingAdds   int
	groupingRemove int
	reloads        int
}

func (r *fakePolicyReceiver) AddNamedPolicies(_ string, _ [][]string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adds++
	return true, nil
}

func (r *fakePolicyReceiver) RemoveNamedPolicies(_ string, _ [][]string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removes++
	return true, nil
}

func (r *fakePolicyReceiver) UpdateNamedPolicies(_ string, _, _ [][]string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updates++
	return true, nil
}

func (r *fakePolicyReceiver) AddNamedGroupingPolicies(_ string, _ [][]string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.groupingAdds++
	return true, nil
}

func (r *fakePolicyReceiver) RemoveNamedGroupingPolicies(_ string, _ [][]string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.groupingRemove++
	return true, nil
}

func (r *fakePolicyReceiver) UpdateNamedGroupingPolicies(_ string, _, _ [][]string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updates++
	return true, nil
}

func (r *fakePolicyReceiver) LoadPolicy() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reloads++
	return nil
}

func TestEnforcerApplierDispatchesOperations(t *testing.T) {
	receiver := &fakePolicyReceiver{}
	applier := NewEnforcerApplier(receiver)
	batch := &ChangeBatch{
		Sequence: 1,
		BatchID:  "batch-1",
		Kind:     KindOperations,
		Operations: []persist.PolicyOperation{
			{Type: persist.OperationAdd, Section: "p", PolicyType: "p", Rules: [][]string{{"a", "b"}}},
			{Type: persist.OperationRemove, Section: "p", PolicyType: "p", Rules: [][]string{{"c", "d"}}},
			{Type: persist.OperationUpdate, Section: "p", PolicyType: "p", OldRules: [][]string{{"e"}}, Rules: [][]string{{"f"}}},
			{Type: persist.OperationAdd, Section: "g", PolicyType: "g", Rules: [][]string{{"alice", "admin"}}},
		},
	}
	if err := applier.Apply(batch); err != nil {
		t.Fatalf("apply operations: %v", err)
	}
	if receiver.adds != 1 || receiver.removes != 1 || receiver.updates != 1 ||
		receiver.groupingAdds != 1 || receiver.reloads != 0 {
		t.Fatalf("unexpected call counts: %+v", receiver)
	}
}

func TestEnforcerApplierReloadBatchTriggersLoadPolicy(t *testing.T) {
	receiver := &fakePolicyReceiver{}
	applier := NewEnforcerApplier(receiver)
	if err := applier.Apply(makeBatch(1, "batch-1")); err != nil {
		t.Fatalf("apply reload: %v", err)
	}
	if receiver.reloads != 1 {
		t.Fatalf("reloads = %d, want 1", receiver.reloads)
	}
}
