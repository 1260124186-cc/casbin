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
	"reflect"
	"sync"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/persist/outbox"
)

var errOutboxInner = errors.New("simulated outbox inner watcher failure")

// outboxRecordingWatcher implements the full watcher surface and records the
// granular notification methods invoked by the outbox notifier.
type outboxRecordingWatcher struct {
	mu      sync.Mutex
	calls   []string
	failing bool
}

func (w *outboxRecordingWatcher) SetUpdateCallback(func(string)) error { return nil }

func (w *outboxRecordingWatcher) Close() {}

func (w *outboxRecordingWatcher) record(call string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failing {
		return errOutboxInner
	}
	w.calls = append(w.calls, call)
	return nil
}

func (w *outboxRecordingWatcher) callNames() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append(make([]string, 0, len(w.calls)), w.calls...)
}

func (w *outboxRecordingWatcher) Update() error {
	return w.record("Update")
}

func (w *outboxRecordingWatcher) UpdateForAddPolicy(_, _ string, _ ...string) error {
	return w.record("UpdateForAddPolicy")
}

func (w *outboxRecordingWatcher) UpdateForRemovePolicy(_, _ string, _ ...string) error {
	return w.record("UpdateForRemovePolicy")
}

func (w *outboxRecordingWatcher) UpdateForRemoveFilteredPolicy(_, _ string, _ int, _ ...string) error {
	return w.record("UpdateForRemoveFilteredPolicy")
}

func (w *outboxRecordingWatcher) UpdateForSavePolicy(model.Model) error {
	return w.record("UpdateForSavePolicy")
}

func (w *outboxRecordingWatcher) UpdateForAddPolicies(_, _ string, _ ...[]string) error {
	return w.record("UpdateForAddPolicies")
}

func (w *outboxRecordingWatcher) UpdateForRemovePolicies(_, _ string, _ ...[]string) error {
	return w.record("UpdateForRemovePolicies")
}

func (w *outboxRecordingWatcher) UpdateForUpdatePolicy(_, _ string, _, _ []string) error {
	return w.record("UpdateForUpdatePolicy")
}

func (w *outboxRecordingWatcher) UpdateForUpdatePolicies(_, _ string, _, _ [][]string) error {
	return w.record("UpdateForUpdatePolicies")
}

func newOutboxEnforcer(t *testing.T, inner persist.Watcher, dir string) (*Enforcer, *outbox.OutboxWatcher) {
	t.Helper()
	enforcer, err := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Fatalf("create enforcer: %v", err)
	}
	store, err := outbox.NewFileStore(dir)
	if err != nil {
		t.Fatalf("create outbox store: %v", err)
	}
	watcher, err := outbox.NewOutboxWatcher(context.Background(), inner, store)
	if err != nil {
		t.Fatalf("create outbox watcher: %v", err)
	}
	if err := enforcer.SetWatcher(watcher); err != nil {
		t.Fatalf("set watcher: %v", err)
	}
	return enforcer, watcher
}

func TestOutboxIntegrationCommitsArePersistedAndAcknowledged(t *testing.T) {
	ctx := context.Background()
	inner := &outboxRecordingWatcher{}
	enforcer, watcher := newOutboxEnforcer(t, inner, t.TempDir())
	defer watcher.Close()

	if _, err := enforcer.AddPolicy("charlie", "data3", "read"); err != nil {
		t.Fatalf("add policy: %v", err)
	}
	if _, err := enforcer.RemovePolicy("bob", "data2", "write"); err != nil {
		t.Fatalf("remove policy: %v", err)
	}
	if _, err := enforcer.AddGroupingPolicy("bob", "data2_admin"); err != nil {
		t.Fatalf("add grouping policy: %v", err)
	}

	wantCalls := []string{
		"UpdateForAddPolicies",
		"UpdateForRemovePolicies",
		"UpdateForAddPolicies",
	}
	if names := inner.callNames(); !reflect.DeepEqual(names, wantCalls) {
		t.Fatalf("watcher calls = %v, want %v", names, wantCalls)
	}
	pending, err := watcher.Outbox().PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("pending batches = %d, want 0 after successful notifications", pending)
	}
}

func TestOutboxIntegrationFailureReturnsErrorAndReplaysAfterRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	failingInner := &outboxRecordingWatcher{failing: true}
	enforcer, firstWatcher := newOutboxEnforcer(t, failingInner, dir)

	_, err := enforcer.AddPolicy("charlie", "data3", "read")
	if !errors.Is(err, errOutboxInner) {
		t.Fatalf("add policy error = %v, want explicit notification failure", err)
	}
	// The policy commit itself stays effective; only the notification failed.
	if ok, hasErr := enforcer.HasPolicy("charlie", "data3", "read"); hasErr != nil || !ok {
		t.Fatalf("committed policy missing after notification failure: %v", hasErr)
	}
	pending, err := firstWatcher.Outbox().PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending after failure = %d, want 1 (replayable state retained)", pending)
	}
	firstWatcher.Close()

	// Restart: a fresh watcher over the same directory must replay the batch.
	store, err := outbox.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	healthyInner := &outboxRecordingWatcher{}
	secondWatcher, err := outbox.NewOutboxWatcher(ctx, healthyInner, store)
	if err != nil {
		t.Fatal(err)
	}
	defer secondWatcher.Close()

	if names := healthyInner.callNames(); len(names) != 1 || names[0] != "UpdateForAddPolicies" {
		t.Fatalf("restart replay calls = %v, want [UpdateForAddPolicies]", names)
	}
	pending, err = secondWatcher.Outbox().PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("pending after restart replay = %d, want 0", pending)
	}
}

func TestOutboxIntegrationTransactionCommitGoesThroughOutbox(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	inner := &outboxRecordingWatcher{}
	enforcer, watcher := newTransactionalOutboxEnforcer(t, inner, dir)
	defer watcher.Close()

	err := enforcer.WithTransaction(ctx, func(tx *Transaction) error {
		_, addErr := tx.AddPolicy("charlie", "data3", "read")
		return addErr
	})
	if err != nil {
		t.Fatalf("transaction commit: %v", err)
	}
	if names := inner.callNames(); len(names) != 1 || names[0] != "UpdateForAddPolicies" {
		t.Fatalf("transaction watcher calls = %v, want [UpdateForAddPolicies]", names)
	}
	pending, err := watcher.Outbox().PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("pending after transaction = %d, want 0", pending)
	}
}

func TestOutboxIntegrationTransactionFailureRetainsBatch(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	failingInner := &outboxRecordingWatcher{failing: true}
	enforcer, firstWatcher := newTransactionalOutboxEnforcer(t, failingInner, dir)

	err := enforcer.WithTransaction(ctx, func(tx *Transaction) error {
		_, addErr := tx.AddPolicy("charlie", "data3", "read")
		return addErr
	})
	if !errors.Is(err, errOutboxInner) {
		t.Fatalf("transaction error = %v, want explicit notification failure", err)
	}
	pending, err := firstWatcher.Outbox().PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 1 {
		t.Fatalf("pending after failed transaction notify = %d, want 1", pending)
	}
	firstWatcher.Close()

	store, err := outbox.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	healthyInner := &outboxRecordingWatcher{}
	secondWatcher, err := outbox.NewOutboxWatcher(ctx, healthyInner, store)
	if err != nil {
		t.Fatal(err)
	}
	defer secondWatcher.Close()
	pending, err = secondWatcher.Outbox().PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("pending after replay = %d, want 0", pending)
	}
}

func newTransactionalOutboxEnforcer(
	t *testing.T,
	inner persist.Watcher,
	dir string,
) (*TransactionalEnforcer, *outbox.OutboxWatcher) {
	t.Helper()
	enforcer, err := NewTransactionalEnforcer("examples/rbac_model.conf", NewMockTransactionalAdapter())
	if err != nil {
		t.Fatalf("create transactional enforcer: %v", err)
	}
	store, err := outbox.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := outbox.NewOutboxWatcher(context.Background(), inner, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := enforcer.SetWatcher(watcher); err != nil {
		t.Fatal(err)
	}
	return enforcer, watcher
}

// fanOutReceiver is one receiving instance with its own durable guard.
type fanOutReceiver struct {
	enforcer   *Enforcer
	guard      *outbox.Guard
	applier    *outbox.EnforcerApplier
	applyCount int
}

// fanOutNotifier models a transport that pushes every outbox batch to all
// receiving instances.
type fanOutNotifier struct {
	receivers []*fanOutReceiver
}

func (n *fanOutNotifier) Notify(ctx context.Context, batch *outbox.ChangeBatch) error {
	for index := range n.receivers {
		receiver := n.receivers[index]
		applied, err := receiver.guard.Accept(ctx, batch, func() error {
			return receiver.applier.Apply(batch)
		})
		if err != nil {
			return err
		}
		if applied {
			receiver.applyCount++
		}
	}
	return nil
}

func TestOutboxIntegrationReceiversConvergeWithIdempotentDelivery(t *testing.T) {
	ctx := context.Background()

	sender, err := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	receivers := make([]*fanOutReceiver, 2)
	for index := range receivers {
		enforcer, enforcerErr := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
		if enforcerErr != nil {
			t.Fatal(enforcerErr)
		}
		store, storeErr := outbox.NewFileStore(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		guard, guardErr := outbox.NewGuard(ctx, store)
		if guardErr != nil {
			t.Fatal(guardErr)
		}
		receivers[index] = &fanOutReceiver{
			enforcer: enforcer,
			guard:    guard,
			applier:  outbox.NewEnforcerApplier(enforcer),
		}
	}

	senderStore, err := outbox.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	relay, err := outbox.New(ctx, senderStore, &fanOutNotifier{receivers: receivers})
	if err != nil {
		t.Fatal(err)
	}

	operations := []persist.PolicyOperation{
		{Type: persist.OperationAdd, Section: "p", PolicyType: "p", Rules: [][]string{{"charlie", "data3", "read"}}},
		{Type: persist.OperationRemove, Section: "p", PolicyType: "p", Rules: [][]string{{"bob", "data2", "write"}}},
		{Type: persist.OperationAdd, Section: "g", PolicyType: "g", Rules: [][]string{{"bob", "data2_admin"}}},
	}
	batches := make([]*outbox.ChangeBatch, 0, len(operations))
	for _, operation := range operations {
		batch, enqueueErr := relay.Enqueue(ctx, outbox.KindOperations, []persist.PolicyOperation{operation})
		if enqueueErr != nil {
			t.Fatal(enqueueErr)
		}
		batches = append(batches, batch)
		if flushErr := relay.Flush(ctx); flushErr != nil {
			t.Fatal(flushErr)
		}
	}

	// Mirror the changes on the sender itself for the final comparison.
	if _, err := sender.AddPolicy("charlie", "data3", "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.RemovePolicy("bob", "data2", "write"); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.AddGroupingPolicy("bob", "data2_admin"); err != nil {
		t.Fatal(err)
	}

	// Redeliver every batch: duplicates and a stale re-send must be ignored.
	for _, batch := range batches {
		applied, acceptErr := receivers[0].guard.Accept(ctx, batch, func() error {
			t.Fatal("duplicate batch must never be re-applied")
			return nil
		})
		if acceptErr != nil || applied {
			t.Fatalf("duplicate delivery accepted = (%v, %v)", applied, acceptErr)
		}
	}
	stale := *batches[0]
	if receivers[1].guard.IsDeliverable(&stale) {
		t.Fatal("stale batch must not be deliverable after newer versions were applied")
	}

	for index, receiver := range receivers {
		if receiver.applyCount != len(batches) {
			t.Fatalf("receiver %d applied %d batches, want %d", index, receiver.applyCount, len(batches))
		}
		if receiver.guard.LastSequence() != uint64(len(batches)) {
			t.Fatalf("receiver %d last sequence = %d, want %d", index, receiver.guard.LastSequence(), len(batches))
		}
		assertEnforcersConverged(t, sender, receiver.enforcer, index)
	}
}

func assertEnforcersConverged(t *testing.T, sender, receiver *Enforcer, index int) {
	t.Helper()
	senderPolicy, err := sender.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	receiverPolicy, err := receiver.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(senderPolicy, receiverPolicy) {
		t.Fatalf("receiver %d policy = %v, want %v", index, receiverPolicy, senderPolicy)
	}
	senderGrouping, err := sender.GetGroupingPolicy()
	if err != nil {
		t.Fatal(err)
	}
	receiverGrouping, err := receiver.GetGroupingPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(senderGrouping, receiverGrouping) {
		t.Fatalf("receiver %d grouping = %v, want %v", index, receiverGrouping, senderGrouping)
	}
}
