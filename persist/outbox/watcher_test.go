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

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

var errFakeInner = errors.New("simulated inner watcher failure")

// fakeInnerWatcher implements every watcher interface and records calls.
type fakeInnerWatcher struct {
	mu       sync.Mutex
	calls    []string
	failing  bool
	callback func(string)
}

func (w *fakeInnerWatcher) SetUpdateCallback(callback func(string)) error {
	w.callback = callback
	return nil
}

func (w *fakeInnerWatcher) Close() {}

func (w *fakeInnerWatcher) record(call string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failing {
		return errFakeInner
	}
	w.calls = append(w.calls, call)
	return nil
}

func (w *fakeInnerWatcher) callNames() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append(make([]string, 0, len(w.calls)), w.calls...)
}

func (w *fakeInnerWatcher) Update() error {
	return w.record("Update")
}

func (w *fakeInnerWatcher) UpdateForAddPolicy(_, _ string, _ ...string) error {
	return w.record("AddPolicy")
}

func (w *fakeInnerWatcher) UpdateForRemovePolicy(_, _ string, _ ...string) error {
	return w.record("RemovePolicy")
}

func (w *fakeInnerWatcher) UpdateForRemoveFilteredPolicy(_, _ string, _ int, _ ...string) error {
	return w.record("RemoveFilteredPolicy")
}

func (w *fakeInnerWatcher) UpdateForSavePolicy(model.Model) error {
	return w.record("SavePolicy")
}

func (w *fakeInnerWatcher) UpdateForAddPolicies(_, _ string, _ ...[]string) error {
	return w.record("AddPolicies")
}

func (w *fakeInnerWatcher) UpdateForRemovePolicies(_, _ string, _ ...[]string) error {
	return w.record("RemovePolicies")
}

func (w *fakeInnerWatcher) UpdateForUpdatePolicy(_, _ string, _, _ []string) error {
	return w.record("UpdatePolicy")
}

func (w *fakeInnerWatcher) UpdateForUpdatePolicies(_, _ string, _, _ [][]string) error {
	return w.record("UpdatePolicies")
}

// plainWatcher implements only the base Watcher interface.
type plainWatcher struct {
	mu    sync.Mutex
	calls int
}

func (w *plainWatcher) SetUpdateCallback(func(string)) error { return nil }
func (w *plainWatcher) Close()                               {}
func (w *plainWatcher) Update() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	return nil
}

func TestWatcherNotifierDispatchesGranularOperations(t *testing.T) {
	inner := &fakeInnerWatcher{}
	notifier := NewWatcherNotifier(inner)
	batch := &ChangeBatch{
		Sequence: 1,
		BatchID:  "batch-1",
		Kind:     KindOperations,
		Operations: []persist.PolicyOperation{
			{Type: persist.OperationAdd, Section: "p", PolicyType: "p", Rules: [][]string{{"a"}}},
			{Type: persist.OperationRemove, Section: "p", PolicyType: "p", Rules: [][]string{{"b"}}},
			{Type: persist.OperationUpdate, Section: "p", PolicyType: "p", OldRules: [][]string{{"c"}}, Rules: [][]string{{"d"}}},
		},
	}
	if err := notifier.Notify(context.Background(), batch); err != nil {
		t.Fatalf("notify: %v", err)
	}
	names := inner.callNames()
	want := []string{"AddPolicies", "RemovePolicies", "UpdatePolicies"}
	if len(names) != len(want) {
		t.Fatalf("calls = %v, want %v", names, want)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Fatalf("calls = %v, want %v", names, want)
		}
	}
}

func TestWatcherNotifierReloadsForKindReload(t *testing.T) {
	inner := &fakeInnerWatcher{}
	notifier := NewWatcherNotifier(inner)
	if err := notifier.Notify(context.Background(), makeBatch(1, "batch-1")); err != nil {
		t.Fatalf("notify reload: %v", err)
	}
	if names := inner.callNames(); len(names) != 1 || names[0] != "Update" {
		t.Fatalf("calls = %v, want [Update]", names)
	}
}

func TestWatcherNotifierFallsBackForPlainWatcher(t *testing.T) {
	inner := &plainWatcher{}
	notifier := NewWatcherNotifier(inner)
	batch := &ChangeBatch{
		Sequence:   1,
		BatchID:    "batch-1",
		Kind:       KindOperations,
		Operations: []persist.PolicyOperation{{Type: persist.OperationAdd, Section: "p", PolicyType: "p"}},
	}
	if err := notifier.Notify(context.Background(), batch); err != nil {
		t.Fatalf("notify through plain watcher: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("plain watcher calls = %d, want 1", inner.calls)
	}
}

func TestOutboxWatcherAcknowledgesAfterSuccessfulCommit(t *testing.T) {
	ctx := context.Background()
	store := newTestFileStore(t)
	inner := &fakeInnerWatcher{}
	watcher, err := NewOutboxWatcher(ctx, inner, store)
	if err != nil {
		t.Fatal(err)
	}

	err = watcher.UpdateForAddPolicies("p", "p", []string{"alice", "data1", "read"})
	if err != nil {
		t.Fatalf("add policy notification: %v", err)
	}
	if names := inner.callNames(); len(names) != 1 || names[0] != "AddPolicies" {
		t.Fatalf("inner calls = %v, want [AddPolicies]", names)
	}
	count, err := watcher.Outbox().PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("pending after success = %d, want 0", count)
	}
}

func TestOutboxWatcherFailureRetainsBatchAndReplaysOnRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	firstStore, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	failingInner := &fakeInnerWatcher{failing: true}
	firstWatcher, err := NewOutboxWatcher(ctx, failingInner, firstStore)
	if err != nil {
		t.Fatal(err)
	}
	err = firstWatcher.Update()
	if !errors.Is(err, errFakeInner) {
		t.Fatalf("update with failing inner = %v, want errFakeInner", err)
	}
	count, err := firstWatcher.Outbox().PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("pending after failure = %d, want 1", count)
	}
	firstWatcher.Close()

	// Reopen simulates a restart: the new watcher must replay the batch.
	secondStore, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	healthyInner := &fakeInnerWatcher{}
	secondWatcher, err := NewOutboxWatcher(ctx, healthyInner, secondStore)
	if err != nil {
		t.Fatal(err)
	}
	if names := healthyInner.callNames(); len(names) != 1 || names[0] != "Update" {
		t.Fatalf("startup replay calls = %v, want [Update]", names)
	}
	count, err = secondWatcher.Outbox().PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("pending after replay = %d, want 0", count)
	}
	secondWatcher.Close()
}

func TestOutboxWatcherMapsAllNotificationKinds(t *testing.T) {
	ctx := context.Background()
	store := newTestFileStore(t)
	inner := &fakeInnerWatcher{}
	watcher, err := NewOutboxWatcher(ctx, inner, store)
	if err != nil {
		t.Fatal(err)
	}

	_ = watcher.UpdateForAddPolicy("p", "p", "a", "b")
	_ = watcher.UpdateForRemovePolicy("p", "p", "a", "b")
	_ = watcher.UpdateForRemoveFilteredPolicy("p", "p", 1, "b")
	_ = watcher.UpdateForSavePolicy(nil)
	_ = watcher.UpdateForAddPolicies("g", "g", []string{"alice", "admin"})
	_ = watcher.UpdateForRemovePolicies("g", "g", []string{"alice", "admin"})
	_ = watcher.UpdateForUpdatePolicy("p", "p", []string{"old"}, []string{"new"})
	_ = watcher.UpdateForUpdatePolicies("p", "p", [][]string{{"old"}}, [][]string{{"new"}})

	names := inner.callNames()
	want := []string{
		"AddPolicies", "RemovePolicies",
		"Update", "Update",
		"AddPolicies", "RemovePolicies",
		"UpdatePolicies", "UpdatePolicies",
	}
	if len(names) != len(want) {
		t.Fatalf("calls = %v, want %v", names, want)
	}
	for index := range want {
		if names[index] != want[index] {
			t.Fatalf("calls = %v, want %v", names, want)
		}
	}
}

func TestOutboxWatcherRejectsNilDependencies(t *testing.T) {
	if _, err := NewOutboxWatcher(context.Background(), nil, newTestFileStore(t)); err == nil {
		t.Fatal("expected error for nil inner watcher")
	}
	if _, err := NewOutboxWatcher(context.Background(), &fakeInnerWatcher{}, nil); err == nil {
		t.Fatal("expected error for nil store")
	}
}
