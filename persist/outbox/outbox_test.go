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
	"time"

	"github.com/casbin/casbin/v3/persist"
)

var errFakeNotify = errors.New("simulated notification failure")

// fakeNotifier records deliveries and can fail a configured number of times.
type fakeNotifier struct {
	mu           sync.Mutex
	delivered    []*ChangeBatch
	failuresLeft int
}

func (n *fakeNotifier) Notify(_ context.Context, batch *ChangeBatch) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failuresLeft > 0 {
		n.failuresLeft--
		return errFakeNotify
	}
	n.delivered = append(n.delivered, batch)
	return nil
}

func (n *fakeNotifier) deliveredCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.delivered)
}

func (n *fakeNotifier) sequences() []uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	result := make([]uint64, 0, len(n.delivered))
	for _, batch := range n.delivered {
		result = append(result, batch.Sequence)
	}
	return result
}

func newTestOutbox(t *testing.T, notifier Notifier) (*Outbox, *FileStore) {
	t.Helper()
	store := newTestFileStore(t)
	relay, err := New(context.Background(), store, notifier)
	if err != nil {
		t.Fatalf("create outbox: %v", err)
	}
	return relay, store
}

func sampleOperations() []persist.PolicyOperation {
	return []persist.PolicyOperation{{
		Type:       persist.OperationAdd,
		Section:    "p",
		PolicyType: "p",
		Rules:      [][]string{{"alice", "data1", "read"}},
	}}
}

func TestOutboxEnqueueAssignsMonotonicSequences(t *testing.T) {
	ctx := context.Background()
	relay, _ := newTestOutbox(t, &fakeNotifier{})

	identifiers := make(map[string]struct{})
	for index := 0; index < 3; index++ {
		batch, err := relay.Enqueue(ctx, KindOperations, sampleOperations())
		if err != nil {
			t.Fatalf("enqueue %d: %v", index, err)
		}
		if batch.Sequence != uint64(index+1) {
			t.Fatalf("sequence = %d, want %d", batch.Sequence, index+1)
		}
		if batch.BatchID == "" {
			t.Fatal("batch id must be generated")
		}
		if _, exists := identifiers[batch.BatchID]; exists {
			t.Fatalf("duplicate batch id %s", batch.BatchID)
		}
		identifiers[batch.BatchID] = struct{}{}
	}

	count, err := relay.PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("pending count = %d, want 3", count)
	}
}

func TestOutboxRejectsEmptyOperationsBatch(t *testing.T) {
	relay, _ := newTestOutbox(t, &fakeNotifier{})
	if _, err := relay.Enqueue(context.Background(), KindOperations, nil); !errors.Is(err, ErrEmptyBatch) {
		t.Fatalf("enqueue empty operations batch = %v, want ErrEmptyBatch", err)
	}
}

func TestOutboxFlushCheckpointsOnSuccess(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{}
	relay, _ := newTestOutbox(t, notifier)

	for index := 0; index < 3; index++ {
		if _, err := relay.Enqueue(ctx, KindOperations, sampleOperations()); err != nil {
			t.Fatal(err)
		}
	}
	if err := relay.Flush(ctx); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if count := notifier.deliveredCount(); count != 3 {
		t.Fatalf("delivered %d batches, want 3", count)
	}
	if sequences := notifier.sequences(); len(sequences) != 3 ||
		sequences[0] != 1 || sequences[1] != 2 || sequences[2] != 3 {
		t.Fatalf("delivery order = %v, want [1 2 3]", sequences)
	}
	count, err := relay.PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("pending after flush = %d, want 0", count)
	}
}

func TestOutboxNotifyFailureRetainsBatchAndReturnsError(t *testing.T) {
	ctx := context.Background()
	notifier := &fakeNotifier{failuresLeft: 1}
	relay, _ := newTestOutbox(t, notifier)

	if _, err := relay.Enqueue(ctx, KindReload, nil); err != nil {
		t.Fatal(err)
	}
	err := relay.Flush(ctx)
	if !errors.Is(err, errFakeNotify) {
		t.Fatalf("flush error = %v, want errFakeNotify", err)
	}

	count, err := relay.PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("pending after failed flush = %d, want 1 (batch must be retained)", count)
	}

	err = relay.Flush(ctx)
	if err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	delivered := notifier.deliveredCount()
	if delivered != 1 {
		t.Fatalf("delivered %d batches after retry, want 1", delivered)
	}
	count, err = relay.PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("pending after retry = %d, want 0", count)
	}
}

func TestOutboxReplayAfterRestartDeliversPendingInOrder(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	firstStore, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	failing := &fakeNotifier{failuresLeft: 100}
	firstRelay, err := New(ctx, firstStore, failing)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if _, enqueueErr := firstRelay.Enqueue(ctx, KindOperations, sampleOperations()); enqueueErr != nil {
			t.Fatal(enqueueErr)
		}
	}
	err = firstRelay.Flush(ctx)
	if !errors.Is(err, errFakeNotify) {
		t.Fatalf("expected notify failure, got %v", err)
	}
	err = firstStore.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a process restart: reopen the store and build a fresh relay.
	secondStore, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	notifier := &fakeNotifier{}
	secondRelay, err := New(ctx, secondStore, notifier)
	if err != nil {
		t.Fatal(err)
	}
	err = secondRelay.Flush(ctx)
	if err != nil {
		t.Fatalf("replay flush: %v", err)
	}
	if sequences := notifier.sequences(); len(sequences) != 3 ||
		sequences[0] != 1 || sequences[1] != 2 || sequences[2] != 3 {
		t.Fatalf("replayed sequences = %v, want [1 2 3]", sequences)
	}

	// The sequence counter must continue above the replayed batches.
	batch, err := secondRelay.Enqueue(ctx, KindReload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Sequence != 4 {
		t.Fatalf("sequence after restart = %d, want 4", batch.Sequence)
	}
}

func TestOutboxEnqueueFailureReturnsExplicitError(t *testing.T) {
	ctx := context.Background()
	store := newTestFileStore(t)
	brokenStore := &failingAppendStore{Store: store, appendErr: errFakeNotify}
	relay, err := New(ctx, brokenStore, &fakeNotifier{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = relay.Enqueue(ctx, KindReload, nil)
	if !errors.Is(err, errFakeNotify) {
		t.Fatalf("enqueue on broken store = %v, want the underlying error", err)
	}
	pending, err := store.FetchPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("no batch may be visible after a failed append, got %d", len(pending))
	}
}

func TestOutboxFlushWithoutNotifierReportsError(t *testing.T) {
	store := newTestFileStore(t)
	relay, err := New(context.Background(), store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.Enqueue(context.Background(), KindReload, nil); err != nil {
		t.Fatal(err)
	}
	if err := relay.Flush(context.Background()); !errors.Is(err, ErrNotifierMissing) {
		t.Fatalf("flush without notifier = %v, want ErrNotifierMissing", err)
	}
}

func TestOutboxBackgroundFlushRetriesUntilAcknowledged(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notifier := &fakeNotifier{failuresLeft: 2}
	relay, _ := newTestOutbox(t, notifier)
	if _, err := relay.Enqueue(ctx, KindReload, nil); err != nil {
		t.Fatal(err)
	}
	if err := relay.Start(ctx, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		count, err := relay.PendingCount(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	count, err := relay.PendingCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("background flush did not drain the outbox, pending = %d", count)
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOutboxEnqueueAfterCloseFails(t *testing.T) {
	relay, _ := newTestOutbox(t, &fakeNotifier{})
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.Enqueue(context.Background(), KindReload, nil); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("enqueue after close = %v, want ErrStoreClosed", err)
	}
}

func TestOutboxErrorHandlerObservesBackgroundFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notifier := &fakeNotifier{failuresLeft: 1}
	relay, _ := newTestOutbox(t, notifier)
	observed := make(chan error, 1)
	relay.SetErrorHandler(func(err error) {
		observed <- err
	})
	if _, err := relay.Enqueue(ctx, KindReload, nil); err != nil {
		t.Fatal(err)
	}
	if err := relay.Start(ctx, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-observed:
		if !errors.Is(err, errFakeNotify) {
			t.Fatalf("handler received %v, want errFakeNotify", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("error handler was not invoked")
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestChangeBatchMarshalRoundTrip(t *testing.T) {
	batch := &ChangeBatch{
		Sequence:   9,
		BatchID:    "batch-9",
		Kind:       KindOperations,
		Operations: sampleOperations(),
		CreatedAt:  time.Now().UTC(),
	}
	data, err := batch.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalBatch(data)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Sequence != batch.Sequence || restored.BatchID != batch.BatchID || restored.Kind != batch.Kind {
		t.Fatalf("restored batch = %+v", restored)
	}
	if len(restored.Operations) != 1 || restored.Operations[0].PolicyType != "p" {
		t.Fatalf("restored operations = %+v", restored.Operations)
	}
}

func TestUnmarshalBatchRejectsIncompletePayload(t *testing.T) {
	if _, err := UnmarshalBatch([]byte(`{"sequence":1}`)); !errors.Is(err, ErrInvalidBatch) {
		t.Fatalf("unmarshal without batch id = %v, want ErrInvalidBatch", err)
	}
}
