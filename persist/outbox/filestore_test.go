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
	"testing"
)

func newTestFileStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("create file store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func makeBatch(sequence uint64, id string) *ChangeBatch {
	return &ChangeBatch{
		Sequence: sequence,
		BatchID:  id,
		Kind:     KindReload,
	}
}

func TestFileStoreAppendFetchAndCheckpoint(t *testing.T) {
	ctx := context.Background()
	store := newTestFileStore(t)

	for sequence := uint64(1); sequence <= 3; sequence++ {
		if err := store.Append(ctx, makeBatch(sequence, "batch-"+string(rune('0'+sequence)))); err != nil {
			t.Fatalf("append batch %d: %v", sequence, err)
		}
	}

	pending, err := store.FetchPending(ctx)
	if err != nil {
		t.Fatalf("fetch pending: %v", err)
	}
	if len(pending) != 3 || pending[0].Sequence != 1 || pending[2].Sequence != 3 {
		t.Fatalf("unexpected pending batches: %+v", pending)
	}

	err = store.Checkpoint(ctx, 2)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	pending, err = store.FetchPending(ctx)
	if err != nil {
		t.Fatalf("fetch pending after checkpoint: %v", err)
	}
	if len(pending) != 1 || pending[0].Sequence != 3 {
		t.Fatalf("only sequence 3 should remain pending, got %+v", pending)
	}

	checkpoint, err := store.LoadCheckpoint(ctx)
	if err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
	if checkpoint != 2 {
		t.Fatalf("checkpoint = %d, want 2", checkpoint)
	}
}

func TestFileStoreCheckpointNeverMovesBackwards(t *testing.T) {
	ctx := context.Background()
	store := newTestFileStore(t)

	if err := store.Append(ctx, makeBatch(1, "a")); err != nil {
		t.Fatal(err)
	}
	if err := store.Checkpoint(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Checkpoint(ctx, 1); err != nil {
		t.Fatalf("repeated checkpoint should be a no-op: %v", err)
	}
	checkpoint, err := store.LoadCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint != 1 {
		t.Fatalf("checkpoint = %d, want 1", checkpoint)
	}
}

func TestFileStoreRestoresStateAfterReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 3; sequence++ {
		err = store.Append(ctx, makeBatch(sequence, "batch-"+string(rune('0'+sequence))))
		if err != nil {
			t.Fatal(err)
		}
	}
	err = store.Checkpoint(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = store.Close()
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	checkpoint, err := reopened.LoadCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint != 1 {
		t.Fatalf("restored checkpoint = %d, want 1", checkpoint)
	}
	pending, err := reopened.FetchPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || pending[0].Sequence != 2 || pending[1].Sequence != 3 {
		t.Fatalf("restored pending = %+v, want sequences 2 and 3", pending)
	}
}

func TestFileStorePersistsReceiverCursor(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cursor := &AppliedCursor{Sequence: 7, BatchIDs: []string{"id-1", "id-2"}}
	err = store.SaveCursor(ctx, cursor)
	if err != nil {
		t.Fatalf("save cursor: %v", err)
	}
	err = store.Close()
	if err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.LoadCursor(ctx)
	if err != nil {
		t.Fatalf("load cursor: %v", err)
	}
	if loaded.Sequence != 7 || len(loaded.BatchIDs) != 2 || loaded.BatchIDs[1] != "id-2" {
		t.Fatalf("restored cursor = %+v", loaded)
	}
}

func TestFileStoreRejectsOperationsAfterClose(t *testing.T) {
	ctx := context.Background()
	store := newTestFileStore(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if err := store.Append(ctx, makeBatch(1, "a")); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("append after close = %v, want ErrStoreClosed", err)
	}
	if _, err := store.FetchPending(ctx); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("fetch after close = %v, want ErrStoreClosed", err)
	}
	if err := store.Checkpoint(ctx, 1); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("checkpoint after close = %v, want ErrStoreClosed", err)
	}
}

func TestFileStoreHonorsCanceledContext(t *testing.T) {
	store := newTestFileStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := store.Append(ctx, makeBatch(1, "a")); !errors.Is(err, context.Canceled) {
		t.Fatalf("append with canceled context = %v, want context.Canceled", err)
	}
}

// failingAppendStore wraps a Store and forces Append to fail.
type failingAppendStore struct {
	Store
	appendErr error
}

func (s *failingAppendStore) Append(ctx context.Context, batch *ChangeBatch) error {
	return s.appendErr
}

func TestFileStoreRejectsInvalidBatch(t *testing.T) {
	ctx := context.Background()
	store := newTestFileStore(t)
	if err := store.Append(ctx, &ChangeBatch{Sequence: 1}); !errors.Is(err, ErrInvalidBatch) {
		t.Fatalf("append batch without id = %v, want ErrInvalidBatch", err)
	}
}
