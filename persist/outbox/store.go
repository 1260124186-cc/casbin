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

import "context"

// Store is the durable backend of a notification outbox. Implementations
// must survive process restarts and must not report success before a write
// has reached stable storage. A batch that has been appended must remain
// fetchable until a checkpoint advances past it.
type Store interface {
	// Append persists a pending batch. The batch sequence is assigned by
	// the outbox and must be unique. Returning an error means the batch is
	// not stored and the caller keeps ownership of it.
	Append(ctx context.Context, batch *ChangeBatch) error
	// FetchPending returns every batch whose sequence is greater than the
	// current checkpoint, ordered by ascending sequence.
	FetchPending(ctx context.Context) ([]*ChangeBatch, error)
	// Checkpoint advances the acknowledgment watermark. All batches with a
	// sequence up to and including the given one are considered delivered
	// and may be removed from pending storage. The watermark must never
	// move backwards.
	Checkpoint(ctx context.Context, sequence uint64) error
	// LoadCheckpoint returns the current acknowledgment watermark. It
	// returns zero when no batch has been acknowledged yet.
	LoadCheckpoint(ctx context.Context) (uint64, error)
	// Close releases any resources held by the store.
	Close() error
}

// AppliedCursor is the durable receiver-side position. Sequence is the last
// applied batch sequence and BatchIDs keeps a bounded window of recently
// applied batch IDs so that duplicate deliveries can be recognized.
type AppliedCursor struct {
	// Sequence is the highest batch sequence that has been applied.
	Sequence uint64 `json:"sequence"`
	// BatchIDs are the recently applied batch identifiers, oldest first.
	BatchIDs []string `json:"batch_ids"`
}

// CursorStore persists the receiver-side application cursor. It is kept
// separate from Store so that a receiving instance can track applied
// batches without owning an outbox of its own.
type CursorStore interface {
	// LoadCursor returns the persisted cursor, or a zero-value cursor when
	// nothing has been applied yet.
	LoadCursor(ctx context.Context) (*AppliedCursor, error)
	// SaveCursor durably stores the given cursor, replacing any previous
	// one.
	SaveCursor(ctx context.Context, cursor *AppliedCursor) error
	// Close releases any resources held by the cursor store.
	Close() error
}
