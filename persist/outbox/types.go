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

// Package outbox provides a persistent outbox for policy-change
// notifications. Every committed policy change is first stored as a
// uniquely identified, monotonically ordered batch and is only marked as
// acknowledged after the watcher has been notified successfully. Batches
// that are not acknowledged are replayed after a restart, and receivers can
// apply them idempotently and in version order through Guard.
package outbox

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/casbin/casbin/v3/persist"
)

// Sentinel errors returned by the outbox. Callers can use errors.Is to test
// for them instead of matching error strings.
var (
	// ErrStoreClosed is returned when an operation hits a store that has
	// already been closed.
	ErrStoreClosed = errors.New("outbox: store is closed")
	// ErrNotifierMissing is returned when flushing is requested without a
	// configured notifier.
	ErrNotifierMissing = errors.New("outbox: notifier is not configured")
	// ErrEmptyBatch is returned when an enqueue request carries no change.
	ErrEmptyBatch = errors.New("outbox: batch must contain at least one operation")
	// ErrInvalidBatch is returned when a batch cannot be unmarshaled or is
	// missing its identity fields.
	ErrInvalidBatch = errors.New("outbox: invalid change batch")
	// ErrCursorUnavailable is returned when the receiver cursor cannot be
	// loaded or persisted.
	ErrCursorUnavailable = errors.New("outbox: receiver cursor unavailable")
)

// BatchKind describes how a batch should be delivered and applied.
type BatchKind int

const (
	// KindOperations carries granular policy operations that receivers can
	// apply incrementally.
	KindOperations BatchKind = iota
	// KindReload asks receivers to reload their complete policy set. It is
	// used when granular information is unavailable, e.g. a plain Watcher
	// Update call or a full SavePolicy notification.
	KindReload
)

// ChangeBatch is the persisted, uniquely identified unit of policy-change
// notification. Sequence is strictly monotonic per outbox and BatchID is the
// idempotency key used by receivers.
type ChangeBatch struct {
	// Sequence is the monotonic policy version of this batch.
	Sequence uint64 `json:"sequence"`
	// BatchID uniquely identifies this batch for idempotent delivery.
	BatchID string `json:"batch_id"`
	// Kind selects granular application or a full reload.
	Kind BatchKind `json:"kind"`
	// Operations holds the granular policy operations. It is empty for
	// KindReload batches.
	Operations []persist.PolicyOperation `json:"operations,omitempty"`
	// CreatedAt records when the batch was produced.
	CreatedAt time.Time `json:"created_at"`
}

// Marshal serializes the batch so that transports can carry it, e.g. as the
// string payload of a watcher update callback.
func (b *ChangeBatch) Marshal() ([]byte, error) {
	if b == nil || b.BatchID == "" || b.Sequence == 0 {
		return nil, ErrInvalidBatch
	}
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// UnmarshalBatch parses a batch produced by Marshal and validates its
// identity fields.
func UnmarshalBatch(data []byte) (*ChangeBatch, error) {
	batch := &ChangeBatch{}
	if err := json.Unmarshal(data, batch); err != nil {
		return nil, err
	}
	if batch.BatchID == "" || batch.Sequence == 0 {
		return nil, ErrInvalidBatch
	}
	return batch, nil
}
