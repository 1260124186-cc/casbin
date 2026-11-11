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
	"fmt"
	"sync"
	"time"

	"github.com/casbin/casbin/v3/persist"
	"github.com/google/uuid"
)

// Notifier delivers a single persisted batch to other instances. It must be
// safe for concurrent use when the outbox runs a background flusher.
type Notifier interface {
	Notify(ctx context.Context, batch *ChangeBatch) error
}

// ErrorHandler observes failures of the background flusher. It must never
// block. Inline Flush calls still return their errors directly.
type ErrorHandler func(error)

// Outbox is the send-side relay. Policy commits append batches through
// Enqueue; Flush delivers pending batches in ascending sequence order and
// only advances the store checkpoint after each successful notification.
// Batches that could not be acknowledged stay durable and are replayed by
// the next Flush, including after a process restart.
type Outbox struct {
	store      Store
	notifier   Notifier
	errHandler ErrorHandler

	mu      sync.Mutex
	nextSeq uint64
	closed  bool
	started bool
	lastErr error
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// New creates an outbox over store and restores the monotonic sequence
// counter from the durable checkpoint and pending log. notifier may be nil
// if batches are only enqueued for now; Flush requires one.
func New(ctx context.Context, store Store, notifier Notifier) (*Outbox, error) {
	checkpoint, err := store.LoadCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("outbox: load checkpoint: %w", err)
	}
	pending, err := store.FetchPending(ctx)
	if err != nil {
		return nil, fmt.Errorf("outbox: load pending batches: %w", err)
	}

	nextSeq := checkpoint + 1
	for _, batch := range pending {
		if batch.Sequence >= nextSeq {
			nextSeq = batch.Sequence + 1
		}
	}
	return &Outbox{
		store:    store,
		notifier: notifier,
		nextSeq:  nextSeq,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}, nil
}

// SetErrorHandler installs a callback for background flusher failures.
func (o *Outbox) SetErrorHandler(handler ErrorHandler) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.errHandler = handler
}

// Enqueue durably stores a new batch and returns it. The batch is retained
// for replay until Flush acknowledges it. A persistence failure is returned
// explicitly and nothing is silently dropped.
func (o *Outbox) Enqueue(ctx context.Context, kind BatchKind, operations []persist.PolicyOperation) (*ChangeBatch, error) {
	if kind == KindOperations && len(operations) == 0 {
		return nil, ErrEmptyBatch
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, ErrStoreClosed
	}

	batch := &ChangeBatch{
		Sequence:   o.nextSeq,
		BatchID:    uuid.NewString(),
		Kind:       kind,
		Operations: cloneOperations(operations),
		CreatedAt:  time.Now().UTC(),
	}
	if err := o.store.Append(ctx, batch); err != nil {
		return nil, fmt.Errorf("outbox: persist batch at sequence %d: %w", batch.Sequence, err)
	}
	o.nextSeq++
	return batch, nil
}

// Flush delivers every pending batch in ascending sequence order. It stops
// at the first failure, leaves the failing batch (and all later ones)
// untouched for replay and returns a wrapped error identifying the batch.
func (o *Outbox) Flush(ctx context.Context) error {
	if o.notifier == nil {
		return ErrNotifierMissing
	}
	pending, err := o.store.FetchPending(ctx)
	if err != nil {
		return fmt.Errorf("outbox: fetch pending batches: %w", err)
	}
	for _, batch := range pending {
		if err := o.deliverOne(ctx, batch); err != nil {
			o.reportError(err)
			return err
		}
	}
	return nil
}

// Start launches a background flusher that replays pending batches
// immediately and then every interval. It must be called at most once.
func (o *Outbox) Start(ctx context.Context, interval time.Duration) error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return ErrStoreClosed
	}
	if o.started {
		o.mu.Unlock()
		return nil
	}
	o.started = true
	o.mu.Unlock()

	go o.flushLoop(ctx, interval)
	return nil
}

// Close stops the background flusher and closes the underlying store.
func (o *Outbox) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	close(o.stopCh)
	started := o.started
	o.mu.Unlock()

	if started {
		<-o.doneCh
	}
	return o.store.Close()
}

// PendingCount returns how many batches are currently unacknowledged.
func (o *Outbox) PendingCount(ctx context.Context) (int, error) {
	pending, err := o.store.FetchPending(ctx)
	if err != nil {
		return 0, err
	}
	return len(pending), nil
}

// LastError returns the most recent background flusher failure, if any.
func (o *Outbox) LastError() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastErr
}

func (o *Outbox) deliverOne(ctx context.Context, batch *ChangeBatch) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := o.notifier.Notify(ctx, batch); err != nil {
		return fmt.Errorf("outbox: notify batch %s at sequence %d failed, batch retained for replay: %w",
			batch.BatchID, batch.Sequence, err)
	}
	if err := o.store.Checkpoint(ctx, batch.Sequence); err != nil {
		return fmt.Errorf("outbox: checkpoint batch %s at sequence %d failed, batch retained for replay: %w",
			batch.BatchID, batch.Sequence, err)
	}
	return nil
}

func (o *Outbox) flushLoop(ctx context.Context, interval time.Duration) {
	defer close(o.doneCh)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	o.runBackgroundFlush(ctx)
	for {
		select {
		case <-o.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.runBackgroundFlush(ctx)
		}
	}
}

func (o *Outbox) runBackgroundFlush(ctx context.Context) {
	if err := o.Flush(ctx); err != nil {
		o.reportError(err)
	}
}

func (o *Outbox) reportError(err error) {
	o.mu.Lock()
	o.lastErr = err
	handler := o.errHandler
	o.mu.Unlock()
	if handler != nil {
		handler(err)
	}
}

func cloneOperations(operations []persist.PolicyOperation) []persist.PolicyOperation {
	if len(operations) == 0 {
		return nil
	}
	cloned := make([]persist.PolicyOperation, len(operations))
	for i, op := range operations {
		cloned[i] = persist.PolicyOperation{
			Type:       op.Type,
			Section:    op.Section,
			PolicyType: op.PolicyType,
			Rules:      cloneRules(op.Rules),
			OldRules:   cloneRules(op.OldRules),
		}
	}
	return cloned
}

func cloneRules(rules [][]string) [][]string {
	if len(rules) == 0 {
		return nil
	}
	cloned := make([][]string, len(rules))
	for i, rule := range rules {
		cloned[i] = append(make([]string, 0, len(rule)), rule...)
	}
	return cloned
}
