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
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// Interface compliance checks.
var (
	_ persist.Watcher          = (*OutboxWatcher)(nil)
	_ persist.WatcherEx        = (*OutboxWatcher)(nil)
	_ persist.UpdatableWatcher = (*OutboxWatcher)(nil)
)

// OutboxWatcher wraps a regular watcher with a persistent outbox. Every
// watcher notification triggered by a policy commit first becomes a durable,
// ordered batch and is only acknowledged after the wrapped watcher has been
// notified successfully. Notification failures are returned to the enforcer
// while the batch stays replayable. On construction, batches left
// unacknowledged by a previous process are replayed automatically.
type OutboxWatcher struct {
	inner  persist.Watcher
	outbox *Outbox
}

type watcherOptions struct {
	autoFlush     bool
	flushInterval time.Duration
	errHandler    ErrorHandler
}

// Option customizes an OutboxWatcher.
type Option func(*watcherOptions)

// WithAutoFlush enables a background flusher that periodically retries
// unacknowledged batches. Without it, flushing happens inline with every
// policy commit and can be triggered manually through Outbox.
func WithAutoFlush(interval time.Duration) Option {
	return func(options *watcherOptions) {
		options.autoFlush = true
		options.flushInterval = interval
	}
}

// WithErrorHandler installs a handler for failures of the automatic startup
// replay and the background flusher. Inline commit errors are still returned
// from the watcher methods directly.
func WithErrorHandler(handler ErrorHandler) Option {
	return func(options *watcherOptions) {
		options.errHandler = handler
	}
}

// NewOutboxWatcher wraps inner with an outbox backed by store. Unacknowledged
// batches found in store are replayed immediately; a replay failure does not
// abort construction, it is recorded on the outbox (and forwarded to the
// error handler) while the batches remain pending.
func NewOutboxWatcher(
	ctx context.Context,
	inner persist.Watcher,
	store Store,
	options ...Option,
) (*OutboxWatcher, error) {
	if inner == nil {
		return nil, errors.New("outbox: inner watcher must not be nil")
	}
	if store == nil {
		return nil, errors.New("outbox: store must not be nil")
	}

	config := &watcherOptions{}
	for _, option := range options {
		option(config)
	}

	relay, err := New(ctx, store, NewWatcherNotifier(inner))
	if err != nil {
		return nil, err
	}
	if config.errHandler != nil {
		relay.SetErrorHandler(config.errHandler)
	}

	// Automatic startup replay: a failure is retained for the next flush
	// instead of blocking enforcer construction.
	_ = relay.Flush(ctx)

	if config.autoFlush {
		if err := relay.Start(ctx, config.flushInterval); err != nil {
			return nil, err
		}
	}
	return &OutboxWatcher{inner: inner, outbox: relay}, nil
}

// Outbox exposes the underlying relay for manual flushing and inspection.
func (w *OutboxWatcher) Outbox() *Outbox {
	return w.outbox
}

// SetUpdateCallback delegates callback registration to the wrapped watcher.
func (w *OutboxWatcher) SetUpdateCallback(callback func(string)) error {
	return w.inner.SetUpdateCallback(callback)
}

// Close stops the relay, closes the store and releases the wrapped watcher.
func (w *OutboxWatcher) Close() {
	_ = w.outbox.Close()
	w.inner.Close()
}

// Update persists a full-reload batch.
func (w *OutboxWatcher) Update() error {
	return w.submit(KindReload, nil)
}

// UpdateForAddPolicy persists a single-rule add batch.
func (w *OutboxWatcher) UpdateForAddPolicy(sec, ptype string, params ...string) error {
	operation := persist.PolicyOperation{
		Type:       persist.OperationAdd,
		Section:    sec,
		PolicyType: ptype,
		Rules:      [][]string{params},
	}
	return w.submit(KindOperations, []persist.PolicyOperation{operation})
}

// UpdateForRemovePolicy persists a single-rule remove batch.
func (w *OutboxWatcher) UpdateForRemovePolicy(sec, ptype string, params ...string) error {
	operation := persist.PolicyOperation{
		Type:       persist.OperationRemove,
		Section:    sec,
		PolicyType: ptype,
		Rules:      [][]string{params},
	}
	return w.submit(KindOperations, []persist.PolicyOperation{operation})
}

// UpdateForRemoveFilteredPolicy falls back to a full reload because the
// filtered operation cannot be represented as a granular PolicyOperation.
func (w *OutboxWatcher) UpdateForRemoveFilteredPolicy(
	sec, ptype string,
	fieldIndex int,
	fieldValues ...string,
) error {
	return w.submit(KindReload, nil)
}

// UpdateForSavePolicy persists a full-reload batch for the saved model.
func (w *OutboxWatcher) UpdateForSavePolicy(model model.Model) error {
	return w.submit(KindReload, nil)
}

// UpdateForAddPolicies persists a batch add operation.
func (w *OutboxWatcher) UpdateForAddPolicies(sec string, ptype string, rules ...[]string) error {
	operation := persist.PolicyOperation{
		Type:       persist.OperationAdd,
		Section:    sec,
		PolicyType: ptype,
		Rules:      rules,
	}
	return w.submit(KindOperations, []persist.PolicyOperation{operation})
}

// UpdateForRemovePolicies persists a batch remove operation.
func (w *OutboxWatcher) UpdateForRemovePolicies(sec string, ptype string, rules ...[]string) error {
	operation := persist.PolicyOperation{
		Type:       persist.OperationRemove,
		Section:    sec,
		PolicyType: ptype,
		Rules:      rules,
	}
	return w.submit(KindOperations, []persist.PolicyOperation{operation})
}

// UpdateForUpdatePolicy persists a single-rule update operation.
func (w *OutboxWatcher) UpdateForUpdatePolicy(
	sec, ptype string,
	oldRule, newRule []string,
) error {
	operation := persist.PolicyOperation{
		Type:       persist.OperationUpdate,
		Section:    sec,
		PolicyType: ptype,
		Rules:      [][]string{newRule},
		OldRules:   [][]string{oldRule},
	}
	return w.submit(KindOperations, []persist.PolicyOperation{operation})
}

// UpdateForUpdatePolicies persists a batch update operation.
func (w *OutboxWatcher) UpdateForUpdatePolicies(
	sec, ptype string,
	oldRules, newRules [][]string,
) error {
	operation := persist.PolicyOperation{
		Type:       persist.OperationUpdate,
		Section:    sec,
		PolicyType: ptype,
		Rules:      newRules,
		OldRules:   oldRules,
	}
	return w.submit(KindOperations, []persist.PolicyOperation{operation})
}

func (w *OutboxWatcher) submit(kind BatchKind, operations []persist.PolicyOperation) error {
	ctx := context.Background()
	if _, err := w.outbox.Enqueue(ctx, kind, operations); err != nil {
		return err
	}
	return w.outbox.Flush(ctx)
}
