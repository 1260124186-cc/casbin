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

	"github.com/casbin/casbin/v3/persist"
)

// defaultTrackedBatches bounds how many applied batch identifiers are kept
// for duplicate detection. Anything older than the window is already covered
// by the monotonic sequence check.
const defaultTrackedBatches = 1024

// Guard is the receiver-side protection against duplicate and out-of-order
// deliveries. A batch is applied only when its sequence is greater than the
// last applied one and its batch identifier has not been seen before. The
// applied position is persisted before Accept reports success, so the
// guarantees survive process restarts.
type Guard struct {
	store CursorStore
	limit int

	mu       sync.Mutex
	sequence uint64
	seen     map[string]struct{}
	recent   []string
}

// NewGuard restores the durable receiver position from store.
func NewGuard(ctx context.Context, store CursorStore) (*Guard, error) {
	cursor, err := store.LoadCursor(ctx)
	if err != nil {
		return nil, fmt.Errorf("outbox: load receiver cursor: %w", err)
	}
	guard := &Guard{
		store:    store,
		limit:    defaultTrackedBatches,
		sequence: cursor.Sequence,
		seen:     make(map[string]struct{}, len(cursor.BatchIDs)),
		recent:   append(make([]string, 0, len(cursor.BatchIDs)), cursor.BatchIDs...),
	}
	for _, batchID := range cursor.BatchIDs {
		guard.seen[batchID] = struct{}{}
	}
	return guard, nil
}

// Accept applies batch through apply when it is a new, in-order delivery.
// It reports applied=false without an error for duplicate batches and for
// batches older than the applied position. An apply or cursor persistence
// failure leaves the guard position untouched so that the batch can be
// retried safely. apply must not re-enter the guard and should be idempotent
// for redelivery; EnforcerApplier satisfies that contract.
func (g *Guard) Accept(ctx context.Context, batch *ChangeBatch, apply func() error) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if batch == nil || batch.BatchID == "" || batch.Sequence == 0 {
		return false, ErrInvalidBatch
	}
	if !g.deliverableLocked(batch) {
		return false, nil
	}
	if apply != nil {
		if err := apply(); err != nil {
			return false, err
		}
	}

	recent := nextRecent(g.recent, batch.BatchID, g.limit)
	cursor := &AppliedCursor{Sequence: batch.Sequence, BatchIDs: recent}
	if err := g.store.SaveCursor(ctx, cursor); err != nil {
		return false, fmt.Errorf("outbox: persist receiver cursor: %w", err)
	}

	g.sequence = batch.Sequence
	g.recent = recent
	g.seen[batch.BatchID] = struct{}{}
	return true, nil
}

// LastSequence returns the highest applied batch sequence.
func (g *Guard) LastSequence() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sequence
}

// IsDeliverable reports whether a batch would be accepted.
func (g *Guard) IsDeliverable(batch *ChangeBatch) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.deliverableLocked(batch)
}

func (g *Guard) deliverableLocked(batch *ChangeBatch) bool {
	if batch.Sequence <= g.sequence {
		return false
	}
	_, duplicated := g.seen[batch.BatchID]
	return !duplicated
}

func nextRecent(recent []string, batchID string, limit int) []string {
	result := append(make([]string, 0, len(recent)+1), recent...)
	result = append(result, batchID)
	if len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

// PolicyReceiver is the granular policy surface required to apply a batch.
// *casbin.Enforcer and the synced/distributed enforcers implement it.
type PolicyReceiver interface {
	AddNamedPolicies(ptype string, rules [][]string) (bool, error)
	RemoveNamedPolicies(ptype string, rules [][]string) (bool, error)
	UpdateNamedPolicies(ptype string, oldRules, newRules [][]string) (bool, error)
	AddNamedGroupingPolicies(ptype string, rules [][]string) (bool, error)
	RemoveNamedGroupingPolicies(ptype string, rules [][]string) (bool, error)
	UpdateNamedGroupingPolicies(ptype string, oldRules, newRules [][]string) (bool, error)
	LoadPolicy() error
}

// EnforcerApplier turns a batch into idempotent enforcer calls. Re-applying
// an already effective batch is a no-op: the enforcer reports no change and
// no error for adds, removes and updates whose rules are already in the
// target state.
type EnforcerApplier struct {
	receiver PolicyReceiver
}

// NewEnforcerApplier wraps an enforcer as a batch applier.
func NewEnforcerApplier(receiver PolicyReceiver) *EnforcerApplier {
	return &EnforcerApplier{receiver: receiver}
}

// Apply executes all operations of one batch, or reloads the full policy for
// a KindReload batch.
func (a *EnforcerApplier) Apply(batch *ChangeBatch) error {
	if batch.Kind == KindReload {
		return a.receiver.LoadPolicy()
	}
	for _, operation := range batch.Operations {
		if err := a.applyOperation(operation); err != nil {
			return err
		}
	}
	return nil
}

func (a *EnforcerApplier) applyOperation(operation persist.PolicyOperation) error {
	if operation.Section == "g" {
		return a.applyGrouping(operation)
	}
	return a.applyPolicy(operation)
}

func (a *EnforcerApplier) applyPolicy(operation persist.PolicyOperation) error {
	switch operation.Type {
	case persist.OperationAdd:
		_, err := a.receiver.AddNamedPolicies(operation.PolicyType, operation.Rules)
		return err
	case persist.OperationRemove:
		_, err := a.receiver.RemoveNamedPolicies(operation.PolicyType, operation.Rules)
		return err
	case persist.OperationUpdate:
		_, err := a.receiver.UpdateNamedPolicies(operation.PolicyType, operation.OldRules, operation.Rules)
		return err
	}
	return nil
}

func (a *EnforcerApplier) applyGrouping(operation persist.PolicyOperation) error {
	switch operation.Type {
	case persist.OperationAdd:
		_, err := a.receiver.AddNamedGroupingPolicies(operation.PolicyType, operation.Rules)
		return err
	case persist.OperationRemove:
		_, err := a.receiver.RemoveNamedGroupingPolicies(operation.PolicyType, operation.Rules)
		return err
	case persist.OperationUpdate:
		_, err := a.receiver.UpdateNamedGroupingPolicies(operation.PolicyType, operation.OldRules, operation.Rules)
		return err
	}
	return nil
}
