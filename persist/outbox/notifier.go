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

	"github.com/casbin/casbin/v3/persist"
)

// WatcherNotifier adapts a persist.Watcher (optionally also WatcherEx or
// UpdatableWatcher) to the Notifier interface. It mirrors the notification
// dispatch the enforcer performs for non-transactional and transactional
// policy commits, so existing watcher implementations can be wrapped without
// changes.
type WatcherNotifier struct {
	watcher persist.Watcher
}

// NewWatcherNotifier wraps an existing watcher as an outbox Notifier.
func NewWatcherNotifier(watcher persist.Watcher) *WatcherNotifier {
	return &WatcherNotifier{watcher: watcher}
}

// Notify delivers one batch through the wrapped watcher.
func (n *WatcherNotifier) Notify(ctx context.Context, batch *ChangeBatch) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if batch.Kind == KindReload {
		return n.watcher.Update()
	}

	watcherEx, isWatcherEx := n.watcher.(persist.WatcherEx)
	updatableWatcher, isUpdatable := n.watcher.(persist.UpdatableWatcher)
	if !isWatcherEx && !isUpdatable {
		return n.watcher.Update()
	}

	for _, operation := range batch.Operations {
		if err := n.notifyOperation(watcherEx, isWatcherEx, updatableWatcher, isUpdatable, operation); err != nil {
			return err
		}
	}
	return nil
}

func (n *WatcherNotifier) notifyOperation(
	watcherEx persist.WatcherEx,
	isWatcherEx bool,
	updatableWatcher persist.UpdatableWatcher,
	isUpdatable bool,
	operation persist.PolicyOperation,
) error {
	switch operation.Type {
	case persist.OperationAdd:
		if isWatcherEx {
			return watcherEx.UpdateForAddPolicies(operation.Section, operation.PolicyType, operation.Rules...)
		}
		return n.watcher.Update()
	case persist.OperationRemove:
		if isWatcherEx {
			return watcherEx.UpdateForRemovePolicies(operation.Section, operation.PolicyType, operation.Rules...)
		}
		return n.watcher.Update()
	case persist.OperationUpdate:
		if isUpdatable {
			return updatableWatcher.UpdateForUpdatePolicies(
				operation.Section, operation.PolicyType, operation.OldRules, operation.Rules)
		}
		return n.watcher.Update()
	}
	return n.watcher.Update()
}
