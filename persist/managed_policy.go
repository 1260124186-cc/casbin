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

package persist

// ManagedPolicyAdapter is implemented by adapters that can persist which
// policy rules are owned (delivered) by a management console for a domain.
//
// The ownership record is the basis of domain policy reconciliation: on
// ReconcileDomainPolicySnapshot, only rules recorded here are revoked when
// they disappear from a new snapshot, while rules added out-of-band (manual
// rules) stay untouched. Both methods participate in the adapter transaction
// returned by TransactionalAdapter.BeginTransaction when the transaction
// scoped adapter (TransactionContext.GetAdapter) also implements this
// interface, so ownership updates and policy writes commit or roll back
// together.
type ManagedPolicyAdapter interface {
	// LoadManagedPolicy loads the policy rule tuples currently owned by the
	// management console in the given domain. An empty result means the
	// console owns no rule in that domain yet.
	LoadManagedPolicy(domain string) ([][]string, error)

	// ReplaceManagedPolicy replaces the whole ownership record of the given
	// domain with the provided rule tuples. Passing an empty slice clears the
	// record for the domain.
	ReplaceManagedPolicy(domain string, rules [][]string) error
}
