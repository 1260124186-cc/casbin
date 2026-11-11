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

package casbin

import "errors"

// Sentinel errors returned by the model and policy cutover workflow.
// Callers should use errors.Is to detect them, because concrete errors wrap
// the sentinel together with the underlying cause.
var (
	// ErrNilStore is returned when a cutover manager is created without a store.
	ErrNilStore = errors.New("casbin: cutover generation store is nil")

	// ErrNilModel is returned when Stage receives a nil candidate model.
	ErrNilModel = errors.New("casbin: cutover candidate model is nil")

	// ErrInvalidGenerationID is returned when a generation ID is empty or unsafe.
	ErrInvalidGenerationID = errors.New("casbin: invalid generation ID")

	// ErrModelPolicyMismatch is returned when the policy references a ptype that
	// the model does not define, or when the model misses a required section.
	ErrModelPolicyMismatch = errors.New("casbin: model and policy do not match")

	// ErrPolicyRuleLengthMismatch is returned when a rule length does not fit
	// the token count of its policy definition.
	ErrPolicyRuleLengthMismatch = errors.New("casbin: policy rule length does not match the model definition")

	// ErrGenerationNotLoadable is returned when a candidate cannot be loaded as
	// a fully working enforcer generation.
	ErrGenerationNotLoadable = errors.New("casbin: generation is not loadable")

	// ErrPersistenceFailed is returned when writing a generation or the cutover
	// state to the store fails. The previously active generation stays in service.
	ErrPersistenceFailed = errors.New("casbin: generation persistence failed")

	// ErrGenerationAlreadyActive is returned when the active generation is
	// staged or committed again. It makes re-applying the same generation a
	// safe no-op instead of a second cutover.
	ErrGenerationAlreadyActive = errors.New("casbin: generation is already active")

	// ErrNoStagedGeneration is returned when Commit targets a generation that
	// has not been staged successfully.
	ErrNoStagedGeneration = errors.New("casbin: no matching staged generation")

	// ErrGenerationNotFound is returned when the store holds no record of a generation.
	ErrGenerationNotFound = errors.New("casbin: generation not found")

	// ErrNoPreviousGeneration is returned when Rollback is called without a
	// retained previous generation.
	ErrNoPreviousGeneration = errors.New("casbin: no previous generation to roll back to")

	// ErrCannotRetireActiveGeneration is returned when Retire targets the
	// generation currently serving traffic.
	ErrCannotRetireActiveGeneration = errors.New("casbin: cannot retire the active generation")

	// ErrBootstrapRequired is returned on an empty store when no bootstrap
	// enforcer and ID are supplied.
	ErrBootstrapRequired = errors.New("casbin: bootstrap enforcer is required for an empty store")

	// ErrInvalidStoredGeneration is returned when neither the active nor the
	// previous persisted generation can be recovered into a working enforcer.
	ErrInvalidStoredGeneration = errors.New("casbin: stored generation is not loadable")

	// ErrStateNotFound is returned by a store when no cutover state has been
	// persisted yet. It is expected on the very first manager creation.
	ErrStateNotFound = errors.New("casbin: cutover state not found")
)
