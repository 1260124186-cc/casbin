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

package errors

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors returned by MigrateImplicitPriority. They are wrapped in
// PriorityMigrationError, so callers should use errors.Is instead of
// comparing messages.
var (
	// ErrPriorityMigration is the generic sentinel for every migration failure.
	ErrPriorityMigration = errors.New("implicit priority migration failed")
	// ErrRuleNotMappable reports a rule that cannot be converted to an
	// explicit priority, e.g. its priority field holds a non-numeric value.
	ErrRuleNotMappable = errors.New("rule cannot be mapped to an explicit priority")
	// ErrDuplicatePriority reports that two rules would carry the same priority.
	ErrDuplicatePriority = errors.New("duplicate explicit priority")
	// ErrPriorityPersist reports that persisting migrated rules failed.
	ErrPriorityPersist = errors.New("failed to persist migrated priorities")
)

// PriorityMigrationError carries enough context to locate the rule that
// blocked the migration. Index is the zero-based position of the rule inside
// its named policy; it is -1 when the failure is not rule-specific.
type PriorityMigrationError struct {
	// Op is the migration stage that failed, one of
	// "map", "duplicate" and "persist".
	Op string
	// PType is the named policy type being migrated, e.g. "p".
	PType string
	// Index is the zero-based rule index within PType, -1 when unknown.
	Index int
	// Rule is the offending policy rule (without the ptype prefix).
	Rule []string
	// Detail holds extra human-readable context.
	Detail string
	// Err wraps the underlying cause, if any.
	Err error
}

// NewPriorityMigrationError builds a locatable migration error.
func NewPriorityMigrationError(op, ptype string, index int, rule []string, detail string, cause error) *PriorityMigrationError {
	return &PriorityMigrationError{
		Op:     op,
		PType:  ptype,
		Index:  index,
		Rule:   append([]string(nil), rule...),
		Detail: detail,
		Err:    cause,
	}
}

func (e *PriorityMigrationError) Error() string {
	var b strings.Builder
	b.WriteString(ErrPriorityMigration.Error())
	b.WriteString(" [op=")
	b.WriteString(e.Op)
	b.WriteString(", ptype=")
	b.WriteString(e.PType)
	if e.Index >= 0 {
		b.WriteString(fmt.Sprintf(", rule_index=%d", e.Index))
	}
	if len(e.Rule) > 0 {
		b.WriteString(fmt.Sprintf(", rule=%v", e.Rule))
	}
	b.WriteString("]")
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

// Unwrap exposes the underlying cause and the matching sentinel error.
func (e *PriorityMigrationError) Unwrap() []error {
	wrapped := make([]error, 0, 2)
	switch e.Op {
	case "map":
		wrapped = append(wrapped, ErrRuleNotMappable)
	case "duplicate":
		wrapped = append(wrapped, ErrDuplicatePriority)
	case "persist":
		wrapped = append(wrapped, ErrPriorityPersist)
	}
	wrapped = append(wrapped, ErrPriorityMigration)
	if e.Err != nil {
		wrapped = append(wrapped, e.Err)
	}
	return wrapped
}
