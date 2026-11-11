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
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const (
	logFileName        = "outbox.log"
	checkpointFileName = "checkpoint.json"
	cursorFileName     = "receiver-cursor.json"
	dirPerm            = 0o750
	filePerm           = 0o600
)

// FileStore is a filesystem-backed implementation of Store and CursorStore.
// Pending batches live in an append-only JSON-lines log that is fsynced on
// every append, while the checkpoint and the receiver cursor are written
// atomically through temp-file rename plus a directory fsync. The layout
// therefore stays replayable after a crash at any point.
//
// A single directory must only be owned by one FileStore at a time;
// in-process access is serialized and multiple processes sharing a directory
// require an external lock.
type FileStore struct {
	dir        string
	mu         sync.Mutex
	closed     bool
	checkpoint uint64
}

// NewFileStore opens (or creates) a file store in dir and restores the
// previously persisted checkpoint.
func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, err
	}
	store := &FileStore{dir: dir}
	checkpoint, err := store.readCheckpointFile()
	if err != nil {
		return nil, err
	}
	store.checkpoint = checkpoint
	return store, nil
}

// Append durably appends a pending batch to the log.
func (s *FileStore) Append(ctx context.Context, batch *ChangeBatch) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if batch == nil || batch.BatchID == "" || batch.Sequence == 0 {
		return ErrInvalidBatch
	}
	line, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	return s.appendLine(line)
}

// FetchPending returns all unacknowledged batches in ascending sequence
// order.
func (s *FileStore) FetchPending(ctx context.Context) ([]*ChangeBatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	batches, err := s.readLogLocked()
	if err != nil {
		return nil, err
	}
	pending := make([]*ChangeBatch, 0, len(batches))
	for _, batch := range batches {
		if batch.Sequence > s.checkpoint {
			pending = append(pending, batch)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].Sequence < pending[j].Sequence
	})
	return pending, nil
}

// Checkpoint advances the acknowledgment watermark and compacts the log by
// dropping every batch at or below it. Moving the watermark backwards is a
// no-op.
func (s *FileStore) Checkpoint(ctx context.Context, sequence uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if sequence <= s.checkpoint {
		return nil
	}
	if err := s.writeCheckpointLocked(sequence); err != nil {
		return err
	}
	s.checkpoint = sequence
	return s.compactLogLocked(sequence)
}

// LoadCheckpoint returns the current acknowledgment watermark.
func (s *FileStore) LoadCheckpoint(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrStoreClosed
	}
	return s.checkpoint, nil
}

// LoadCursor returns the persisted receiver cursor or a zero cursor when no
// batch has been applied yet.
func (s *FileStore) LoadCursor(ctx context.Context) (*AppliedCursor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	data, err := os.ReadFile(s.cursorPath())
	if os.IsNotExist(err) {
		return &AppliedCursor{BatchIDs: make([]string, 0)}, nil
	}
	if err != nil {
		return nil, err
	}
	cursor := &AppliedCursor{}
	if err := json.Unmarshal(data, cursor); err != nil {
		return nil, err
	}
	if cursor.BatchIDs == nil {
		cursor.BatchIDs = make([]string, 0)
	}
	return cursor, nil
}

// SaveCursor durably persists the receiver cursor.
func (s *FileStore) SaveCursor(ctx context.Context, cursor *AppliedCursor) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if cursor == nil {
		return ErrCursorUnavailable
	}
	payload, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	return s.atomicWriteLocked(s.cursorPath(), payload)
}

// Close marks the store as closed. It is safe to call multiple times.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *FileStore) appendLine(line []byte) error {
	file, err := os.OpenFile(s.logPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, filePerm)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(line)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func (s *FileStore) readLogLocked() ([]*ChangeBatch, error) {
	file, err := os.Open(s.logPath())
	if os.IsNotExist(err) {
		return make([]*ChangeBatch, 0), nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	batches := make([]*ChangeBatch, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		batch := &ChangeBatch{}
		if err := json.Unmarshal(line, batch); err != nil {
			return nil, err
		}
		batches = append(batches, batch)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return batches, nil
}

func (s *FileStore) compactLogLocked(sequence uint64) error {
	batches, err := s.readLogLocked()
	if err != nil {
		return err
	}
	pending := make([]*ChangeBatch, 0, len(batches))
	for _, batch := range batches {
		if batch.Sequence > sequence {
			pending = append(pending, batch)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].Sequence < pending[j].Sequence
	})

	payload := make([]byte, 0)
	for _, batch := range pending {
		line, marshalErr := json.Marshal(batch)
		if marshalErr != nil {
			return marshalErr
		}
		payload = append(payload, line...)
		payload = append(payload, '\n')
	}
	return s.atomicWriteLocked(s.logPath(), payload)
}

func (s *FileStore) writeCheckpointLocked(sequence uint64) error {
	payload, err := json.Marshal(sequence)
	if err != nil {
		return err
	}
	return s.atomicWriteLocked(s.checkpointPath(), payload)
}

func (s *FileStore) readCheckpointFile() (uint64, error) {
	data, err := os.ReadFile(s.checkpointPath())
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var checkpoint uint64
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return 0, err
	}
	return checkpoint, nil
}

// atomicWriteLocked writes payload to path via a temp file, fsync and rename,
// then fsyncs the directory so the rename itself is durable. The caller must
// hold s.mu.
func (s *FileStore) atomicWriteLocked(path string, payload []byte) error {
	tmpPath := path + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, filePerm)
	if err != nil {
		return err
	}
	if _, err = file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDir(s.dir)
}

func (s *FileStore) logPath() string {
	return filepath.Join(s.dir, logFileName)
}

func (s *FileStore) checkpointPath() string {
	return filepath.Join(s.dir, checkpointFileName)
}

func (s *FileStore) cursorPath() string {
	return filepath.Join(s.dir, cursorFileName)
}

func syncDir(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
