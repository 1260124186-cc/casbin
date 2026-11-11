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

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// GenerationID identifies one immutable model and policy generation.
// A generation never changes once it has been validated and persisted;
// switching traffic means pointing the active pointer at another ID.
type GenerationID string

// CutoverState is the durable pointer to the generations managed by a cutover.
// The JSON document is replaced atomically, so a process that exits at any
// point always observes either the old or the new complete state on restart.
type CutoverState struct {
	// Active is the generation that serves new enforcement requests.
	Active GenerationID `json:"active"`

	// Staged is the validated generation waiting to be committed. It is empty
	// when no cutover is in flight.
	Staged GenerationID `json:"staged,omitempty"`

	// Previous is the generation that was active before the latest cutover and
	// remains readable for rollback until it is retired.
	Previous GenerationID `json:"previous,omitempty"`

	// UpdatedAt records when the state document was last replaced.
	UpdatedAt time.Time `json:"updated_at"`
}

// GenerationStore persists generation artifacts and the cutover state.
// Implementations must make every write crash-safe: readers must never
// observe a partially written generation document or state document.
type GenerationStore interface {
	// SaveGeneration persists the model text and policy text of one generation.
	SaveGeneration(id GenerationID, modelText, policyText string) error

	// LoadGeneration reads back a previously persisted generation.
	LoadGeneration(id GenerationID) (modelText, policyText string, err error)

	// ListGenerations returns the IDs of every persisted generation.
	ListGenerations() ([]GenerationID, error)

	// DeleteGeneration removes every artifact of one generation.
	DeleteGeneration(id GenerationID) error

	// SaveState atomically replaces the cutover state document.
	SaveState(state *CutoverState) error

	// LoadState reads the cutover state document. It returns ErrStateNotFound
	// when no state has been persisted yet.
	LoadState() (*CutoverState, error)
}

const (
	generationDirName  = "generations"
	modelFileName      = "model.conf"
	policyFileName     = "policy.csv"
	stateFileName      = "state.json"
	generationDirPerm  = 0o700
	generationFilePerm = 0o600
	maxGenerationIDLen = 128
)

// generationIDPattern keeps IDs usable as plain directory names and blocks
// path traversal and hidden-file tricks.
var generationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validateGenerationID(id GenerationID) error {
	if len(id) == 0 || len(id) > maxGenerationIDLen || !generationIDPattern.MatchString(string(id)) {
		return fmt.Errorf("%w: %q", ErrInvalidGenerationID, id)
	}
	return nil
}

// FileGenerationStore is a directory-backed GenerationStore.
//
// Layout:
//
//	<root>/state.json
//	<root>/generations/<id>/model.conf
//	<root>/generations/<id>/policy.csv
//
// Every document is written to a temporary file in the same directory,
// flushed and renamed into place, which makes each replacement atomic on
// local file systems.
type FileGenerationStore struct {
	root string
}

// NewFileGenerationStore creates a store rooted at root. The directory is
// created lazily on the first write.
func NewFileGenerationStore(root string) *FileGenerationStore {
	return &FileGenerationStore{root: root}
}

func (s *FileGenerationStore) generationPath(id GenerationID) (string, error) {
	if err := validateGenerationID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.root, generationDirName, string(id)), nil
}

// SaveGeneration implements GenerationStore.
func (s *FileGenerationStore) SaveGeneration(id GenerationID, modelText, policyText string) error {
	dir, err := s.generationPath(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, generationDirPerm); err != nil {
		return fmt.Errorf("%w: create generation directory: %v", ErrPersistenceFailed, err)
	}
	if err := atomicWriteFile(filepath.Join(dir, modelFileName), []byte(modelText)); err != nil {
		return fmt.Errorf("%w: model text: %v", ErrPersistenceFailed, err)
	}
	if err := atomicWriteFile(filepath.Join(dir, policyFileName), []byte(policyText)); err != nil {
		return fmt.Errorf("%w: policy text: %v", ErrPersistenceFailed, err)
	}
	return nil
}

// LoadGeneration implements GenerationStore.
func (s *FileGenerationStore) LoadGeneration(id GenerationID) (string, string, error) {
	dir, err := s.generationPath(id)
	if err != nil {
		return "", "", err
	}
	modelText, err := readAtomicFile(filepath.Join(dir, modelFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("%w: %s", ErrGenerationNotFound, id)
		}
		return "", "", fmt.Errorf("%w: model text: %v", ErrPersistenceFailed, err)
	}
	policyText, err := readAtomicFile(filepath.Join(dir, policyFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("%w: %s", ErrGenerationNotFound, id)
		}
		return "", "", fmt.Errorf("%w: policy text: %v", ErrPersistenceFailed, err)
	}
	return modelText, policyText, nil
}

// ListGenerations implements GenerationStore.
func (s *FileGenerationStore) ListGenerations() ([]GenerationID, error) {
	dir := filepath.Join(s.root, generationDirName)
	entries, err := listDirectoryNames(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []GenerationID{}, nil
		}
		return nil, err
	}
	ids := make([]GenerationID, 0, len(entries))
	for _, entry := range entries {
		id := GenerationID(entry)
		if validateGenerationID(id) == nil {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// DeleteGeneration implements GenerationStore.
func (s *FileGenerationStore) DeleteGeneration(id GenerationID) error {
	dir, err := s.generationPath(id)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrGenerationNotFound, id)
		}
		return fmt.Errorf("%w: %v", ErrPersistenceFailed, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("%w: %v", ErrPersistenceFailed, err)
	}
	return nil
}

// SaveState implements GenerationStore.
func (s *FileGenerationStore) SaveState(state *CutoverState) error {
	if state == nil {
		return fmt.Errorf("%w: state is nil", ErrPersistenceFailed)
	}
	if err := os.MkdirAll(s.root, generationDirPerm); err != nil {
		return fmt.Errorf("%w: create store directory: %v", ErrPersistenceFailed, err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode state: %v", ErrPersistenceFailed, err)
	}
	if err := atomicWriteFile(filepath.Join(s.root, stateFileName), data); err != nil {
		return fmt.Errorf("%w: state document: %v", ErrPersistenceFailed, err)
	}
	return nil
}

// LoadState implements GenerationStore.
func (s *FileGenerationStore) LoadState() (*CutoverState, error) {
	data, err := readAtomicFile(filepath.Join(s.root, stateFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrStateNotFound
		}
		return nil, fmt.Errorf("%w: state document: %v", ErrPersistenceFailed, err)
	}
	state := &CutoverState{}
	if err := json.Unmarshal([]byte(data), state); err != nil {
		return nil, fmt.Errorf("%w: decode state: %v", ErrInvalidStoredGeneration, err)
	}
	if state.Active == "" {
		return nil, fmt.Errorf("%w: state has no active generation", ErrInvalidStoredGeneration)
	}
	return state, nil
}

// atomicWriteFile replaces path with a flushed temporary file so concurrent
// readers never see a torn document.
func atomicWriteFile(path string, data []byte) error {
	tmp := path + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 10)
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, generationFilePerm)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if syncErr := file.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func readAtomicFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, file); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func listDirectoryNames(path string) ([]string, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.Readdirnames(-1)
}
