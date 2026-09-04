// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package agentprotocol

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const desiredFile = "desired_state.json"

func DesiredStatePath(dataDir string) string {
	return filepath.Join(dataDir, desiredFile)
}

func SaveDesiredState(dataDir string, state DesiredState) error {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := DesiredStatePath(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, DesiredStatePath(dataDir))
}

func LoadDesiredState(dataDir string) (DesiredState, error) {
	raw, err := os.ReadFile(DesiredStatePath(dataDir))
	if err != nil {
		return DesiredState{}, err
	}
	var state DesiredState
	if err := json.Unmarshal(raw, &state); err != nil {
		return DesiredState{}, err
	}
	return state, nil
}

func LoadDesiredStateOptional(dataDir string) (DesiredState, bool, error) {
	state, err := LoadDesiredState(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return DesiredState{}, false, nil
		}
		return DesiredState{}, false, fmt.Errorf("load desired state: %w", err)
	}
	return state, true, nil
}
