// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Attestation is the eval proof required for enforce modes.
type Attestation struct {
	ModelHash   string    `json:"model_hash"`
	FPR         float64   `json:"fpr"`
	TPR         float64   `json:"tpr"`
	P99Micros   int64     `json:"p99_micros"`
	AllocsPerOp int64     `json:"allocs_per_op"`
	Passed      bool      `json:"passed"`
	CreatedAt   time.Time `json:"created_at"`
	Marker      string    `json:"marker"`
}

const attestMarker = "RG_ML_EVAL_PASS"

// WriteAttestation writes JSON attestation to path.
func WriteAttestation(path string, a Attestation) error {
	a.Marker = attestMarker
	a.CreatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// LoadAttestation reads and validates an attestation file.
func LoadAttestation(path string) (Attestation, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Attestation{}, err
	}
	var a Attestation
	if err := json.Unmarshal(b, &a); err != nil {
		return Attestation{}, err
	}
	if a.Marker != attestMarker || !a.Passed {
		return a, fmt.Errorf("ml: attestation not passed")
	}
	return a, nil
}

// AttestOKForModel checks path attestation matches model hash and FPR gate.
func AttestOKForModel(path, modelHash string, fprGate float64) bool {
	a, err := LoadAttestation(path)
	if err != nil {
		return false
	}
	if a.ModelHash != modelHash {
		return false
	}
	if fprGate > 0 && a.FPR > fprGate {
		return false
	}
	return a.Passed
}
