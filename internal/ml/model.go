// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ml

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

const modelMagic = "RGML"
const modelVersion = 1

// Model is a pure-Go logistic regression over FeatureDim inputs.
type Model struct {
	Weights [FeatureDim]float32
	Bias    float32
	Hash    string
}

// DefaultModel returns a hand-tuned base model favoring semantic signals.
func DefaultModel() *Model {
	m := &Model{}
	m.Weights[FSemanticSQLi] = 3.5
	m.Weights[FSemanticXSS] = 3.2
	m.Weights[FSemanticCMD] = 3.0
	m.Weights[FSemanticPath] = 2.5
	m.Weights[FCorazaHit] = 2.0
	m.Weights[FCorazaScoreNorm] = 1.5
	m.Weights[FProbeHint] = 1.8
	m.Weights[FMissingUA] = 0.8
	m.Weights[FBotScoreLow] = 1.2
	m.Weights[FOddMethod] = 0.6
	m.Weights[FBehaviorBurst] = 0.9
	m.Weights[FQueryEntropy] = 0.4
	m.Weights[FBias] = -2.5
	m.Bias = -2.5
	m.Hash = m.computeHash()
	return m
}
func (m *Model) Predict(feats []float32) float64 {
	if m == nil || len(feats) < FeatureDim {
		return 0
	}
	var z float64
	for i := range FeatureDim {
		z += float64(m.Weights[i]) * float64(feats[i])
	}
	z += float64(m.Bias)
	return 1 / (1 + math.Exp(-z))
}

func (m *Model) computeHash() string {
	h := sha256.New()
	var buf [4]byte
	for i := range FeatureDim {
		binary.LittleEndian.PutUint32(buf[:], math.Float32bits(m.Weights[i]))
		_, _ = h.Write(buf[:])
	}
	binary.LittleEndian.PutUint32(buf[:], math.Float32bits(m.Bias))
	_, _ = h.Write(buf[:])
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Rehash updates Hash from weights.
func (m *Model) Rehash() {
	if m != nil {
		m.Hash = m.computeHash()
	}
}

// Save writes the model to path.
func (m *Model) Save(path string) error {
	if m == nil {
		return fmt.Errorf("ml: nil model")
	}
	if m.Hash == "" {
		m.Hash = m.computeHash()
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(modelMagic); err != nil {
		return err
	}
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], modelVersion)
	binary.LittleEndian.PutUint32(hdr[4:8], FeatureDim)
	if _, err := f.Write(hdr[:]); err != nil {
		return err
	}
	for i := range FeatureDim {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], math.Float32bits(m.Weights[i]))
		if _, err := f.Write(buf[:]); err != nil {
			return err
		}
	}
	var bias [4]byte
	binary.LittleEndian.PutUint32(bias[:], math.Float32bits(m.Bias))
	if _, err := f.Write(bias[:]); err != nil {
		return err
	}
	return nil
}

// LoadModel reads a model from path.
func LoadModel(path string) (*Model, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseModel(b)
}

// ParseModel parses model bytes.
func ParseModel(b []byte) (*Model, error) {
	need := 4 + 8 + FeatureDim*4 + 4
	if len(b) < need {
		return nil, fmt.Errorf("ml: model too short")
	}
	if string(b[0:4]) != modelMagic {
		return nil, fmt.Errorf("ml: bad magic")
	}
	ver := binary.LittleEndian.Uint32(b[4:8])
	dim := binary.LittleEndian.Uint32(b[8:12])
	if ver != modelVersion || int(dim) != FeatureDim {
		return nil, fmt.Errorf("ml: unsupported version/dim %d/%d", ver, dim)
	}
	m := &Model{}
	off := 12
	for i := range FeatureDim {
		m.Weights[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[off : off+4]))
		off += 4
	}
	m.Bias = math.Float32frombits(binary.LittleEndian.Uint32(b[off : off+4]))
	m.Hash = m.computeHash()
	return m, nil
}
