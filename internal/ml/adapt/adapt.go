// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package adapt

import (
	"fmt"
	"math"

	"github.com/Quad4-Software/ravenguard/internal/ml"
)

// LabeledSample is a feature row with binary label (1=attack, 0=benign/FP).
type LabeledSample struct {
	Features [ml.FeatureDim]float32
	Label    float64
}

// TrainOverlay fits a small logistic overlay from labeled samples.
// Requires minFP false-positive labels (label=0) to reduce accidental overfit.
func TrainOverlay(samples []LabeledSample, minFP int, epochs int, lr float64) (*ml.Model, error) {
	if len(samples) < 8 {
		return nil, fmt.Errorf("adapt: need at least 8 samples")
	}
	fps := 0
	for _, s := range samples {
		if s.Label < 0.5 {
			fps++
		}
	}
	if fps < minFP {
		return nil, fmt.Errorf("adapt: need at least %d FP labels, have %d", minFP, fps)
	}
	if epochs <= 0 {
		epochs = 40
	}
	if lr <= 0 {
		lr = 0.05
	}
	m := &ml.Model{}
	for epoch := 0; epoch < epochs; epoch++ {
		for _, s := range samples {
			p := m.Predict(s.Features[:])
			err := p - s.Label
			for i := range ml.FeatureDim {
				m.Weights[i] -= float32(lr * err * float64(s.Features[i]))
			}
			m.Bias -= float32(lr * err)
		}
	}
	for i := range ml.FeatureDim {
		m.Weights[i] = float32(math.Max(-5, math.Min(5, float64(m.Weights[i]))))
	}
	m.Bias = float32(math.Max(-5, math.Min(5, float64(m.Bias))))
	m.Rehash()
	return m, nil
}

// ShouldRollback reports if new FPR is worse than old by margin.
func ShouldRollback(oldFPR, newFPR, margin float64) bool {
	if margin <= 0 {
		margin = 0.0005
	}
	return newFPR > oldFPR+margin
}
