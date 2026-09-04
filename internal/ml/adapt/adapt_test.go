// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package adapt_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/ml"
	"github.com/Quad4-Software/ravenguard/internal/ml/adapt"
)

func TestShouldRollback(t *testing.T) {
	if !adapt.ShouldRollback(0.01, 0.02, 0.001) {
		t.Fatal("expected rollback when FPR rises past margin")
	}
	if adapt.ShouldRollback(0.01, 0.0102, 0.001) {
		t.Fatal("should not rollback within margin")
	}
	if !adapt.ShouldRollback(0.01, 0.011, 0) {
		t.Fatal("default margin should still roll back clear rise")
	}
}

func TestTrainOverlay(t *testing.T) {
	samples := make([]adapt.LabeledSample, 0, 10)
	for i := 0; i < 5; i++ {
		var f [ml.FeatureDim]float32
		f[0] = 1
		samples = append(samples, adapt.LabeledSample{Features: f, Label: 1})
	}
	for i := 0; i < 5; i++ {
		var f [ml.FeatureDim]float32
		f[1] = 1
		samples = append(samples, adapt.LabeledSample{Features: f, Label: 0})
	}
	if _, err := adapt.TrainOverlay(samples[:4], 2, 5, 0.1); err == nil {
		t.Fatal("expected error for too few samples")
	}
	if _, err := adapt.TrainOverlay(samples, 20, 5, 0.1); err == nil {
		t.Fatal("expected error for too few FP labels")
	}
	m, err := adapt.TrainOverlay(samples, 2, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || m.Hash == "" {
		t.Fatal("expected trained model with hash")
	}
}
