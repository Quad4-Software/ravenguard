// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ml_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/ml"
	"github.com/Quad4-Software/ravenguard/internal/ml/adapt"
)

func TestDefaultModelPredict(t *testing.T) {
	m := ml.DefaultModel()
	var feats [ml.FeatureDim]float32
	feats[ml.FBias] = 1
	pClean := m.Predict(feats[:])
	feats[ml.FSemanticSQLi] = 0.9
	pAtk := m.Predict(feats[:])
	if pAtk <= pClean {
		t.Fatalf("attack prob %v should exceed clean %v", pAtk, pClean)
	}
}

func TestModelRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.bin")
	m := ml.DefaultModel()
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := ml.LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Hash != m.Hash {
		t.Fatalf("hash %s vs %s", loaded.Hash, m.Hash)
	}
}

func TestScorerShadowNoBlock(t *testing.T) {
	s := ml.New(config.MLConfig{
		Enabled: true, Mode: "shadow", ChallengeProb: 0.5, BlockProb: 0.9,
		ConfidenceMin: 0.5, MaxPoints: 60,
	}, ml.DefaultModel())
	s.SetAttestOK(true)
	r := httptest.NewRequest(http.MethodGet, "/x?q=1'+union+select+1", nil)
	res := s.Evaluate(r, ml.Input{SemanticSQLi: 90})
	if res.ShouldBlock {
		t.Fatalf("shadow must not block: %+v", res)
	}
}

func TestScorerConfidenceCap(t *testing.T) {
	s := ml.New(config.MLConfig{
		Enabled: true, Mode: "block", ChallengeProb: 0.5, BlockProb: 0.6,
		ConfidenceMin: 0.99, MaxPoints: 60,
	}, ml.DefaultModel())
	s.SetAttestOK(true)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	res := s.Evaluate(r, ml.Input{SemanticSQLi: 40})
	if res.ShouldBlock {
		t.Fatalf("low confidence must not hard-block: %+v", res)
	}
}

func TestFeatureStable(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/x?a=1", nil)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	var a, b [ml.FeatureDim]float32
	ml.ExtractInto(a[:], r, ml.Input{SemanticSQLi: 10})
	ml.ExtractInto(b[:], r, ml.Input{SemanticSQLi: 10})
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("feat %d %v vs %v", i, a[i], b[i])
		}
	}
}

func TestAdaptTrain(t *testing.T) {
	var samples []adapt.LabeledSample
	for range 10 {
		var f [ml.FeatureDim]float32
		f[ml.FBias] = 1
		f[ml.FSemanticSQLi] = 0.9
		samples = append(samples, adapt.LabeledSample{Features: f, Label: 1})
	}
	for range 5 {
		var f [ml.FeatureDim]float32
		f[ml.FBias] = 1
		samples = append(samples, adapt.LabeledSample{Features: f, Label: 0})
	}
	m, err := adapt.TrainOverlay(samples, 3, 20, 0.1)
	if err != nil {
		t.Fatal(err)
	}
	if m.Hash == "" {
		t.Fatal("missing hash")
	}
}

func TestAttestation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.json")
	m := ml.DefaultModel()
	a := ml.Attestation{ModelHash: m.Hash, FPR: 0.0001, TPR: 0.95, Passed: true}
	if err := ml.WriteAttestation(path, a); err != nil {
		t.Fatal(err)
	}
	if !ml.AttestOKForModel(path, m.Hash, 0.001) {
		t.Fatal("expected ok")
	}
	if ml.AttestOKForModel(path, "nope", 0.001) {
		t.Fatal("hash mismatch")
	}
}

func FuzzFeatureExtract(f *testing.F) {
	f.Add("GET", "/x", "a=1")
	f.Fuzz(func(t *testing.T, method, path, query string) {
		r := httptest.NewRequest(method, "http://x"+path+"?"+query, nil)
		if r == nil {
			return
		}
		var feats [ml.FeatureDim]float32
		ml.ExtractInto(feats[:], r, ml.Input{})
	})
}

func BenchmarkMLInfer(b *testing.B) {
	s := ml.New(config.MLConfig{Enabled: true, Mode: "shadow", MaxPoints: 60, ConfidenceMin: 0.5, ChallengeProb: 0.75, BlockProb: 0.95}, ml.DefaultModel())
	r := httptest.NewRequest(http.MethodGet, "/products", nil)
	b.ReportAllocs()
	for b.Loop() {
		_ = s.Evaluate(r, ml.Input{})
	}
}
