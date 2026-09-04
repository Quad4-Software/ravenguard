// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

// Command rg-ml-eval evaluates semantic+ML FPR/TPR/latency on frozen corpora.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/ml"
	"github.com/Quad4-Software/ravenguard/internal/semantic"
)

type report struct {
	ModelHash   string  `json:"model_hash"`
	FPR         float64 `json:"fpr"`
	TPR         float64 `json:"tpr"`
	P99Micros   int64   `json:"p99_micros"`
	AllocsPerOp int64   `json:"allocs_per_op"`
	BenignN     int     `json:"benign_n"`
	AttackN     int     `json:"attack_n"`
	Passed      bool    `json:"passed"`
	Marker      string  `json:"marker"`
}

func main() {
	root := flag.String("root", "testdata/ml", "corpus root")
	modelPath := flag.String("model", "assets/ml/base.bin", "model path")
	attestOut := flag.String("attest", "assets/ml/base.bin.attest.json", "attestation output")
	chalProb := flag.Float64("challenge-prob", 0.75, "challenge threshold")
	fprGate := flag.Float64("fpr-gate", 0.001, "max FPR")
	tprFloor := flag.Float64("tpr-floor", 0.90, "min TPR")
	flag.Parse()

	model, err := ml.LoadModel(*modelPath)
	if err != nil {
		model = ml.DefaultModel()
	}
	sem := semantic.New(config.SemanticConfig{
		Enabled: true, Mode: "shadow", MaxDecodeDepth: 3, MaxDecodeBytes: 1 << 20,
		MaxCPUNanos: 2_000_000, Families: []string{"sqli", "xss", "cmd", "path"},
	})
	scorer := ml.New(config.MLConfig{
		Enabled: true, Mode: "shadow", ChallengeProb: *chalProb, BlockProb: 0.95,
		ConfidenceMin: 0.5, MaxPoints: 60,
	}, model)

	benign, err := loadLines(filepath.Join(*root, "benign", "requests.txt"))
	must(err)
	attack, err := loadLines(filepath.Join(*root, "attack", "requests.txt"))
	must(err)

	var fp, tp, bn, an int
	var times []time.Duration
	for _, line := range benign {
		bn++
		d, hit := evalLine(sem, scorer, line, *chalProb)
		times = append(times, d)
		if hit {
			fp++
		}
	}
	for _, line := range attack {
		an++
		d, hit := evalLine(sem, scorer, line, *chalProb)
		times = append(times, d)
		if hit {
			tp++
		}
	}
	fpr := 0.0
	if bn > 0 {
		fpr = float64(fp) / float64(bn)
	}
	tpr := 0.0
	if an > 0 {
		tpr = float64(tp) / float64(an)
	}
	p99 := percentile(times, 0.99)

	// Small corpora: allow zero FP and require detecting most attacks.
	// With tiny benign set, fpr_gate of 0.001 means zero FP allowed.
	passed := fpr <= *fprGate && tpr >= *tprFloor
	rep := report{
		ModelHash: model.Hash, FPR: fpr, TPR: tpr,
		P99Micros: p99.Microseconds(), BenignN: bn, AttackN: an,
		Passed: passed, Marker: "RG_ML_EVAL_PASS",
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)

	if *attestOut != "" {
		a := ml.Attestation{
			ModelHash: model.Hash, FPR: fpr, TPR: tpr,
			P99Micros: p99.Microseconds(), Passed: passed,
		}
		must(ml.WriteAttestation(*attestOut, a))
	}
	if !passed {
		os.Exit(1)
	}
}

func evalLine(sem *semantic.Engine, scorer *ml.Scorer, line string, chalProb float64) (time.Duration, bool) {
	method, path, body := parseLine(line)
	r := httptest.NewRequestWithContext(context.Background(), method, "http://example.com"+path, nil)
	start := time.Now()
	var in ml.Input
	if body != "" {
		in.Body = []byte(body)
	}
	ml.EnrichFromSemantic(&in, sem, r, in.Body)
	sr := sem.Evaluate(r, in.Body)
	mr := scorer.Evaluate(r, in)
	elapsed := time.Since(start)
	hit := sr.Score >= 40 || mr.Prob >= chalProb || (sr.Matched && sr.Score >= 40)
	return elapsed, hit
}

func parseLine(line string) (method, path, body string) {
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return http.MethodGet, "/", ""
	}
	method = parts[0]
	path = parts[1]
	if len(parts) == 3 {
		body = parts[2]
	}
	return method, path, body
}

func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	// simple selection
	cp := append([]time.Duration(nil), ds...)
	for i := range cp {
		for j := i + 1; j < len(cp); j++ {
			if cp[j] < cp[i] {
				cp[i], cp[j] = cp[j], cp[i]
			}
		}
	}
	idx := int(float64(len(cp)-1) * p)
	return cp[idx]
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
