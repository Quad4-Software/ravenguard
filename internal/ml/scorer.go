// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

// Package ml provides lightweight request scoring with a pure-Go linear model.
package ml

import (
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/semantic"
)

// FeatureDim is the fixed feature vector length.
const FeatureDim = 24

const (
	FMethodPOST = iota
	FMethodWrite
	FPathLen
	FQueryLen
	FQueryEntropy
	FMissingUA
	FHasAccept
	FHasAcceptLang
	FHasSecFetch
	FBodyLenNorm
	FCTJSON
	FCTForm
	FSemanticSQLi
	FSemanticXSS
	FSemanticCMD
	FSemanticPath
	FCorazaHit
	FCorazaScoreNorm
	FBehaviorBurst
	FJA4Present
	FBotScoreLow
	FOddMethod
	FProbeHint
	FBias
)

// Input carries optional side-channel features for scoring.
type Input struct {
	Body          []byte
	SemanticSQLi  int
	SemanticXSS   int
	SemanticCMD   int
	SemanticPath  int
	CorazaMatched bool
	CorazaScore   int
	BehaviorBurst float64
	BotScoreLow   bool
	JA4Present    bool
}

// Result is an ML decision.
type Result struct {
	Prob        float64
	Points      int
	Confidence  float64
	ShouldBlock bool
	NeedChal    bool
	ShadowOnly  bool
	ModelHash   string
	Features    [FeatureDim]float32
}

// Scorer runs feature extract + linear model + optional adapt overlay.
type Scorer struct {
	mu       sync.RWMutex
	enabled  bool
	mode     string
	cfg      config.MLConfig
	model    atomic.Pointer[Model]
	adapt    atomic.Pointer[Model]
	attestOK atomic.Bool
	shadow   *ShadowLog
	featPool sync.Pool
}

// New creates a scorer. model may be nil (scores stay 0).
func New(cfg config.MLConfig, model *Model) *Scorer {
	s := &Scorer{
		shadow: NewShadowLog(4096),
		featPool: sync.Pool{New: func() any {
			a := make([]float32, FeatureDim)
			return &a
		}},
	}
	s.apply(cfg)
	if model != nil {
		s.model.Store(model)
	}
	return s
}

func (s *Scorer) apply(cfg config.MLConfig) {
	s.enabled = cfg.Enabled && !strings.EqualFold(cfg.Mode, "off")
	s.mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if s.mode == "" {
		s.mode = "shadow"
	}
	s.cfg = cfg
}

// Enabled reports whether scoring is active.
func (s *Scorer) Enabled() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// Mode returns the live mode.
func (s *Scorer) Mode() string {
	if s == nil {
		return "off"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

// UpdateLive toggles enable/mode.
func (s *Scorer) UpdateLive(enabled bool, mode string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if mode != "" {
		s.mode = strings.ToLower(strings.TrimSpace(mode))
	}
	s.enabled = enabled && s.mode != "off"
	s.cfg.Enabled = s.enabled
	s.cfg.Mode = s.mode
}

// SetModel swaps the base model.
func (s *Scorer) SetModel(m *Model) {
	if s == nil {
		return
	}
	s.model.Store(m)
}

// SetAdapt swaps the adaptation overlay (may be nil).
func (s *Scorer) SetAdapt(m *Model) {
	if s == nil {
		return
	}
	s.adapt.Store(m)
}

// SetAttestOK records whether eval attestation passed for enforce modes.
func (s *Scorer) SetAttestOK(ok bool) {
	if s == nil {
		return
	}
	s.attestOK.Store(ok)
}

// AttestOK reports whether enforce is allowed.
func (s *Scorer) AttestOK() bool {
	if s == nil {
		return false
	}
	return s.attestOK.Load()
}

// Shadow returns the async shadow logger.
func (s *Scorer) Shadow() *ShadowLog {
	if s == nil {
		return nil
	}
	return s.shadow
}

// Evaluate scores the request.
func (s *Scorer) Evaluate(r *http.Request, in Input) Result {
	if !s.Enabled() || r == nil {
		return Result{}
	}
	s.mu.RLock()
	cfg := s.cfg
	mode := s.mode
	s.mu.RUnlock()

	m := s.model.Load()
	if m == nil {
		return Result{}
	}

	fp := s.featPool.Get().(*[]float32)
	feats := (*fp)[:FeatureDim]
	for i := range feats {
		feats[i] = 0
	}
	ExtractInto(feats, r, in)
	var out [FeatureDim]float32
	copy(out[:], feats)
	s.featPool.Put(fp)

	prob := m.Predict(out[:])
	if ad := s.adapt.Load(); ad != nil {
		// Blend overlay: sigmoid(base_logit + adapt_logit)
		prob = combineProb(prob, ad.Predict(out[:]))
	}
	conf := math.Abs(prob-0.5) * 2
	points := min(int(prob*float64(cfg.MaxPoints)), cfg.MaxPoints)

	res := Result{
		Prob:       prob,
		Points:     points,
		Confidence: conf,
		ModelHash:  m.Hash,
		Features:   out,
		ShadowOnly: mode == "shadow",
	}

	canEnforce := mode == "challenge" || mode == "block"
	if canEnforce && !s.attestOK.Load() {
		res.ShadowOnly = true
		canEnforce = false
	}
	if conf < cfg.ConfidenceMin {
		// Cap: ML alone cannot hard-block without confidence.
		if mode == "block" {
			res.NeedChal = prob >= cfg.ChallengeProb
		}
		return res
	}
	if prob >= cfg.ChallengeProb {
		res.NeedChal = true
	}
	if canEnforce && mode == "block" && prob >= cfg.BlockProb && conf >= cfg.ConfidenceMin {
		res.ShouldBlock = true
	}
	if mode == "challenge" && res.NeedChal {
		res.ShouldBlock = false
	}
	if mode == "shadow" {
		res.ShouldBlock = false
	}
	return res
}

func combineProb(a, b float64) float64 {
	// average in logit space lightly toward adapt
	la := math.Log((a + 1e-6) / (1 - a + 1e-6))
	lb := math.Log((b + 1e-6) / (1 - b + 1e-6))
	l := 0.7*la + 0.3*lb
	return 1 / (1 + math.Exp(-l))
}

// ExtractInto fills a preallocated feature slice.
func ExtractInto(dst []float32, r *http.Request, in Input) {
	if len(dst) < FeatureDim || r == nil {
		return
	}
	method := r.Method
	switch method {
	case http.MethodPost:
		dst[FMethodPOST] = 1
	case http.MethodPut, http.MethodPatch, http.MethodDelete:
		dst[FMethodWrite] = 1
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		dst[FOddMethod] = 1
	}
	path := ""
	q := ""
	if r.URL != nil {
		path = r.URL.Path
		q = r.URL.RawQuery
	}
	dst[FPathLen] = float32(math.Min(float64(len(path))/200.0, 1))
	dst[FQueryLen] = float32(math.Min(float64(len(q))/200.0, 1))
	dst[FQueryEntropy] = float32(entropyNorm([]byte(q)))
	if r.Header.Get("User-Agent") == "" {
		dst[FMissingUA] = 1
	}
	if r.Header.Get("Accept") != "" {
		dst[FHasAccept] = 1
	}
	if r.Header.Get("Accept-Language") != "" {
		dst[FHasAcceptLang] = 1
	}
	if r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Sec-Fetch-Mode") != "" {
		dst[FHasSecFetch] = 1
	}
	dst[FBodyLenNorm] = float32(math.Min(float64(len(in.Body))/float64(64<<10), 1))
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "json") {
		dst[FCTJSON] = 1
	}
	if strings.Contains(ct, "form") {
		dst[FCTForm] = 1
	}
	dst[FSemanticSQLi] = float32(in.SemanticSQLi) / 100
	dst[FSemanticXSS] = float32(in.SemanticXSS) / 100
	dst[FSemanticCMD] = float32(in.SemanticCMD) / 100
	dst[FSemanticPath] = float32(in.SemanticPath) / 100
	if in.CorazaMatched {
		dst[FCorazaHit] = 1
	}
	dst[FCorazaScoreNorm] = float32(math.Min(float64(in.CorazaScore)/100.0, 1))
	dst[FBehaviorBurst] = float32(math.Min(in.BehaviorBurst, 1))
	if in.JA4Present {
		dst[FJA4Present] = 1
	}
	if in.BotScoreLow {
		dst[FBotScoreLow] = 1
	}
	if looksProbe(path) {
		dst[FProbeHint] = 1
	}
	dst[FBias] = 1
}

func looksProbe(path string) bool {
	p := strings.ToLower(path)
	for _, s := range []string{"/.env", "/wp-admin", "/phpmyadmin", "/.git", "/actuator", "/vendor/phpunit"} {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

func entropyNorm(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return math.Min(h/8.0, 1)
}

// EnrichFromSemantic fills semantic scores using an engine.
func EnrichFromSemantic(in *Input, eng *semantic.Engine, r *http.Request, body []byte) {
	if in == nil || eng == nil {
		return
	}
	in.Body = body
	in.SemanticSQLi, in.SemanticXSS, in.SemanticCMD, in.SemanticPath = eng.FamilyScores(r, body)
}
