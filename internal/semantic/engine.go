// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

// Package semantic provides bounded payload decode and intent analysis.
package semantic

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/config"
)

// Result is the outcome of semantic evaluation.
type Result struct {
	Matched     bool
	ShouldBlock bool
	NeedChal    bool
	Family      string
	Score       int
	Confidence  float64
	Evidence    string
	Aborted     bool
	Error       string
}

// Engine runs decode + family analyzers under hard budgets.
type Engine struct {
	mu       sync.RWMutex
	enabled  bool
	mode     string
	cfg      config.SemanticConfig
	families map[string]bool
}

// New builds an engine from config.
func New(cfg config.SemanticConfig) *Engine {
	e := &Engine{}
	e.apply(cfg)
	return e
}

func (e *Engine) apply(cfg config.SemanticConfig) {
	e.enabled = cfg.Enabled
	e.mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if e.mode == "" {
		e.mode = "shadow"
	}
	e.cfg = cfg
	fam := make(map[string]bool, len(cfg.Families))
	for _, f := range cfg.Families {
		fam[strings.ToLower(strings.TrimSpace(f))] = true
	}
	if len(fam) == 0 {
		fam["sqli"] = true
		fam["xss"] = true
		fam["cmd"] = true
		fam["path"] = true
	}
	e.families = fam
}

// Enabled reports whether evaluation is active.
func (e *Engine) Enabled() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// Mode returns shadow, challenge, or block.
func (e *Engine) Mode() string {
	if e == nil {
		return "shadow"
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mode
}

// UpdateLive toggles enable/mode without reloading budgets.
func (e *Engine) UpdateLive(enabled bool, mode string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = enabled
	if mode != "" {
		e.mode = strings.ToLower(strings.TrimSpace(mode))
	}
}

// Evaluate inspects path, query, and optional body bytes.
// body may be nil when no body was captured.
func (e *Engine) Evaluate(r *http.Request, body []byte) Result {
	if !e.Enabled() || r == nil {
		return Result{}
	}
	e.mu.RLock()
	cfg := e.cfg
	mode := e.mode
	fams := e.families
	e.mu.RUnlock()

	path := ""
	rawQuery := ""
	if r.URL != nil {
		path = r.URL.Path
		rawQuery = r.URL.RawQuery
	}
	for _, p := range cfg.SkipPathPrefixes {
		if pathSkipped(path, p) {
			return Result{}
		}
	}

	deadline := time.Now().Add(time.Duration(cfg.MaxCPUNanos) * time.Nanosecond)
	budget := &Budget{
		Deadline: deadline,
		MaxBytes: cfg.MaxDecodeBytes,
		MaxDepth: cfg.MaxDecodeDepth,
	}

	inputs := make([][]byte, 0, 4)
	if path != "" {
		inputs = append(inputs, []byte(path))
	}
	if rawQuery != "" {
		inputs = append(inputs, []byte(rawQuery))
	}
	if len(body) > 0 && !skipBodyCT(r.Header.Get("Content-Type")) {
		max := int(cfg.MaxBodyInspect)
		if max <= 0 {
			max = 64 << 10
		}
		if len(body) > max {
			body = body[:max]
		}
		inputs = append(inputs, body)
	}

	best := Result{}
	for _, in := range inputs {
		if budget.Expired() {
			return abortResult(mode, cfg.StrictBudget, "cpu budget exceeded")
		}
		if !cheapPrefilter(in) {
			continue
		}
		decoded, err := DecodeChain(in, budget)
		if err != nil {
			if err == ErrBudget {
				return abortResult(mode, cfg.StrictBudget, "decode budget exceeded")
			}
			continue
		}
		for _, candidate := range decoded {
			if budget.Expired() {
				return abortResult(mode, cfg.StrictBudget, "cpu budget exceeded")
			}
			res := analyzeAll(candidate, fams)
			if res.Score > best.Score {
				best = res
			}
		}
	}

	if best.Score <= 0 {
		return Result{}
	}
	best.Matched = true
	best.NeedChal = best.Score >= 50
	best.ShouldBlock = best.Score >= 80 && (mode == "block")
	if mode == "challenge" && best.NeedChal {
		best.ShouldBlock = false
	}
	if mode == "shadow" {
		best.ShouldBlock = false
	}
	return best
}

func abortResult(mode string, strict bool, msg string) Result {
	block := strict && mode == "block"
	return Result{
		Matched:     strict,
		ShouldBlock: block,
		Aborted:     true,
		Error:       msg,
		Score:       0,
	}
}

func analyzeAll(b []byte, fams map[string]bool) Result {
	best := Result{}
	if fams["sqli"] {
		if r := scoreSQLi(b); r.Score > best.Score {
			best = r
		}
	}
	if fams["xss"] {
		if r := scoreXSS(b); r.Score > best.Score {
			best = r
		}
	}
	if fams["cmd"] {
		if r := scoreCMD(b); r.Score > best.Score {
			best = r
		}
	}
	if fams["path"] {
		if r := scorePath(b); r.Score > best.Score {
			best = r
		}
	}
	return best
}

func cheapPrefilter(b []byte) bool {
	for _, c := range b {
		switch c {
		case 0, '%', '\'', '"', '<', '>', ';', '|', '`', '$', '(', ')', '{', '}', '\\', '/':
			return true
		}
	}
	// look for ../ without scanning twice
	if len(b) >= 3 {
		for i := 0; i+2 < len(b); i++ {
			if b[i] == '.' && b[i+1] == '.' && (b[i+2] == '/' || b[i+2] == '\\') {
				return true
			}
		}
	}
	return false
}

func skipBodyCT(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") {
		return true
	}
	if strings.Contains(ct, "octet-stream") {
		return true
	}
	return false
}

func pathSkipped(path, prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return false
	}
	if path == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return strings.HasPrefix(path, prefix+"/")
}

// FamilyScores returns per-family scores for ML features (ignores mode).
func (e *Engine) FamilyScores(r *http.Request, body []byte) (sqli, xss, cmdi, pathScore int) {
	if e == nil || r == nil {
		return 0, 0, 0, 0
	}
	e.mu.RLock()
	cfg := e.cfg
	fams := e.families
	e.mu.RUnlock()

	path := ""
	rawQuery := ""
	if r.URL != nil {
		path = r.URL.Path
		rawQuery = r.URL.RawQuery
	}
	for _, p := range cfg.SkipPathPrefixes {
		if pathSkipped(path, p) {
			return 0, 0, 0, 0
		}
	}
	deadline := time.Now().Add(time.Duration(cfg.MaxCPUNanos) * time.Nanosecond)
	budget := &Budget{Deadline: deadline, MaxBytes: cfg.MaxDecodeBytes, MaxDepth: cfg.MaxDecodeDepth}
	inputs := make([][]byte, 0, 4)
	if path != "" {
		inputs = append(inputs, []byte(path))
	}
	if rawQuery != "" {
		inputs = append(inputs, []byte(rawQuery))
	}
	if len(body) > 0 && !skipBodyCT(r.Header.Get("Content-Type")) {
		max := int(cfg.MaxBodyInspect)
		if max <= 0 {
			max = 64 << 10
		}
		if len(body) > max {
			body = body[:max]
		}
		inputs = append(inputs, body)
	}
	for _, in := range inputs {
		if budget.Expired() || !cheapPrefilter(in) {
			continue
		}
		decoded, err := DecodeChain(in, budget)
		if err != nil {
			continue
		}
		for _, candidate := range decoded {
			if fams["sqli"] {
				if r := scoreSQLi(candidate); r.Score > sqli {
					sqli = r.Score
				}
			}
			if fams["xss"] {
				if r := scoreXSS(candidate); r.Score > xss {
					xss = r.Score
				}
			}
			if fams["cmd"] {
				if r := scoreCMD(candidate); r.Score > cmdi {
					cmdi = r.Score
				}
			}
			if fams["path"] {
				if r := scorePath(candidate); r.Score > pathScore {
					pathScore = r.Score
				}
			}
		}
	}
	return sqli, xss, cmdi, pathScore
}
