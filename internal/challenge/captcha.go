// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

var ErrCaptchaFailed = errors.New("captcha verification failed")

type StubCaptcha struct {
	Token string
}

func (s StubCaptcha) Verify(_ *http.Request, token string) error {
	want := s.Token
	if want == "" {
		want = "ok"
	}
	if strings.TrimSpace(token) != want {
		return ErrCaptchaFailed
	}
	return nil
}

// RavenCaptcha verifies a protocol v1 widget payload using Manager.
type RavenCaptcha struct {
	Manager *Manager
}

func (r RavenCaptcha) Verify(req *http.Request, token string) error {
	if r.Manager == nil {
		return ErrCaptchaNeeded
	}
	bindID := req.Header.Get("X-RavenGuard-Bind")
	p, err := r.Manager.VerifyPayload(token, bindID)
	if err != nil {
		return ErrCaptchaFailed
	}
	verdict := r.Manager.EvaluateEnv(p.Env.ToReport(), p.Difficulty)
	if verdict.Refuse {
		return ErrCaptchaFailed
	}
	return nil
}

func NewCaptcha(provider, token string) (CaptchaVerifier, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "stub":
		return StubCaptcha{Token: token}, nil
	case "ravenguard":
		return RavenCaptcha{}, nil
	default:
		return nil, ErrCaptchaNeeded
	}
}

// NewRavenCaptcha returns a verifier bound to m.
func NewRavenCaptcha(m *Manager) CaptchaVerifier {
	return RavenCaptcha{Manager: m}
}

type riskEntry struct {
	level RiskLevel
	exp   int64
}

type riskCache struct {
	mu   sync.Mutex
	byID map[string]riskEntry
}

func (c *riskCache) put(id string, level RiskLevel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byID == nil {
		c.byID = make(map[string]riskEntry)
	}
	c.byID[id] = riskEntry{level: level, exp: time.Now().Unix() + tokenTTL}
}

func (c *riskCache) get(id string) RiskLevel {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID[id]
	if !ok || e.exp < time.Now().Unix() {
		return RiskLow
	}
	return e.level
}

func (c *riskCache) sweep(now int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.byID {
		if e.exp < now {
			delete(c.byID, k)
		}
	}
}

// RememberRisk stores adaptive risk for the next challenge issue.
func (m *Manager) RememberRisk(bindID string, risk RiskLevel) {
	if m == nil {
		return
	}
	m.risks.put(bindID, risk)
}

// TakeRisk returns remembered risk or RiskLow.
func (m *Manager) TakeRisk(bindID string) RiskLevel {
	if m == nil {
		return RiskLow
	}
	return m.risks.get(bindID)
}
