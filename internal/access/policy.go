// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package access

import (
	"net"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/iputil"
)

// Rule type identifiers.
const (
	RulePassword    = "password"
	RulePIN         = "pin"
	RuleIPAllowlist = "ip_allowlist"
	RuleHeader      = "header"
	RuleUserAgent   = "user_agent"

	ModeAll = "all"
	ModeAny = "any"

	CookieName = "rg_access"

	defaultCookieTTL = 24 * time.Hour
)

// Rule is one gate condition inside a Policy.
type Rule struct {
	Type string `json:"type"`
	// Secret is plaintext only on create or update input. Cleared after hashing.
	Secret string `json:"secret,omitempty"` // #nosec G117 -- secret only on write input
	// SecretHash is the argon2id encoding for password and pin rules.
	SecretHash  string   `json:"secret_hash,omitempty"`
	HeaderName  string   `json:"header_name,omitempty"`
	HeaderValue string   `json:"header_value,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty"`
	// UserAgents is a substring allowlist matched against the request User-Agent.
	UserAgents []string `json:"user_agents,omitempty"`
}

// Policy is a named set of access rules for a route or site gate.
type Policy struct {
	ID        string
	Name      string
	Mode      string // "all" (default AND) or "any"
	Rules     []Rule
	CookieTTL time.Duration
}

type compiledRule struct {
	Rule
	nets []net.IPNet
}

type compiledPolicy struct {
	Policy
	rules []compiledRule
}

// Manager holds HMAC secret material and a thread-safe policy map.
type Manager struct {
	Secret     []byte
	Brand      string
	CookieName string

	mu       sync.RWMutex
	policies map[string]compiledPolicy
}

// NewManager returns a Manager ready for Replace.
func NewManager(secret []byte) *Manager {
	return &Manager{
		Secret:     secret,
		Brand:      "RavenGuard",
		CookieName: CookieName,
		policies:   make(map[string]compiledPolicy),
	}
}

func (m *Manager) cookieName() string {
	if m != nil && m.CookieName != "" {
		return m.CookieName
	}
	return CookieName
}

// Replace swaps the full policy set. Password and PIN plaintext secrets are hashed.
func (m *Manager) Replace(policies []Policy) {
	next := make(map[string]compiledPolicy, len(policies))
	for _, p := range policies {
		if p.ID == "" {
			continue
		}
		cp := compilePolicy(p)
		next[p.ID] = cp
	}
	m.mu.Lock()
	m.policies = next
	m.mu.Unlock()
}

// Get returns a copy of the policy by ID.
func (m *Manager) Get(id string) (Policy, bool) {
	m.mu.RLock()
	cp, ok := m.policies[id]
	m.mu.RUnlock()
	if !ok {
		return Policy{}, false
	}
	return cp.clone(), true
}

func (m *Manager) getCompiled(id string) (compiledPolicy, bool) {
	m.mu.RLock()
	cp, ok := m.policies[id]
	m.mu.RUnlock()
	return cp, ok
}

func compilePolicy(p Policy) compiledPolicy {
	out := compiledPolicy{
		Policy: Policy{
			ID:        p.ID,
			Name:      p.Name,
			Mode:      normalizeMode(p.Mode),
			CookieTTL: p.CookieTTL,
			Rules:     make([]Rule, 0, len(p.Rules)),
		},
		rules: make([]compiledRule, 0, len(p.Rules)),
	}
	if out.CookieTTL <= 0 {
		out.CookieTTL = defaultCookieTTL
	}
	for _, r := range p.Rules {
		cr := compileRule(r)
		out.rules = append(out.rules, cr)
		out.Rules = append(out.Rules, cr.Rule)
	}
	return out
}

func compileRule(r Rule) compiledRule {
	cr := compiledRule{Rule: r}
	switch r.Type {
	case RulePassword, RulePIN:
		minLen := MinPasswordLen
		if r.Type == RulePIN {
			minLen = MinPINLen
		}
		if r.Secret != "" {
			if hash, err := HashSecret(r.Secret, minLen); err == nil {
				cr.SecretHash = hash
			}
			cr.Secret = ""
		}
	case RuleIPAllowlist:
		if nets, err := iputil.ParseCIDRs(r.CIDRs); err == nil {
			cr.nets = nets
		}
	}
	return cr
}

func normalizeMode(mode string) string {
	if mode == ModeAny {
		return ModeAny
	}
	return ModeAll
}

func (p Policy) clone() Policy {
	out := p
	if p.Rules != nil {
		out.Rules = make([]Rule, len(p.Rules))
		copy(out.Rules, p.Rules)
		for i := range out.Rules {
			if p.Rules[i].CIDRs != nil {
				out.Rules[i].CIDRs = append([]string(nil), p.Rules[i].CIDRs...)
			}
			if p.Rules[i].UserAgents != nil {
				out.Rules[i].UserAgents = append([]string(nil), p.Rules[i].UserAgents...)
			}
		}
	}
	return out
}

func (p Policy) ttl() time.Duration {
	if p.CookieTTL > 0 {
		return p.CookieTTL
	}
	return defaultCookieTTL
}
