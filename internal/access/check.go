// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package access

import (
	"net"
	"net/http"
	"strings"

	"github.com/Quad4-Software/ravenguard/internal/iputil"
)

// Result is the outcome of an access policy check.
type Result struct {
	OK       bool
	NeedForm bool
	Status   int
	Reason   string
}

// Check evaluates policyID against the request, optional clearance cookie, and clientIP.
func (m *Manager) Check(r *http.Request, policyID, bindID string, clientIP net.IP) Result {
	if policyID == "" {
		return allow()
	}
	cp, ok := m.getCompiled(policyID)
	if !ok {
		return deny("unknown access policy")
	}
	if m.VerifyCookie(r, policyID, bindID) {
		return allow()
	}
	if len(cp.rules) == 0 {
		return allow()
	}
	if cp.Mode == ModeAny {
		return m.checkAny(r, cp, clientIP)
	}
	return m.checkAll(r, cp, clientIP)
}

// VerifyForm checks a submitted password or PIN against policy secret rules.
func (m *Manager) VerifyForm(r *http.Request, policyID, bindID, secret string) bool {
	_ = r
	_ = bindID
	cp, ok := m.getCompiled(policyID)
	if !ok || secret == "" {
		return false
	}
	matched := 0
	needed := 0
	for _, rule := range cp.rules {
		if rule.Type != RulePassword && rule.Type != RulePIN {
			continue
		}
		needed++
		if rule.SecretHash == "" {
			continue
		}
		if VerifySecret(rule.SecretHash, secret) == nil {
			matched++
		}
	}
	if needed == 0 {
		return false
	}
	if cp.Mode == ModeAny {
		return matched > 0
	}
	return matched == needed
}

func (m *Manager) checkAll(r *http.Request, cp compiledPolicy, clientIP net.IP) Result {
	needAuth := false
	for _, rule := range cp.rules {
		switch rule.Type {
		case RulePassword, RulePIN:
			needAuth = true
		case RuleIPAllowlist:
			if !matchIP(rule.nets, clientIP) {
				return deny("ip not allowed")
			}
		case RuleHeader:
			if !matchHeader(r, rule.HeaderName, rule.HeaderValue) {
				return deny("header mismatch")
			}
		case RuleUserAgent:
			if !matchUserAgent(r, rule.UserAgents) {
				return deny("user agent not allowed")
			}
		default:
			return deny("unknown rule type")
		}
	}
	if needAuth {
		return needForm("authentication required")
	}
	return allow()
}

func (m *Manager) checkAny(r *http.Request, cp compiledPolicy, clientIP net.IP) Result {
	hasAuth := false
	for _, rule := range cp.rules {
		switch rule.Type {
		case RulePassword, RulePIN:
			hasAuth = true
		case RuleIPAllowlist:
			if matchIP(rule.nets, clientIP) {
				return allow()
			}
		case RuleHeader:
			if matchHeader(r, rule.HeaderName, rule.HeaderValue) {
				return allow()
			}
		case RuleUserAgent:
			if matchUserAgent(r, rule.UserAgents) {
				return allow()
			}
		}
	}
	if hasAuth {
		return needForm("authentication required")
	}
	return deny("access denied")
}

func matchIP(nets []net.IPNet, ip net.IP) bool {
	if ip == nil || len(nets) == 0 {
		return false
	}
	return iputil.ContainsIP(nets, ip)
}

func matchHeader(r *http.Request, name, want string) bool {
	if r == nil || name == "" {
		return false
	}
	return r.Header.Get(name) == want
}

func matchUserAgent(r *http.Request, allow []string) bool {
	if r == nil || len(allow) == 0 {
		return false
	}
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		return false
	}
	for _, sub := range allow {
		if sub == "" {
			continue
		}
		if strings.Contains(ua, sub) {
			return true
		}
	}
	return false
}

func allow() Result {
	return Result{OK: true, Status: http.StatusOK}
}

func needForm(reason string) Result {
	return Result{NeedForm: true, Status: http.StatusUnauthorized, Reason: reason}
}

func deny(reason string) Result {
	return Result{Status: http.StatusForbidden, Reason: reason}
}
