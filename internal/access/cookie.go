// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package access

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// IssueCookie writes an HMAC-signed rg_access clearance cookie bound to policyID and bindID.
// Cookie value format: policyID|expiryUnix|bindHMAC|mac
func (m *Manager) IssueCookie(w http.ResponseWriter, policyID, bindID string, secure bool) {
	ttl := defaultCookieTTL
	if p, ok := m.Get(policyID); ok {
		ttl = p.ttl()
	}
	exp := time.Now().Add(ttl)
	bindMAC := m.mac(bindID)
	payload := policyID + "|" + strconv.FormatInt(exp.Unix(), 10) + "|" + bindMAC
	mac := m.mac(payload)
	val := payload + "|" + mac
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName(),
		Value:    val,
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// VerifyCookie reports whether r carries a valid clearance for policyID and bindID.
func (m *Manager) VerifyCookie(r *http.Request, policyID, bindID string) bool {
	c, err := r.Cookie(m.cookieName())
	if err != nil || c.Value == "" {
		return false
	}
	return m.validateCookie(c.Value, policyID, bindID)
}

func (m *Manager) validateCookie(val, policyID, bindID string) bool {
	parts := strings.Split(val, "|")
	if len(parts) != 4 {
		return false
	}
	if parts[0] != policyID {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	wantBind := m.mac(bindID)
	if !hmac.Equal([]byte(wantBind), []byte(parts[2])) {
		return false
	}
	payload := parts[0] + "|" + parts[1] + "|" + parts[2]
	wantMAC := m.mac(payload)
	return hmac.Equal([]byte(wantMAC), []byte(parts[3]))
}

func (m *Manager) mac(payload string) string {
	h := hmac.New(sha256.New, m.Secret)
	_, _ = h.Write([]byte(payload))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}
