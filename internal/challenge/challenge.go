// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/strhash"
)

var (
	ErrInvalidToken  = errors.New("invalid challenge token")
	ErrBadSolution   = errors.New("bad pow solution")
	ErrExpired       = errors.New("challenge expired")
	ErrBadCookie     = errors.New("invalid clearance cookie")
	ErrCaptchaNeeded = errors.New("captcha provider not configured")
	ErrReplay        = errors.New("challenge token already used")
)

const (
	tokenTTL      = 300
	nonceShards   = 256
	defaultSecure = false
)

type CaptchaVerifier interface {
	Verify(r *http.Request, token string) error
}

type Manager struct {
	Secret     []byte
	Difficulty int
	CookieName string
	CookieTTL  time.Duration
	Secure     bool
	Captcha    CaptchaVerifier
	nonces     nonceStore
}

type Token struct {
	Nonce      string
	IssuedAt   int64
	Difficulty int
}

type nonceStore struct {
	shards [nonceShards]nonceShard
}

type nonceShard struct {
	mu   sync.Mutex
	used map[string]int64
}

func (m *Manager) Issue(clientID string) (Token, string, error) {
	var nb [16]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return Token{}, "", err
	}
	t := Token{
		Nonce:      hex.EncodeToString(nb[:]),
		IssuedAt:   time.Now().Unix(),
		Difficulty: m.Difficulty,
	}
	sig := m.sign(t.Nonce, t.IssuedAt, t.Difficulty, clientID)
	payload := fmt.Sprintf("%s.%d.%d.%s", t.Nonce, t.IssuedAt, t.Difficulty, sig)
	return t, payload, nil
}

func (m *Manager) ParseToken(raw, clientID string) (Token, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 4 {
		return Token{}, ErrInvalidToken
	}
	issued, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return Token{}, ErrInvalidToken
	}
	diff, err := strconv.Atoi(parts[2])
	if err != nil {
		return Token{}, ErrInvalidToken
	}
	expect := m.sign(parts[0], issued, diff, clientID)
	if !hmac.Equal([]byte(expect), []byte(parts[3])) {
		return Token{}, ErrInvalidToken
	}
	if time.Now().Unix()-issued > tokenTTL {
		return Token{}, ErrExpired
	}
	return Token{Nonce: parts[0], IssuedAt: issued, Difficulty: diff}, nil
}

func (m *Manager) VerifyPoW(token Token, nonceSolution string) error {
	n, err := strconv.ParseUint(nonceSolution, 10, 64)
	if err != nil {
		return ErrBadSolution
	}
	if !checkPoW(token.Nonce, n, token.Difficulty) {
		return ErrBadSolution
	}
	return nil
}

func (m *Manager) ConsumeNonce(token Token) error {
	exp := token.IssuedAt + tokenTTL
	if time.Now().Unix() > exp {
		return ErrExpired
	}
	if !m.nonces.consume(token.Nonce, exp) {
		return ErrReplay
	}
	return nil
}

func (m *Manager) SweepNonces(now time.Time) {
	m.nonces.sweep(now.Unix())
}

func (s *nonceStore) consume(nonce string, exp int64) bool {
	sh := &s.shards[hashNonce(nonce)%nonceShards]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.used == nil {
		sh.used = make(map[string]int64)
	}
	if _, ok := sh.used[nonce]; ok {
		return false
	}
	sh.used[nonce] = exp
	return true
}

func (s *nonceStore) sweep(now int64) {
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for k, exp := range sh.used {
			if exp < now {
				delete(sh.used, k)
			}
		}
		sh.mu.Unlock()
	}
}

func hashNonce(nonce string) uint32 {
	return strhash.String(nonce)
}

func (m *Manager) ClearanceCookie(bindID, ray string, secure bool) *http.Cookie {
	exp := time.Now().Add(m.CookieTTL)
	payload := fmt.Sprintf("%s|%d|%s", bindID, exp.Unix(), ray)
	mac := m.mac(payload)
	val := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + mac
	return &http.Cookie{
		Name:     m.CookieName,
		Value:    val,
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(m.CookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (m *Manager) HasClearance(r *http.Request, bindID string) bool {
	c, err := r.Cookie(m.CookieName)
	if err != nil || c.Value == "" {
		return false
	}
	return m.validateCookie(c.Value, bindID) == nil
}

func (m *Manager) validateCookie(val, bindID string) error {
	parts := strings.Split(val, ".")
	if len(parts) != 2 {
		return ErrBadCookie
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ErrBadCookie
	}
	if !hmac.Equal([]byte(m.mac(string(raw))), []byte(parts[1])) {
		return ErrBadCookie
	}
	fields := strings.Split(string(raw), "|")
	if len(fields) != 3 {
		return ErrBadCookie
	}
	if fields[0] != bindID {
		return ErrBadCookie
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return ErrExpired
	}
	return nil
}

func (m *Manager) sign(nonce string, issued int64, diff int, clientID string) string {
	h := hmac.New(sha256.New, m.Secret)
	_, _ = h.Write(stringBytes(nonce))
	_, _ = h.Write(dotSep)
	var buf [16]byte
	n := strconv.AppendInt(buf[:0], issued, 10)
	_, _ = h.Write(n)
	_, _ = h.Write(dotSep)
	n = strconv.AppendInt(buf[:0], int64(diff), 10)
	_, _ = h.Write(n)
	_, _ = h.Write(dotSep)
	_, _ = h.Write(stringBytes(clientID))
	sum := h.Sum(buf[:0])
	return hex.EncodeToString(sum)
}

func (m *Manager) mac(payload string) string {
	h := hmac.New(sha256.New, m.Secret)
	_, _ = h.Write(stringBytes(payload))
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return hex.EncodeToString(sum[:])
}

var dotSep = []byte{'.'}

func checkPoW(nonce string, solution uint64, difficulty int) bool {
	h := sha256.New()
	_, _ = h.Write(stringBytes(nonce))
	_, _ = h.Write(colonSep)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], solution)
	_, _ = h.Write(b[:])
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return leadingZeroBits(sum[:]) >= difficulty
}

var colonSep = []byte{':'}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, c := range b {
		if c == 0 {
			n += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if c&(1<<uint(i)) == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}

func SolvePoW(nonce string, difficulty int) (uint64, error) {
	for i := range uint64(1 << 32) {
		if checkPoW(nonce, i, difficulty) {
			return i, nil
		}
	}
	return 0, ErrBadSolution
}

func LeadingZeroBits(b []byte) int {
	return leadingZeroBits(b)
}

// SecureDefault reports the manager startup Secure flag.
func (m *Manager) SecureDefault() bool {
	if m == nil {
		return defaultSecure
	}
	return m.Secure
}
