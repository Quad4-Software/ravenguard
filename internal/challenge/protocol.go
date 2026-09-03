// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func randRead(b []byte) (int, error) {
	return rand.Read(b)
}

const ProtocolVersion = 1

var (
	ErrBadPayload   = errors.New("invalid challenge payload")
	ErrBadSignature = errors.New("invalid challenge signature")
	ErrBadAlgorithm = errors.New("unsupported challenge algorithm")
	ErrBindMismatch = errors.New("challenge bind mismatch")
)

// Algorithm names on the wire.
const (
	AlgoSHA256       = "SHA-256"
	AlgoPBKDF2SHA256 = "PBKDF2-SHA256"
	AlgoArgon2id     = "ARGON2ID"
)

// RiskLevel selects adaptive PoW effort.
type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskElevated
	RiskHigh
)

// Challenge is a protocol v1 challenge issued to the widget.
type Challenge struct {
	V          int            `json:"v"`
	Algorithm  string         `json:"algorithm"`
	Challenge  string         `json:"challenge"`
	Salt       string         `json:"salt,omitempty"`
	Difficulty int            `json:"difficulty"`
	MaxNumber  uint64         `json:"maxnumber"`
	Expires    int64          `json:"expires"`
	Bind       string         `json:"bind,omitempty"`
	Params     map[string]int `json:"params,omitempty"`
	Signature  string         `json:"signature"`
}

// EnvAttestation is browser probe data carried in the solved payload.
type EnvAttestation struct {
	Webdriver  bool `json:"webdriver"`
	Playwright bool `json:"playwright"`
	Selenium   bool `json:"selenium"`
	Headless   bool `json:"headless"`
	NoPlugins  bool `json:"no_plugins"`
	Interacted bool `json:"interacted"`
	SolveMs    int  `json:"solve_ms"`
}

// Payload is the base64url JSON the widget submits after solving.
type Payload struct {
	V          int            `json:"v"`
	Algorithm  string         `json:"algorithm"`
	Challenge  string         `json:"challenge"`
	Salt       string         `json:"salt,omitempty"`
	Difficulty int            `json:"difficulty"`
	MaxNumber  uint64         `json:"maxnumber"`
	Expires    int64          `json:"expires"`
	Bind       string         `json:"bind,omitempty"`
	Params     map[string]int `json:"params,omitempty"`
	Signature  string         `json:"signature"`
	Solution   string         `json:"solution"`
	Env        EnvAttestation `json:"env"`
}

func (c Challenge) ToToken() Token {
	return Token{
		Nonce:      c.Challenge,
		IssuedAt:   c.Expires - tokenTTL,
		Difficulty: c.Difficulty,
	}
}

func (m *Manager) IssueChallenge(bindID string, risk RiskLevel) (Challenge, error) {
	algo, diff, params := m.selectEffort(risk)
	var nb [16]byte
	if _, err := randRead(nb[:]); err != nil {
		return Challenge{}, err
	}
	chal := hex.EncodeToString(nb[:])
	var salt string
	if algo == AlgoPBKDF2SHA256 || algo == AlgoArgon2id {
		var sb [16]byte
		if _, err := randRead(sb[:]); err != nil {
			return Challenge{}, err
		}
		salt = hex.EncodeToString(sb[:])
	}
	expires := time.Now().Unix() + tokenTTL
	maxn := maxNumberFor(diff)
	ch := Challenge{
		V:          ProtocolVersion,
		Algorithm:  algo,
		Challenge:  chal,
		Salt:       salt,
		Difficulty: diff,
		MaxNumber:  maxn,
		Expires:    expires,
		Bind:       bindID,
		Params:     params,
	}
	sig, err := m.signChallenge(ch)
	if err != nil {
		return Challenge{}, err
	}
	ch.Signature = sig
	return ch, nil
}

func (m *Manager) selectEffort(risk RiskLevel) (algo string, diff int, params map[string]int) {
	diff = m.Difficulty
	if diff <= 0 {
		diff = 16
	}
	mode := strings.ToLower(strings.TrimSpace(m.Algorithm))
	switch mode {
	case "sha256", "sha-256":
		return AlgoSHA256, diff, nil
	case "pbkdf2", "pbkdf2-sha256":
		return AlgoPBKDF2SHA256, diff, map[string]int{"iterations": 10000}
	case "argon2id":
		return AlgoArgon2id, diff, map[string]int{"memory": 19456, "iterations": 2, "parallelism": 1}
	default:
		// adaptive
	}
	switch risk {
	case RiskHigh:
		d := min(diff+4, 28)
		return AlgoPBKDF2SHA256, d, map[string]int{"iterations": 50000}
	case RiskElevated:
		return AlgoPBKDF2SHA256, diff, map[string]int{"iterations": 10000}
	default:
		return AlgoSHA256, diff, nil
	}
}

func maxNumberFor(diff int) uint64 {
	if diff <= 0 {
		return 1 << 16
	}
	if diff >= 28 {
		return 1 << 32
	}
	// Search space ~ 8x expected work for leading-zero bits.
	shift := min(diff+3, 32)
	return 1 << uint(shift)
}

func (m *Manager) signChallenge(ch Challenge) (string, error) {
	mac := hmac.New(sha256.New, m.Secret)
	_, _ = mac.Write([]byte(canonicalChallenge(ch)))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func canonicalChallenge(ch Challenge) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(ch.V))
	b.WriteByte('|')
	b.WriteString(ch.Algorithm)
	b.WriteByte('|')
	b.WriteString(ch.Challenge)
	b.WriteByte('|')
	b.WriteString(ch.Salt)
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(ch.Difficulty))
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(ch.MaxNumber, 10))
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(ch.Expires, 10))
	b.WriteByte('|')
	b.WriteString(ch.Bind)
	b.WriteByte('|')
	b.WriteString(canonicalParams(ch.Params))
	return b.String()
}

func canonicalParams(p map[string]int) string {
	if len(p) == 0 {
		return ""
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	// Insertion order is unstable; sort for HMAC stability.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(p[k]))
	}
	return b.String()
}

func (m *Manager) verifyChallengeSignature(ch Challenge) error {
	expect, err := m.signChallenge(ch)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(expect), []byte(ch.Signature)) {
		return ErrBadSignature
	}
	return nil
}

// DecodePayload parses a base64url JSON payload from the widget.
func DecodePayload(raw string) (Payload, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Payload{}, ErrBadPayload
	}
	bin, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		bin, err = base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return Payload{}, ErrBadPayload
		}
	}
	var p Payload
	if err := json.Unmarshal(bin, &p); err != nil {
		return Payload{}, ErrBadPayload
	}
	if p.V != ProtocolVersion {
		return Payload{}, ErrBadPayload
	}
	return p, nil
}

// EncodePayload returns base64url JSON for the payload.
func EncodePayload(p Payload) (string, error) {
	bin, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bin), nil
}

func (p Payload) asChallenge() Challenge {
	return Challenge{
		V:          p.V,
		Algorithm:  p.Algorithm,
		Challenge:  p.Challenge,
		Salt:       p.Salt,
		Difficulty: p.Difficulty,
		MaxNumber:  p.MaxNumber,
		Expires:    p.Expires,
		Bind:       p.Bind,
		Params:     p.Params,
		Signature:  p.Signature,
	}
}

// VerifyPayload checks signature, expiry, bind, PoW, and consumes the nonce.
func (m *Manager) VerifyPayload(raw string, bindID string) (Payload, error) {
	p, err := DecodePayload(raw)
	if err != nil {
		return Payload{}, err
	}
	if bindID != "" && p.Bind != "" && p.Bind != bindID {
		return Payload{}, ErrBindMismatch
	}
	if time.Now().Unix() > p.Expires {
		return Payload{}, ErrExpired
	}
	ch := p.asChallenge()
	if err := m.verifyChallengeSignature(ch); err != nil {
		return Payload{}, err
	}
	sol, err := strconv.ParseUint(p.Solution, 10, 64)
	if err != nil {
		return Payload{}, ErrBadSolution
	}
	if p.MaxNumber > 0 && sol > p.MaxNumber {
		return Payload{}, ErrBadSolution
	}
	if err := VerifySolution(ch, sol); err != nil {
		return Payload{}, err
	}
	tok := Token{Nonce: p.Challenge, IssuedAt: p.Expires - tokenTTL, Difficulty: p.Difficulty}
	if err := m.ConsumeNonce(tok); err != nil {
		return Payload{}, err
	}
	return p, nil
}

// RiskFromScore maps a detect score to adaptive risk.
func RiskFromScore(score, challengeScore, blockScore int) RiskLevel {
	if blockScore > 0 && score >= blockScore {
		return RiskHigh
	}
	if challengeScore > 0 && score >= challengeScore+20 {
		return RiskHigh
	}
	if challengeScore > 0 && score >= challengeScore {
		return RiskElevated
	}
	if score >= 20 {
		return RiskElevated
	}
	return RiskLow
}

func (e EnvAttestation) ToReport() EnvReport {
	return EnvReport(e)
}

func FormatChallengeJSON(ch Challenge) ([]byte, error) {
	return json.Marshal(ch)
}

func ParseChallengeJSON(raw []byte) (Challenge, error) {
	var ch Challenge
	if err := json.Unmarshal(raw, &ch); err != nil {
		return Challenge{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if ch.V != ProtocolVersion {
		return Challenge{}, ErrInvalidToken
	}
	return ch, nil
}
