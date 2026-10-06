// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package privacy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"sync"

	"github.com/Quad4-Software/ravenguard/internal/faststr"
)

type Config struct {
	Secret []byte
	LogIP  string
}

type Guard struct {
	secret  []byte
	logIP   string
	macPool sync.Pool
}

func New(cfg Config) *Guard {
	logMode := faststr.TrimSpace(cfg.LogIP)
	if logMode == "" {
		logMode = "hash"
	} else {
		logMode = lowerASCII(logMode)
	}
	secret := append([]byte(nil), cfg.Secret...)
	g := &Guard{
		secret: secret,
		logIP:  logMode,
	}
	g.macPool = sync.Pool{
		New: func() any {
			return hmac.New(sha256.New, secret)
		},
	}
	return g
}

func (g *Guard) ClientKey(ip string) string {
	ip = faststr.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if g == nil {
		return ip
	}
	return g.hash(ip)
}

func (g *Guard) LogIP(ip string) string {
	ip = faststr.TrimSpace(ip)
	if g == nil {
		return ip
	}
	switch g.logIP {
	case "off":
		return ""
	default:
		if ip == "" {
			return ""
		}
		return g.hash(ip)
	}
}

func (g *Guard) hash(ip string) string {
	h := g.macPool.Get().(hash.Hash)
	h.Reset()
	_, _ = h.Write(unsafeBytes(ip))
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	g.macPool.Put(h)
	var out [32]byte
	hex.Encode(out[:], sum[:16])
	return string(out[:])
}

func lowerASCII(s string) string {
	need := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			need = true
			break
		}
	}
	if !need {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
