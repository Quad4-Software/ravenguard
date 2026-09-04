// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package semantic

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"sync"
	"time"
	"unicode/utf8"
)

// ErrBudget is returned when decode depth, bytes, or CPU is exceeded.
var ErrBudget = errors.New("semantic: budget exceeded")

// Budget tracks decode limits for one evaluation.
type Budget struct {
	Deadline time.Time
	MaxBytes int
	MaxDepth int
	used     int
}

// Expired reports whether the CPU deadline passed.
func (b *Budget) Expired() bool {
	return b != nil && !b.Deadline.IsZero() && time.Now().After(b.Deadline)
}

func (b *Budget) add(n int) error {
	if b == nil {
		return nil
	}
	if b.Expired() {
		return ErrBudget
	}
	b.used += n
	if b.MaxBytes > 0 && b.used > b.MaxBytes {
		return ErrBudget
	}
	return nil
}

var decodePool = sync.Pool{
	New: func() any {
		s := make([][]byte, 0, 8)
		return &s
	},
}

// DecodeChain expands encodings up to MaxDepth and returns unique candidates.
func DecodeChain(in []byte, budget *Budget) ([][]byte, error) {
	if len(in) == 0 {
		return nil, nil
	}
	sp := decodePool.Get().(*[][]byte)
	out := (*sp)[:0]
	defer func() {
		*sp = out[:0]
		decodePool.Put(sp)
	}()

	seen := map[string]struct{}{}
	var walk func(b []byte, depth int) error
	walk = func(b []byte, depth int) error {
		if budget != nil && budget.Expired() {
			return ErrBudget
		}
		if depth > 0 && budget != nil && budget.MaxDepth > 0 && depth > budget.MaxDepth {
			return nil
		}
		key := string(b)
		if _, ok := seen[key]; ok {
			return nil
		}
		seen[key] = struct{}{}
		if err := budget.add(len(b)); err != nil {
			return err
		}
		cp := append([]byte(nil), b...)
		out = append(out, cp)

		if depth >= budgetMaxDepth(budget) {
			return nil
		}

		if u, ok := tryURLDecode(b); ok && !bytes.Equal(u, b) {
			if err := walk(u, depth+1); err != nil {
				return err
			}
		}
		if d, ok := tryBase64(b); ok {
			if err := walk(d, depth+1); err != nil {
				return err
			}
		}
		if d, ok := tryHex(b); ok {
			if err := walk(d, depth+1); err != nil {
				return err
			}
		}
		if d, ok := tryUnicodeEscape(b); ok {
			if err := walk(d, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(in, 0); err != nil {
		return nil, err
	}
	// Return copies owned by caller (pool cleared after return).
	res := make([][]byte, len(out))
	for i := range out {
		res[i] = append([]byte(nil), out[i]...)
	}
	return res, nil
}

func budgetMaxDepth(b *Budget) int {
	if b == nil || b.MaxDepth <= 0 {
		return 3
	}
	return b.MaxDepth
}

func tryURLDecode(b []byte) ([]byte, bool) {
	if !bytes.ContainsRune(b, '%') && !bytes.Contains(b, []byte("+")) {
		return nil, false
	}
	s := string(b)
	u, err := url.QueryUnescape(s)
	if err != nil || u == s {
		return nil, false
	}
	return []byte(u), true
}

func tryBase64(b []byte) ([]byte, bool) {
	if len(b) < 8 || len(b)%4 != 0 {
		return nil, false
	}
	for _, c := range b {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '+' && c != '/' && c != '=' && c != '-' && c != '_' {
			return nil, false
		}
	}
	enc := base64.StdEncoding
	if bytes.ContainsAny(b, "-_") {
		enc = base64.URLEncoding
	}
	d := make([]byte, enc.DecodedLen(len(b)))
	n, err := enc.Decode(d, b)
	if err != nil || n == 0 {
		return nil, false
	}
	d = d[:n]
	if !utf8.Valid(d) && !looksBinaryPayload(d) {
		return nil, false
	}
	return d, true
}

func tryHex(b []byte) ([]byte, bool) {
	if len(b) < 4 || len(b)%2 != 0 {
		return nil, false
	}
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return nil, false
		}
	}
	d := make([]byte, hex.DecodedLen(len(b)))
	n, err := hex.Decode(d, b)
	if err != nil || n == 0 {
		return nil, false
	}
	return d[:n], true
}

func tryUnicodeEscape(b []byte) ([]byte, bool) {
	if !bytes.Contains(b, []byte(`\u`)) && !bytes.Contains(b, []byte(`\x`)) {
		return nil, false
	}
	out := make([]byte, 0, len(b))
	changed := false
	for i := 0; i < len(b); {
		if i+5 < len(b) && b[i] == '\\' && b[i+1] == 'u' {
			var v rune
			ok := true
			for j := range 4 {
				c := b[i+2+j]
				var n rune
				switch {
				case c >= '0' && c <= '9':
					n = rune(c - '0')
				case c >= 'a' && c <= 'f':
					n = rune(c-'a') + 10
				case c >= 'A' && c <= 'F':
					n = rune(c-'A') + 10
				default:
					ok = false
				}
				v = v<<4 | n
			}
			if ok {
				out = utf8.AppendRune(out, v)
				i += 6
				changed = true
				continue
			}
		}
		if i+3 < len(b) && b[i] == '\\' && b[i+1] == 'x' {
			h := b[i+2 : i+4]
			d := make([]byte, 1)
			if _, err := hex.Decode(d, h); err == nil {
				out = append(out, d[0])
				i += 4
				changed = true
				continue
			}
		}
		out = append(out, b[i])
		i++
	}
	if !changed {
		return nil, false
	}
	return out, true
}

func looksBinaryPayload(b []byte) bool {
	nul := 0
	for _, c := range b {
		if c == 0 {
			nul++
		}
	}
	return nul > 0 && nul < len(b)/4
}

// TruncEvidence returns a short printable evidence snippet.
func TruncEvidence(b []byte, n int) string {
	if n <= 0 {
		n = 128
	}
	if len(b) > n {
		b = b[:n]
	}
	out := make([]byte, len(b))
	copy(out, b)
	for i, c := range out {
		if c < 0x20 || c > 0x7e {
			out[i] = '.'
		}
	}
	return string(out)
}
