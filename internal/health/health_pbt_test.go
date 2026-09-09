// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package health

import (
	"encoding/json"
	"math/rand/v2"
	"net/url"
	"slices"
	"testing"
)

// referenceHealthyStatus is an independent oracle for the health policy.
// It mirrors the intended semantics without using the code under test.
func referenceHealthyStatus(code int, successCodes []int) bool {
	if len(successCodes) == 0 {
		return code >= 200 && code < 300
	}
	return slices.Contains(successCodes, code)
}

// TestHealthyStatusUniversal checks the status policy against an independent
// oracle across random status codes and random success-code lists.
func TestHealthyStatusUniversal(t *testing.T) {
	const trials = 1000
	r := rand.New(rand.NewPCG(1, 2))

	for i := range trials {
		_ = i
		code := r.IntN(900) + 100

		n := r.IntN(20)
		successCodes := make([]int, n)
		for j := range successCodes {
			successCodes[j] = r.IntN(900) + 100
		}

		c := &Checker{successCodes: successCodes}
		got := c.healthyStatus(code)
		want := referenceHealthyStatus(code, successCodes)
		if got != want {
			t.Fatalf("code=%d successCodes=%v: got %v want %v", code, successCodes, got, want)
		}
	}
}

// TestHealthyStatusMetamorphic checks invariants under equivalent
// transformations of the success-code list.
func TestHealthyStatusMetamorphic(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))

	for range 500 {
		code := r.IntN(900) + 100

		n := r.IntN(10)
		base := make([]int, n)
		for i := range base {
			base[i] = r.IntN(900) + 100
		}

		c := &Checker{successCodes: base}
		original := c.healthyStatus(code)

		// Adding a code that is not the probe code should not change the result
		// when the list is already explicit.
		if len(base) > 0 {
			other := code
			for other == code {
				other = r.IntN(900) + 100
			}
			c2 := &Checker{successCodes: append(slices.Clone(base), other)}
			if got := c2.healthyStatus(code); got != original {
				t.Fatalf("adding unrelated code %d changed result for %d", other, code)
			}
		}

		// Adding the probe code should make the result true.
		c3 := &Checker{successCodes: append(slices.Clone(base), code)}
		if !c3.healthyStatus(code) {
			t.Fatalf("adding probe code %d did not make it healthy", code)
		}

		// Removing a code not equal to the probe code should not change the result
		// as long as the list stays explicit.
		if len(base) > 1 {
			removeIdx := r.IntN(len(base))
			removed := base[removeIdx]
			if removed != code {
				without := slices.Clone(base)
				without = append(without[:removeIdx], without[removeIdx+1:]...)
				c4 := &Checker{successCodes: without}
				if got := c4.healthyStatus(code); got != original {
					t.Fatalf("removing %d changed result for %d", removed, code)
				}
			}
		}
	}
}

// TestHealthyStatusBoundary checks adversarial boundary values.
func TestHealthyStatusBoundary(t *testing.T) {
	type sub struct {
		code         int
		successCodes []int
		want         bool
	}
	cases := []sub{
		{199, nil, false},
		{200, nil, true},
		{299, nil, true},
		{300, nil, false},
		{200, []int{200, 403}, true},
		{403, []int{200, 403}, true},
		{201, []int{200, 403}, false},
		{0, []int{0}, true},
		{-1, nil, false},
		{1000, []int{1000}, true},
	}
	for _, tc := range cases {
		c := &Checker{successCodes: tc.successCodes}
		if got := c.healthyStatus(tc.code); got != tc.want {
			t.Errorf("code=%d success=%v: got %v want %v", tc.code, tc.successCodes, got, tc.want)
		}
	}
}

// TestHealthyStatusOracleInvariant checks that every status code has a stable
// deterministic classification once the success list is fixed.
func TestHealthyStatusOracleInvariant(t *testing.T) {
	successCodes := []int{200, 201, 204, 403, 418}
	c := &Checker{successCodes: successCodes}
	first := c.healthyStatus(200)
	for range 10 {
		if c.healthyStatus(200) != first {
			t.Fatal("healthyStatus is not deterministic")
		}
	}

	// Empty success list must fall back to the 2xx range.
	c2 := &Checker{successCodes: nil}
	for code := 100; code < 600; code++ {
		want := code >= 200 && code < 300
		if got := c2.healthyStatus(code); got != want {
			t.Fatalf("empty list: code=%d got %v want %v", code, got, want)
		}
	}
}

// TestCheckerProbeURLInvariants checks URL scheme normalization with an
// independent oracle based on net/url and string inspection.
func TestCheckerProbeURLInvariants(t *testing.T) {
	type sub struct {
		input string
		path  string
		want  string
	}
	cases := []sub{
		{"", "/healthz", "http://localhost/healthz"},
		{"http://example.com", "/ready", "http://example.com/ready"},
		{"https://example.com/foo?bar=1", "/ready", "https://example.com/ready"},
		{"ws://example.com/app", "/ready", "http://example.com/ready"},
		{"wss://example.com/app", "/ready", "https://example.com/ready"},
		{"unix:///tmp/rg.sock", "/ready", "http://localhost/ready"},
	}
	for _, tc := range cases {
		var u *url.URL
		if tc.input != "" {
			var err error
			u, err = url.Parse(tc.input)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.input, err)
			}
		}
		c := New(Config{URL: u, Path: tc.path})
		if c.probeURL != tc.want {
			t.Errorf("input=%q path=%q: got %q want %q", tc.input, tc.path, c.probeURL, tc.want)
		}
	}
}

func FuzzHealthyStatus(f *testing.F) {
	f.Add(200, []byte("[200,403]"))
	f.Add(503, []byte("[200,403]"))
	f.Add(200, []byte("[]"))

	f.Fuzz(func(t *testing.T, code int, rawCodes []byte) {
		var codes []int
		if err := json.Unmarshal(rawCodes, &codes); err != nil {
			t.Skip("invalid json codes corpus")
		}
		c := &Checker{successCodes: codes}
		got := c.healthyStatus(code)
		want := referenceHealthyStatus(code, codes)
		if got != want {
			t.Fatalf("code=%d codes=%v: got %v want %v", code, codes, got, want)
		}
	})
}
