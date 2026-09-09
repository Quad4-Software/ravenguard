// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package health

import (
	"testing"
)

func FuzzCheckerHealthyStatus(f *testing.F) {
	// Differential / metamorphic seed: any code in the configured success set
	// should be healthy; any code outside an empty set should be unhealthy.
	for _, code := range []int{100, 199, 200, 201, 299, 300, 301, 400, 401, 403, 404, 500, 502, 503} {
		f.Add(code, 0) // empty success set (default 2xx)
		f.Add(code, 1) // success set {200, 403}
		f.Add(code, 2) // success set {200}
	}
	f.Fuzz(func(t *testing.T, code, mode int) {
		c := &Checker{}
		switch mode {
		case 0:
			c.successCodes = nil
		case 1:
			c.successCodes = []int{200, 403}
		case 2:
			c.successCodes = []int{200}
		default:
			c.successCodes = []int{200}
		}
		got := c.healthyStatus(code)
		// Oracle: 200 is always healthy; 500s are never healthy with these sets.
		if code == 200 && !got {
			t.Fatalf("200 must always be healthy, got %v", got)
		}
		if code >= 500 && got {
			t.Fatalf("5xx must never be healthy with set %v, got %v", c.successCodes, got)
		}
	})
}
