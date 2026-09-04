// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package semantic_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/semantic"
)

func TestConcurrentEvaluate(t *testing.T) {
	eng := semantic.New(config.SemanticConfig{
		Enabled: true, Mode: "shadow", MaxDecodeDepth: 3, MaxDecodeBytes: 1 << 20,
		MaxCPUNanos: int64(time.Second), Families: []string{"sqli", "xss", "cmd", "path"},
	})
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			r := httptest.NewRequest(http.MethodGet, "/q?x=1'+union+select+1", nil)
			eng.UpdateLive(true, "shadow")
			_ = eng.Evaluate(r, nil)
		})
	}
	wg.Wait()
}
