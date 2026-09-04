// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ml_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/ml"
)

func TestConcurrentScoreAndAdapt(t *testing.T) {
	s := ml.New(config.MLConfig{
		Enabled: true, Mode: "shadow", MaxPoints: 60, ConfidenceMin: 0.5,
		ChallengeProb: 0.75, BlockProb: 0.95, ShadowSampleRate: 1,
	}, ml.DefaultModel())
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			s.UpdateLive(true, "shadow")
			if i%4 == 0 {
				s.SetAdapt(ml.DefaultModel())
			}
			_ = s.Evaluate(r, ml.Input{SemanticSQLi: (i % 2) * 80})
			if sh := s.Shadow(); sh != nil {
				sh.Offer(ml.Sample{Ray: "r", Prob: 0.1})
			}
		}(i)
	}
	wg.Wait()
}
