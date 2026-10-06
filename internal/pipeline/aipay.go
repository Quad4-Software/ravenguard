// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/detect"
	"github.com/Quad4-Software/ravenguard/internal/requestlog"
)

func newWebBotVerifier(cfg config.Config) *detect.WebBotVerifier {
	if !cfg.Detect.WebBotAuth.Enabled {
		return nil
	}
	return detect.NewWebBotVerifier(cfg.Detect.WebBotAuth.Timeout.Duration)
}

// readOptionalFile loads an operator-provided static file. Missing or
// unreadable paths yield an empty body, which the caller serves as 404.
func readOptionalFile(path string) []byte {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil
	}
	return b
}

// servePolicyFile serves an in-memory static document for AI crawl policy
// files (/.well-known/rsl.xml, /llms.txt). Empty body renders 404.
func (h *Handler) servePolicyFile(body *[]byte, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		b := *body
		if len(b) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if r.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	}
}

// aiPaymentValid reports whether the request carries a payment signature
// that the configured x402 facilitator verifies. Without a facilitator
// configured, no signature can be validated and every pay-policy request
// returns 402.
func (h *Handler) aiPaymentValid(r *http.Request) bool {
	cfg := h.config()
	fac := cfg.Detect.AIPay.Facilitator
	if fac == "" {
		return false
	}
	sig := r.Header.Get("PAYMENT-SIGNATURE")
	if sig == "" {
		sig = r.Header.Get("X-PAYMENT")
	}
	if sig == "" {
		return false
	}
	payload, _ := json.Marshal(map[string]any{
		"x402Version":         1,
		"paymentHeader":       sig,
		"paymentRequirements": h.paymentRequirements(r, cfg),
	})
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fac+"/verify", bytes.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		IsValid bool `json:"isValid"`
	}
	return resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&out) == nil && out.IsValid
}

// paymentRequirements builds the single x402 accept entry describing the
// price for the requested resource.
func (h *Handler) paymentRequirements(r *http.Request, cfg config.Config) map[string]any {
	scheme := "https"
	if !h.requestSecure(r) {
		scheme = "http"
	}
	return map[string]any{
		"scheme":            "exact",
		"network":           cfg.Detect.AIPay.Network,
		"maxAmountRequired": cfg.Detect.AIPay.Amount,
		"resource":          scheme + "://" + r.Host + r.URL.RequestURI(),
		"description":       cfg.Detect.AIPay.Description,
		"mimeType":          "text/html",
		"payTo":             cfg.Detect.AIPay.PayTo,
		"maxTimeoutSeconds": 300,
		"asset":             cfg.Detect.AIPay.Asset,
	}
}

// emitPaymentRequired answers an AI crawler with an HTTP 402 carrying an
// x402 payment document. Crawlers that can pay retry with a signature and
// pass through aiPaymentValid on the next request.
func (h *Handler) emitPaymentRequired(w http.ResponseWriter, r *http.Request, reqID, bindID, ipStr, host, ua string) {
	cfg := h.config()
	h.recordEvent(r, reqID, bindID, ipStr, host, ua, requestlog.ActionPayment, "payment required", 0, nil)
	doc, _ := json.Marshal(map[string]any{
		"x402Version": 1,
		"error":       "Payment required",
		"accepts":     []any{h.paymentRequirements(r, cfg)},
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusPaymentRequired)
	_, _ = w.Write(doc)
}
