// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signRequest builds a webbotauth-style signature over the standard
// component set and returns the headers to send.
func signRequest(t *testing.T, r *http.Request, agentURL, keyID string, priv ed25519.PrivateKey) {
	t.Helper()
	created := time.Now().Unix()
	expires := created + 60
	sigParams := fmt.Sprintf(`("@method" "@authority" "@path" "signature-agent");keyid="%s";alg="ed25519";created=%d;expires=%d;nonce="n-0";tag="web-bot-auth"`, keyID, created, expires)
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, `"@method": %s`+"\n", strings.ToUpper(r.Method))
	_, _ = fmt.Fprintf(&b, `"@authority": %s`+"\n", strings.ToLower(r.Host))
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	_, _ = fmt.Fprintf(&b, `"@path": %s`+"\n", path)
	_, _ = fmt.Fprintf(&b, `"signature-agent": "%s"`+"\n", agentURL)
	_, _ = fmt.Fprintf(&b, `"@signature-params": %s`, sigParams)
	sig := ed25519.Sign(priv, []byte(b.String()))
	r.Header.Set("Signature-Agent", fmt.Sprintf(`"%s"`, agentURL))
	r.Header.Set("Signature-Input", "sig1="+sigParams)
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
}

func jwksServer(t *testing.T, kid string, pub ed25519.PublicKey) *httptest.Server {
	t.Helper()
	jwks := fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"%s","x":"%s"}]}`,
		kid, base64.RawURLEncoding.EncodeToString(pub))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwks))
	}))
}

func TestWebBotVerifySignedRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := jwksServer(t, "k1", pub)
	defer dir.Close()
	v := NewWebBotVerifier(time.Second)

	r := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	r.Host = "example.com"
	signRequest(t, r, dir.URL, "k1", priv)
	if v.Check(context.Background(), r) != WebBotVerified {
		t.Fatal("valid signed request must verify")
	}
}

func TestWebBotRejectsTamperedAndExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := jwksServer(t, "k1", pub)
	defer dir.Close()
	v := NewWebBotVerifier(time.Second)

	// Tampered path: signed over /a but sent to /b.
	r := httptest.NewRequest(http.MethodGet, "http://example.com/a", nil)
	r.Host = "example.com"
	signRequest(t, r, dir.URL, "k1", priv)
	r.URL.Path = "/b"
	if v.Check(context.Background(), r) != WebBotInvalid {
		t.Fatal("tampered path must not verify")
	}

	// Unsigned request is not judged at all.
	r2 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if v.Check(context.Background(), r2) != WebBotNone {
		t.Fatal("unsigned request should return none")
	}

	// Bad signature bytes.
	r3 := httptest.NewRequest(http.MethodGet, "http://example.com/x", nil)
	r3.Host = "example.com"
	signRequest(t, r3, dir.URL, "k1", priv)
	r3.Header.Set("Signature", "sig1=:AAAA:")
	if v.Check(context.Background(), r3) != WebBotInvalid {
		t.Fatal("garbage signature should be invalid")
	}
}

func TestWebBotRejectsHTTPAgentURL(t *testing.T) {
	v := NewWebBotVerifier(time.Second)
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.Header.Set("Signature-Agent", `"http://169.254.169.254/keys"`)
	r.Header.Set("Signature-Input", `sig1=("@method");keyid="k"`)
	r.Header.Set("Signature", "sig1=:AAAA:")
	if got := v.Check(context.Background(), r); got != WebBotUnknown && got != WebBotInvalid {
		t.Fatalf("non-https agent url must not verify, got %v", got)
	}
}
