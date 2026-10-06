// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// WebBotVerdict is the outcome of Web Bot Authentication signature
// verification (draft-ietf-webbotauth-httpsig-protocol).
type WebBotVerdict int

const (
	// WebBotNone means the request carries no Signature-Agent header.
	WebBotNone WebBotVerdict = iota
	// WebBotInvalid means signature headers were present but malformed,
	// expired, or failed cryptographic verification.
	WebBotInvalid
	// WebBotVerified means the request signature verifies against the key
	// directory published at the Signature-Agent URL.
	WebBotVerified
	// WebBotUnknown means verification could not complete, for example a
	// key directory fetch failure. Callers should fail open.
	WebBotUnknown
)

const (
	maxWebBotKeyCache = 2048
	maxJWKSBody       = 64 << 10
	wbaClockSkew      = 30 * time.Second
)

// WebBotVerifier validates HTTP Message Signatures per the webbotauth
// draft. Key directories are fetched over HTTPS, cached, and looked up
// once per agent URL thanks to singleflight.
type WebBotVerifier struct {
	timeout  time.Duration
	client   *http.Client
	inflight singleflight.Group
	now      func() time.Time
	cache    sync.Map
	size     atomic.Int64
}

type webBotCacheEntry struct {
	keys    map[string]ed25519.PublicKey
	expires time.Time
}

// NewWebBotVerifier builds a verifier. timeout bounds directory fetches
// and clock checks.
func NewWebBotVerifier(timeout time.Duration) *WebBotVerifier {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &WebBotVerifier{
		timeout: timeout,
		client: &http.Client{
			Timeout:   timeout * 2,
			Transport: &http.Transport{DisableKeepAlives: false, MaxIdleConns: 64},
		},
		now: time.Now,
	}
}

// Check verifies a request. It only inspects requests that present a
// Signature-Agent header, and returns WebBotNone otherwise.
func (v *WebBotVerifier) Check(ctx context.Context, r *http.Request) WebBotVerdict {
	if v == nil {
		return WebBotUnknown
	}
	agent := parseSignatureAgent(r.Header.Get("Signature-Agent"))
	if agent == "" {
		return WebBotNone
	}
	sig, err := v.verify(ctx, r, agent)
	if err != nil {
		return sig
	}
	return WebBotVerified
}

func (v *WebBotVerifier) verify(ctx context.Context, r *http.Request, agent string) (WebBotVerdict, error) {
	params, comps, ok := parseSignatureInput(r.Header.Get("Signature-Input"))
	if !ok {
		return WebBotInvalid, fmt.Errorf("bad signature-input")
	}
	sigB64, ok := parseSignatureHeader(r.Header.Get("Signature"))
	if !ok {
		return WebBotInvalid, fmt.Errorf("bad signature")
	}
	if params.alg != "" && !strings.EqualFold(params.alg, "ed25519") {
		return WebBotInvalid, fmt.Errorf("unsupported alg %q", params.alg)
	}
	now := v.now()
	if params.expires > 0 && now.After(time.Unix(params.expires, 0).Add(wbaClockSkew)) {
		return WebBotInvalid, fmt.Errorf("signature expired")
	}
	if params.created > 0 && time.Unix(params.created, 0).After(now.Add(wbaClockSkew)) {
		return WebBotInvalid, fmt.Errorf("signature created in future")
	}
	base, ok := signatureBase(r, comps, params)
	if !ok {
		return WebBotUnknown, fmt.Errorf("unsupported covered components")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return WebBotInvalid, fmt.Errorf("bad signature bytes")
	}
	keys, ok := v.keys(ctx, agent)
	if !ok {
		return WebBotUnknown, fmt.Errorf("key directory fetch failed")
	}
	pub, ok := keys[params.keyid]
	if !ok {
		return WebBotInvalid, fmt.Errorf("keyid %q not in directory", params.keyid)
	}
	if !ed25519.Verify(pub, []byte(base), sig) {
		return WebBotInvalid, fmt.Errorf("verify failed")
	}
	return WebBotVerified, nil
}

// keys returns the directory key set for an agent URL, cached and shared
// across concurrent checks via singleflight.
func (v *WebBotVerifier) keys(ctx context.Context, agent string) (map[string]ed25519.PublicKey, bool) {
	now := v.now()
	if e, hit := v.cache.Load(agent); hit {
		ent := e.(webBotCacheEntry)
		if now.Before(ent.expires) {
			return ent.keys, len(ent.keys) > 0
		}
		v.cache.CompareAndDelete(agent, e)
	}
	out, _, _ := v.inflight.Do(agent, func() (any, error) {
		keys, err := v.fetchKeys(context.WithoutCancel(ctx), agent)
		ttl := time.Hour
		if err != nil || len(keys) == 0 {
			ttl = 5 * time.Minute
			v.cache.Store(agent, webBotCacheEntry{keys: keys, expires: v.now().Add(ttl)})
			return keys, err
		}
		v.cache.Store(agent, webBotCacheEntry{keys: keys, expires: v.now().Add(ttl)})
		if v.size.Add(1) > maxWebBotKeyCache {
			v.sweep()
		}
		return keys, nil
	})
	keys, _ := out.(map[string]ed25519.PublicKey)
	return keys, len(keys) > 0
}

// fetchKeys retrieves the key directory at agent. The URL must be HTTPS,
// or HTTP on loopback for local testing. Bodies are size-bounded.
func (v *WebBotVerifier) fetchKeys(ctx context.Context, agent string) (map[string]ed25519.PublicKey, error) {
	u, err := url.Parse(agent)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("bad agent url")
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("agent url must be https")
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agent, nil) // #nosec G704 -- agent directory scheme and host are guarded above
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req) // #nosec G704 -- agent directory scheme and host are guarded above
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBody+1))
	if err != nil || len(body) > maxJWKSBody {
		return nil, fmt.Errorf("directory body too large")
	}
	return parseJWKS(body)
}

func (v *WebBotVerifier) sweep() {
	now := v.now()
	n := int64(0)
	v.cache.Range(func(k, e any) bool {
		if now.After(e.(webBotCacheEntry).expires) {
			v.cache.Delete(k)
		} else {
			n++
		}
		return true
	})
	v.size.Store(n)
}

// parseSignatureAgent extracts the URL member from a structured field
// string like "https://bot.example";keyid="k". The directory URL itself
// is the identity.
func parseSignatureAgent(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if h[0] == '"' {
		if i := strings.IndexByte(h[1:], '"'); i >= 0 {
			return h[1 : 1+i]
		}
	}
	if i := strings.IndexByte(h, ';'); i >= 0 {
		return strings.TrimSpace(h[:i])
	}
	return h
}

type wbaParams struct {
	keyid   string
	alg     string
	created int64
	expires int64
	nonce   string
	tag     string
}

// parseSignatureInput extracts the first dictionary member of the
// Signature-Input header: the covered component list and its params.
// Grammar: sig=("@method" "@path");keyid="k";alg="ed25519";created=1
func parseSignatureInput(h string) (wbaParams, []string, bool) {
	var p wbaParams
	open := strings.IndexByte(h, '(')
	if open < 0 {
		return p, nil, false
	}
	closeIdx := strings.IndexByte(h[open:], ')')
	if closeIdx < 0 {
		return p, nil, false
	}
	closeIdx += open
	compsField := h[open+1 : closeIdx]
	var comps []string
	for _, c := range strings.Fields(compsField) {
		c = strings.Trim(c, `"`)
		if c == "" {
			continue
		}
		comps = append(comps, strings.ToLower(c))
	}
	if len(comps) == 0 {
		return p, nil, false
	}
	for _, kv := range strings.Split(h[closeIdx+1:], ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, found := strings.Cut(kv, "=")
		if !found {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "keyid":
			p.keyid = v
		case "alg":
			p.alg = v
		case "created":
			p.created, _ = strconv.ParseInt(v, 10, 64)
		case "expires":
			p.expires, _ = strconv.ParseInt(v, 10, 64)
		case "nonce":
			p.nonce = v
		case "tag":
			p.tag = v
		}
	}
	return p, comps, true
}

// parseSignatureHeader pulls the base64 signature from the first
// dictionary member: sig1=:AAEC:
func parseSignatureHeader(h string) (string, bool) {
	for _, part := range strings.Split(h, ",") {
		_, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, ":") && strings.HasSuffix(v, ":") && len(v) > 2 {
			return v[1 : len(v)-1], true
		}
	}
	return "", false
}

// signatureBase builds the RFC 9421 signature base string for the
// covered components. Returns false on a component this implementation
// cannot serialize.
func signatureBase(r *http.Request, comps []string, p wbaParams) (string, bool) {
	var b strings.Builder
	for _, c := range comps {
		var val string
		switch c {
		case "@method":
			val = strings.ToUpper(r.Method)
		case "@authority":
			val = strings.ToLower(r.Host)
		case "@path":
			val = r.URL.Path
			if val == "" {
				val = "/"
			}
		case "@query":
			val = "?"
			if r.URL.RawQuery != "" {
				val += r.URL.RawQuery
			}
		case "@scheme":
			val = "http"
			if r.TLS != nil {
				val = "https"
			}
		case "@request-target":
			val = r.URL.RequestURI()
		case "@target-uri":
			val = r.URL.Scheme + "://" + r.Host + r.URL.RequestURI()
		case "signature-agent":
			val = r.Header.Get("Signature-Agent")
		case "@query-param", "@status":
			return "", false
		default:
			if strings.HasPrefix(c, "@") {
				return "", false
			}
			val = strings.Join(r.Header.Values(c), ", ")
			if val == "" && r.Header.Get(c) == "" {
				return "", false
			}
		}
		b.WriteString(`"` + c + `": `)
		b.WriteString(val)
		b.WriteByte('\n')
	}
	var pb strings.Builder
	pb.WriteString(`"@signature-params": (`)
	for i, c := range comps {
		if i > 0 {
			pb.WriteByte(' ')
		}
		pb.WriteByte('"')
		pb.WriteString(c)
		pb.WriteByte('"')
	}
	pb.WriteByte(')')
	if p.keyid != "" {
		pb.WriteString(`;keyid="` + p.keyid + `"`)
	}
	if p.alg != "" {
		pb.WriteString(`;alg="` + p.alg + `"`)
	}
	if p.created != 0 {
		fmt.Fprintf(&pb, ";created=%d", p.created)
	}
	if p.expires != 0 {
		fmt.Fprintf(&pb, ";expires=%d", p.expires)
	}
	if p.nonce != "" {
		pb.WriteString(`;nonce="` + p.nonce + `"`)
	}
	if p.tag != "" {
		pb.WriteString(`;tag="` + p.tag + `"`)
	}
	b.WriteString(pb.String())
	return b.String(), true
}

// parseJWKS decodes a JWKS or a bare JWK into a keyid->public-key map.
func parseJWKS(body []byte) (map[string]ed25519.PublicKey, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
		Kty  string            `json:"kty"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	keys := doc.Keys
	if doc.Kty != "" {
		keys = []json.RawMessage{json.RawMessage(body)}
	}
	out := make(map[string]ed25519.PublicKey, len(keys))
	for _, raw := range keys {
		var k struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Use string `json:"use"`
		}
		if err := json.Unmarshal(raw, &k); err != nil {
			continue
		}
		if k.Kty != "OKP" || !strings.EqualFold(k.Crv, "Ed25519") || k.X == "" {
			continue
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(xb) != ed25519.PublicKeySize {
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = thumbprint(xb)
		}
		out[kid] = ed25519.PublicKey(xb)
	}
	return out, nil
}

// thumbprint is a stable keyid fallback for directory keys that omit kid.
func thumbprint(pub []byte) string {
	sum := make([]byte, 8)
	// Cheap deterministic key-id: first 8 bytes of an xor-folded key.
	for i, b := range pub {
		sum[i%8] ^= b
	}
	return base64.RawURLEncoding.EncodeToString(sum)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
