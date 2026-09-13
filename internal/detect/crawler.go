// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/Quad4-Software/ravenguard/internal/faststr"
)

// CrawlerVerdict is the outcome of a claimed-crawler verification.
type CrawlerVerdict int

const (
	// CrawlerNotClaimed means the User-Agent does not match a verifiable crawler.
	CrawlerNotClaimed CrawlerVerdict = iota
	// CrawlerUnknown means verification was inconclusive (DNS error or timeout).
	// Callers should fail open and take no action.
	CrawlerUnknown
	// CrawlerVerified means the source IP is forward-confirmed to the claimed
	// crawler operator.
	CrawlerVerified
	// CrawlerSpoofed means the User-Agent claims a crawler the source IP does
	// not belong to. Spoofing a trusted crawler identity is hostile.
	CrawlerSpoofed
)

// crawlerSpec maps a User-Agent substring to the reverse-DNS suffixes the
// operator publishes for its crawlers. Only crawlers with documented
// verifiable rDNS are listed; operators that publish IP ranges instead
// (OpenAI, Anthropic, Perplexity) cannot be checked this way.
type crawlerSpec struct {
	uaSub    string
	suffixes []string
}

// Substrings are chosen to avoid matching real browsers. Yandex Browser and
// Sogou browser UAs contain yandex/sogou tokens without claiming to be bots,
// so only explicit bot product tokens are listed.
var crawlerSpecs = []crawlerSpec{
	{"googlebot", []string{"googlebot.com", "google.com"}},
	{"google-inspectiontool", []string{"googlebot.com", "google.com"}},
	{"googleother", []string{"googlebot.com", "google.com"}},
	{"adsbot-google", []string{"google.com"}},
	{"mediapartners-google", []string{"google.com"}},
	{"feedfetcher-google", []string{"google.com"}},
	{"apis-google", []string{"google.com"}},
	{"google-read-aloud", []string{"google.com"}},
	{"bingbot", []string{"search.msn.com"}},
	{"bingpreview", []string{"search.msn.com"}},
	{"adidxbot", []string{"search.msn.com"}},
	{"duckduckbot", []string{"duckduckgo.com"}},
	{"duckassistbot", []string{"duckduckgo.com"}},
	{"baiduspider", []string{"baidu.com", "baidu.jp"}},
	{"yandexbot", []string{"yandex.ru", "yandex.net", "yandex.com"}},
	{"yandexmobilebot", []string{"yandex.ru", "yandex.net", "yandex.com"}},
	{"yandeximages", []string{"yandex.ru", "yandex.net", "yandex.com"}},
	{"yandexmetrika", []string{"yandex.ru", "yandex.net", "yandex.com"}},
	{"yandexaccessibilitybot", []string{"yandex.ru", "yandex.net", "yandex.com"}},
	{"applebot", []string{"applebot.apple.com"}},
	{"qwantify", []string{"qwant.com"}},
	{"exabot", []string{"exabot.com"}},
	{"sogou web spider", []string{"sogou.com"}},
	{"sogou inst spider", []string{"sogou.com"}},
	{"seznambot", []string{"seznam.cz"}},
	{"mj12bot", []string{"majestic12.co.uk", "majestic.com"}},
	{"dotbot", []string{"moz.com"}},
}

// maxCrawlerCache bounds cached verdicts. Once exceeded, expired entries are
// swept and, if still over, a fraction of live entries is evicted so a
// distributed spoofing flood cannot grow the map without limit.
const maxCrawlerCache = 1 << 16

type crawlerEntry struct {
	verdict CrawlerVerdict
	expires time.Time
}

// CrawlerVerifier performs forward-confirmed reverse DNS (FCrDNS) checks for
// requests whose User-Agent claims a well-known crawler identity. Results are
// cached per source IP and claimed identity, and lookups share a bounded
// timeout so a hostile or slow resolver cannot stall the request path.
type CrawlerVerifier struct {
	timeout   time.Duration
	posTTL    time.Duration
	negTTL    time.Duration
	unkTTL    time.Duration
	cache     sync.Map // spec|ip string -> crawlerEntry
	size      atomic.Int64
	inflight  singleflight.Group
	resolver  crawlerResolver
	now       func() time.Time
	specMatch func(string) (crawlerSpec, bool)
}

type crawlerResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

type netResolver struct{}

func (netResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

func (netResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// NewCrawlerVerifier builds a verifier. timeout bounds each verification;
// posTTL and negTTL are the cache lifetimes for verified and spoofed results.
func NewCrawlerVerifier(timeout, posTTL, negTTL time.Duration) *CrawlerVerifier {
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	if posTTL <= 0 {
		posTTL = 24 * time.Hour
	}
	if negTTL <= 0 {
		negTTL = time.Hour
	}
	return &CrawlerVerifier{
		timeout:   timeout,
		posTTL:    posTTL,
		negTTL:    negTTL,
		unkTTL:    5 * time.Minute,
		resolver:  netResolver{},
		now:       time.Now,
		specMatch: matchCrawlerSpec,
	}
}

// MatchCrawler reports whether ua claims a verifiable crawler identity.
func MatchCrawler(ua string) bool {
	_, ok := matchCrawlerSpec(ua)
	return ok
}

func matchCrawlerSpec(ua string) (crawlerSpec, bool) {
	if ua == "" {
		return crawlerSpec{}, false
	}
	bp := lowerPool.Get().(*[]byte)
	low := faststr.AppendLowerASCII((*bp)[:0], ua)
	for _, spec := range crawlerSpecs {
		if faststr.ContainsBytes(low, spec.uaSub) {
			*bp = low[:0]
			lowerPool.Put(bp)
			return spec, true
		}
	}
	*bp = low[:0]
	lowerPool.Put(bp)
	return crawlerSpec{}, false
}

// Check verifies a claimed crawler identity for ip. Results are cached per
// IP and claimed identity, and concurrent checks for the same pair share one
// lookup.
func (v *CrawlerVerifier) Check(ctx context.Context, ip net.IP, ua string) CrawlerVerdict {
	if v == nil || ip == nil {
		return CrawlerUnknown
	}
	spec, ok := v.specMatch(ua)
	if !ok {
		return CrawlerNotClaimed
	}
	key := spec.uaSub + "|" + ip.String()
	now := v.now()
	if e, hit := v.cache.Load(key); hit {
		ent := e.(crawlerEntry)
		if now.Before(ent.expires) {
			return ent.verdict
		}
		if v.cache.CompareAndDelete(key, e) {
			v.size.Add(-1)
		}
	}
	out, _, _ := v.inflight.Do(key, func() (any, error) {
		// Detach from the caller's request context so a client disconnect does
		// not abort the lookup for other waiters or poison the cache.
		verdict := v.verify(context.WithoutCancel(ctx), ip, spec)
		ttl := v.unkTTL
		switch verdict {
		case CrawlerVerified:
			ttl = v.posTTL
		case CrawlerSpoofed:
			ttl = v.negTTL
		}
		v.cache.Store(key, crawlerEntry{verdict: verdict, expires: v.now().Add(ttl)})
		if v.size.Add(1) > maxCrawlerCache {
			v.sweep()
		}
		return verdict, nil
	})
	return out.(CrawlerVerdict)
}

// sweep trims the verdict cache once it grows past maxCrawlerCache. Expired
// entries go first; if the map is still oversized a slice of live entries is
// evicted to keep memory bounded. The size counter is approximate (re-stores
// of a live key inflate it slightly), which only makes the sweep run a bit
// early.
func (v *CrawlerVerifier) sweep() {
	now := v.now()
	n := int64(0)
	v.cache.Range(func(k, e any) bool {
		if now.After(e.(crawlerEntry).expires) {
			v.cache.Delete(k)
		} else {
			n++
		}
		return true
	})
	if n <= maxCrawlerCache {
		v.size.Store(n)
		return
	}
	// Still oversized: evict arbitrary entries until roughly three quarters of
	// the bound remain. sync.Map iteration order is unspecified, which is fine
	// since any verdict can be recomputed.
	target := int64(maxCrawlerCache * 3 / 4)
	v.cache.Range(func(k, _ any) bool {
		if n > target {
			v.cache.Delete(k)
			n--
		}
		return true
	})
	v.size.Store(n)
}

// verify runs the two-step FCrDNS check: reverse-resolve the IP to names,
// keep names under an operator suffix, then forward-confirm that at least one
// resolves back to the source IP.
func (v *CrawlerVerifier) verify(ctx context.Context, ip net.IP, spec crawlerSpec) CrawlerVerdict {
	lctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	names, err := v.resolver.LookupAddr(lctx, ip.String())
	if err != nil {
		return CrawlerUnknown
	}
	sawSuffix := false
	sawForward := false
	for _, raw := range names {
		name := strings.TrimSuffix(strings.ToLower(raw), ".")
		if !suffixAllowed(name, spec.suffixes) {
			continue
		}
		sawSuffix = true
		ips, err := v.resolver.LookupIP(lctx, name)
		if err != nil {
			continue
		}
		for _, a := range ips {
			if a.Equal(ip) {
				return CrawlerVerified
			}
		}
		sawForward = true
	}
	if !sawSuffix {
		// The claimed operator always publishes PTR records for its crawlers;
		// none here means the claim is fabricated.
		return CrawlerSpoofed
	}
	if !sawForward {
		// Every suffix-matching name failed to resolve; treat as inconclusive
		// rather than accusing on a resolver hiccup.
		return CrawlerUnknown
	}
	return CrawlerSpoofed
}

func suffixAllowed(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}
