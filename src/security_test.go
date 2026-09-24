package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"0.0.0.0", "0.1.2.3", "127.0.0.1", "127.8.9.10", "10.0.0.1", "172.16.0.1",
		"172.31.255.255", "192.168.1.1", "100.64.0.1", "100.100.100.200",
		"169.254.169.254", "192.0.0.170", "198.18.0.1", "224.0.0.1", "240.0.0.1",
		"255.255.255.255",
		"::", "::1", "fe80::1", "fe80::1%eth0", "fc00::1", "fd00:ec2::254", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::127.0.0.1",
		"64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "2001:db8::1", "fec0::1",
	}
	allowed := []string{
		"1.1.1.1", "8.8.8.8", "104.16.132.229", "172.32.0.1", "100.128.0.1",
		"::ffff:8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888",
	}

	for _, s := range blocked {
		if !isBlockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range allowed {
		if isBlockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
	if !isBlockedIP(netip.Addr{}) {
		t.Error("the zero Addr should be blocked")
	}
}

func TestSelfPrefixesBlocked(t *testing.T) {
	saved := selfPrefixes
	t.Cleanup(func() { selfPrefixes = saved })

	selfPrefixes = []netip.Prefix{
		netip.MustParsePrefix("2a01:4f8:1234::/48"),
		netip.MustParsePrefix("9.9.9.9/32"),
	}
	for _, s := range []string{"2a01:4f8:1234:6000::1", "9.9.9.9", "::ffff:9.9.9.9"} {
		if !isBlockedIP(netip.MustParseAddr(s)) {
			t.Errorf("own address %s should be blocked", s)
		}
	}
	for _, s := range []string{"2a01:4f8:1235::1", "9.9.9.10"} {
		if isBlockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s is not ours and should be allowed", s)
		}
	}
}

func TestGuardedDialControl(t *testing.T) {
	cases := map[string]bool{ // address -> allowed
		"8.8.8.8:443":                true,
		"8.8.8.8:80":                 true,
		"[2606:4700:4700::1111]:443": true,
		"8.8.8.8:6379":               false,
		"[2606:4700:4700::1111]:22":  false,
		"127.0.0.1:80":               false,
		"127.0.0.1:3000":             false,
		"[::1]:443":                  false,
		"[fe80::1%eth0]:80":          false,
		"169.254.169.254:80":         false,
		"[::ffff:127.0.0.1]:80":      false,
		"not-an-address":             false,
	}
	for address, wantAllowed := range cases {
		err := guardedDialControl("tcp", address, nil)
		if wantAllowed && err != nil {
			t.Errorf("%s: unexpected error %v", address, err)
		}
		if !wantAllowed && !errors.Is(err, errBlockedDestination) {
			t.Errorf("%s: want errBlockedDestination, got %v", address, err)
		}
	}
}

func TestValidateTargetURL(t *testing.T) {
	cases := map[string]bool{ // URL -> allowed
		"https://example.com/sub.srt":             true,
		"http://example.com/":                     true,
		"http://example.com:8080/":                true,
		"https://example.com:2053/":               true,
		"https://1.1.1.1/":                        true,
		"ftp://example.com/":                      false,
		"file:///etc/passwd":                      false,
		"gopher://example.com:70/":                false,
		"http://example.com:6379/":                false,
		"http://example.com:99999/":               false,
		"http://127.0.0.1/":                       false,
		"http://127.0.0.1:3000/":                  false,
		"https://[::1]/":                          false,
		"http://[::ffff:127.0.0.1]/":              false,
		"http://169.254.169.254/latest/meta-data": false,
		"http://10.0.0.5/":                        false,
	}
	for raw, wantAllowed := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		err = validateTargetURL(u)
		if wantAllowed && err != nil {
			t.Errorf("%s: unexpected error %v", raw, err)
		}
		if !wantAllowed && !errors.Is(err, errBlockedDestination) {
			t.Errorf("%s: want errBlockedDestination, got %v", raw, err)
		}
	}
}

func TestCheckRedirect(t *testing.T) {
	public, _ := http.NewRequest(http.MethodGet, "https://example.com/next", nil)
	internal, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:3000/", nil)
	via := func(n int) []*http.Request { return make([]*http.Request, n) }

	for n := 1; n <= MaxRedirects; n++ {
		if err := checkRedirect(public, via(n)); err != nil {
			t.Errorf("redirect %d of %d should be followed, got %v", n, MaxRedirects, err)
		}
	}
	if err := checkRedirect(public, via(MaxRedirects+1)); err != http.ErrUseLastResponse {
		t.Errorf("redirect %d should stop the chain, got %v", MaxRedirects+1, err)
	}
	if err := checkRedirect(internal, via(1)); !errors.Is(err, errBlockedDestination) {
		t.Errorf("redirect to an internal URL should be refused, got %v", err)
	}
}

func TestClientsRefuseInternalTargets(t *testing.T) {
	var reached atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
	}))
	defer server.Close()

	clients := map[string]*http.Client{
		"default": newDefaultClient(),
		"pool":    createIPTracker("").client,
	}
	targets := []string{server.URL, "http://127.0.0.1:80/", "http://[::1]:443/", "http://localhost/"}
	for name, client := range clients {
		for _, target := range targets {
			resp, err := client.Get(target)
			if resp != nil {
				resp.Body.Close()
			}
			if !errors.Is(err, errBlockedDestination) {
				t.Errorf("%s client, %s: want errBlockedDestination, got %v", name, target, err)
			}
		}
	}
	if reached.Load() {
		t.Error("a guarded client reached the loopback test server")
	}
}

func TestBuildForwardedHeaders(t *testing.T) {
	incoming := http.Header{}
	for name, value := range map[string]string{
		"API-Token":        "secret-token",
		"CF-Connecting-IP": "203.0.113.9",
		"X-Forwarded-For":  "203.0.113.9",
		"X-Real-IP":        "203.0.113.9",
		"True-Client-IP":   "203.0.113.9",
		"Forwarded":        "for=203.0.113.9",
		"CF-Ray":           "abc",
		"CDN-Loop":         "cloudflare",
		"Connection":       "keep-alive, X-Requested-With",
		"Keep-Alive":       "timeout=5",
		"TE":               "trailers",
		"Content-Length":   "12",
		"X-Requested-With": "XMLHttpRequest",
		"User-Agent":       "Mozilla/5.0",
		"Accept":           "*/*",
		"X-User-Agent":     "VLSub 0.10.3",
		"Sec-Ch-Ua":        `"Chromium";v="137"`,
		"Sec-Fetch-Site":   "cross-site",
		"Referer":          "https://example.com/",
	} {
		incoming.Set(name, value)
	}
	custom := map[string]string{
		"CF-Connecting-IP": "127.0.0.1",
		"x-forwarded-for":  "127.0.0.1",
		"Host":             "localhost",
		"api-token":        "secret-token",
		"Origin":           "https://example.com",
	}

	got := buildForwardedHeaders(incoming, custom)

	want := []string{"User-Agent", "Accept", "X-User-Agent", "Sec-Ch-Ua", "Sec-Fetch-Site", "Referer", "Origin"}
	for _, name := range want {
		if got.Get(name) == "" {
			t.Errorf("%s should be forwarded", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("forwarded %d headers, want %d: %v", len(got), len(want), got)
	}
	if got.Get("Origin") != "https://example.com" {
		t.Errorf("custom Origin not applied: %q", got.Get("Origin"))
	}
}

func TestHandleRequestRefusesInternalTargets(t *testing.T) {
	savedClient := defaultClient
	t.Cleanup(func() { defaultClient = savedClient })
	defaultClient = newDefaultClient()

	userAgent := "Mozilla/5.0 (test)"
	cases := []struct {
		method, target string
		wantStatus     int
	}{
		{http.MethodPut, "https://example.com/", http.StatusMethodNotAllowed},
		{http.MethodGet, "http://127.0.0.1:3000/", http.StatusForbidden},
		{http.MethodGet, "http://169.254.169.254/latest/meta-data/", http.StatusForbidden},
		{http.MethodGet, "http://localhost/", http.StatusForbidden}, // hostname resolving to loopback
		{http.MethodGet, "ftp://example.com/", http.StatusForbidden},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "/?url="+url.QueryEscape(c.target)+"&normal", nil)
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("API-Token", testToken(userAgent, SharedSecret))
		rec := httptest.NewRecorder()
		handleRequest(rec, req)
		if rec.Code != c.wantStatus {
			t.Errorf("%s %s: status %d, want %d (%s)", c.method, c.target, rec.Code, c.wantStatus, rec.Body.String())
		}
	}
}

func TestEnsureURLHasScheme(t *testing.T) {
	cases := map[string]string{
		"example.com/sub.srt":             "https://example.com/sub.srt",
		"example.com/r?to=http://x.test/": "https://example.com/r?to=http://x.test/",
		"https://example.com/":            "https://example.com/",
		"HTTP://example.com/":             "HTTP://example.com/",
		"ftp://example.com/":              "ftp://example.com/",
		"://example.com/":                 "https://://example.com/",
	}
	for in, want := range cases {
		if got := ensureURLHasScheme(in); got != want {
			t.Errorf("ensureURLHasScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

// testToken mirrors the client side (proxy.ts deriveToken): HMAC-SHA256 keyed
// by the User-Agent over the shared secret, hex encoded.
func testToken(userAgent, secret string) string {
	h := hmac.New(sha256.New, []byte(userAgent))
	h.Write([]byte(secret))
	return hex.EncodeToString(h.Sum(nil))
}
