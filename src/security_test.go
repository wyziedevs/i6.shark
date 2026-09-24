package main

import (
	"net/http"
	"testing"
)

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
