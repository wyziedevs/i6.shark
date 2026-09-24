# i6.shark

An IPv6 proxy server that allows you to make HTTP requests from randomly generated IPv6 addresses in a /48 subnet. This project basically built the best proxy on earth, a /48 subnet has `1,208,925,819,614,629,174,706,176` (1.2 × 10²⁴) IPv6 addresses, which if you can't tell is a lot. Using a single subnet means those who really want to block you can block your ASN address, so be careful with that. This project is designed to be used for educational purposes only, and should not be used for any illegal activities (totally).

Docs moved to [docs.wyzie.io](https://docs.wyzie.io/i6shark/intro).

## What gets proxied

- Methods: `GET`, `HEAD` and `POST` only.
- Targets: `http`/`https` URLs on port 80, 443 or one of Cloudflare's other HTTP(S) ports (8080, 8880, 2052, 2082, 2086, 2095, 8443, 2053, 2083, 2087, 2096).
- Destinations: every connection, including each redirect (at most 5), is checked after DNS resolution. Loopback, private, CGNAT, link-local (cloud metadata), ULA, multicast, reserved and documentation ranges, IPv4-mapped forms of those, this host's own addresses and the configured /48 are refused with `403`.
- Headers: only an allowlist is forwarded (`Accept*`, `User-Agent`, `Content-Type`, `Origin`, `Referer`, `Cookie`, `X-Requested-With`, `X-User-Agent`, `Cache-Control`, `Pragma`, `Range`, `If-None-Match`, `If-Modified-Since`, `Sec-Ch-Ua*`, `Sec-Fetch-*`), after merging the optional `headers=` JSON parameter. `API-Token`, `Host`, hop-by-hop headers and client identity headers (`CF-*`, `X-Forwarded-*`, `X-Real-IP`, `True-Client-IP`, `Forwarded`) are never sent upstream.
