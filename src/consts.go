package main

import "time"

const (
	SharedSecret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // Fallback only; set I6_SHARED_SECRET instead
	Version      = "3.1"                              // Version of the script
	IPv6Prefix   = "xxxx:xxxx:xxxx"                   // Your /48 prefix
	IPv6Subnet   = "6000"                             // Using subnet 6000 within your /48
	Interface    = "ens3"                             // Network interface
	ListenPort   = 80                                 // Proxy server port
	ListenHost   = "0.0.0.0"                          // Listen on all interfaces
	Debug        = false                              // Enable debug output

	// Timeouts
	RequestTimeout      = 30 * time.Second
	DialTimeout         = 8 * time.Second
	KeepAliveInterval   = 30 * time.Second
	TLSHandshakeTimeout = 5 * time.Second
	IdleConnTimeout     = 120 * time.Second
	ServerReadTimeout   = 30 * time.Second
	ServerWriteTimeout  = 120 * time.Second
	ServerIdleTimeout   = 120 * time.Second
	ServerHeaderTimeout = 10 * time.Second
	IPAddTimeout        = 2 * time.Second

	// IP pool sizing
	DesiredPoolSize    = 750
	PoolAddBatchSize   = 75
	MaxRequestsPerIP   = 500
	MaxConcurrentPerIP = 100

	// Pool management intervals
	PoolManageInterval    = 500 * time.Millisecond
	IPFlushInterval       = 1 * time.Hour
	UnusedIPFlushInterval = 10 * time.Minute
	IPInactivityThreshold = 30 * time.Minute

	// I/O
	BufferSize    = 256 * 1024 // 256KB buffer for I/O operations
	MaxHeaderSize = 1 << 20    // 1MB max header size

	// Connection pool sizing
	DefaultMaxIdleConns        = 2000
	DefaultMaxIdleConnsPerHost = 150
	PerIPMaxIdleConns          = 300
	PerIPMaxIdleConnsPerHost   = 40

	// Concurrency limits
	IPAddConcurrency   = 20 // Concurrent IP additions to interface
	IPFlushConcurrency = 30 // Concurrent IP removals from interface
	UrgentAddChanSize  = 20

	// Security
	SharedSecretEnv = "I6_SHARED_SECRET" // Env var holding the shared secret (overrides SharedSecret)
	MaxRedirects    = 5                  // Redirects followed per proxied request
)

// FAMILY_V6 is AF_INET6 used by netlink
const FAMILY_V6 = 10

// skipHeaders are hop-by-hop headers that should not be forwarded
var skipHeaders = map[string]bool{
	"transfer-encoding": true,
	"connection":        true,
	"keep-alive":        true,
	"server":            true,
}

// allowedMethods are the only request methods the proxy forwards
var allowedMethods = map[string]bool{
	"GET":  true,
	"HEAD": true,
	"POST": true,
}

// forwardedHeaderAllowlist is the set of request headers (lowercase) passed
// on to the target; Sec-Ch-Ua* and Sec-Fetch-* are allowed by prefix in
// isForwardableHeader. Everything else is dropped, notably API-Token, Host,
// hop-by-hop headers and client identity headers (CF-*, X-Forwarded-*,
// X-Real-IP, True-Client-IP, Forwarded).
var forwardedHeaderAllowlist = map[string]bool{
	"accept":            true,
	"accept-encoding":   true,
	"accept-language":   true,
	"cache-control":     true,
	"content-type":      true,
	"cookie":            true,
	"if-modified-since": true,
	"if-none-match":     true,
	"origin":            true,
	"pragma":            true,
	"range":             true,
	"referer":           true,
	"user-agent":        true,
	"x-requested-with":  true,
	"x-user-agent":      true, // OpenSubtitles identifies API clients by it
}

// allowedPorts are the destination ports the proxy connects to: 80/443 plus
// the other HTTP(S) ports Cloudflare proxies, so sites on those still work
// while mail, database, SSH, etc. ports are never reachable through the proxy.
var allowedPorts = map[uint16]bool{
	80: true, 8080: true, 8880: true, 2052: true, 2082: true, 2086: true, 2095: true,
	443: true, 8443: true, 2053: true, 2083: true, 2087: true, 2096: true,
}
