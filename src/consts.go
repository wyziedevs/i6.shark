package main

import "time"

const (
	SharedSecret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // Secret between client & server
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

// headersToStripBeforeForwarding removes client identity headers
var headersToStripBeforeForwarding = map[string]bool{
	"cf-connecting-ip":  true,
	"cf-ipcountry":      true,
	"cf-ray":            true,
	"cf-visitor":        true,
	"cf-worker":         true,
	"cf-ew-via":         true,
	"x-forwarded-for":   true,
	"x-forwarded-proto": true,
	"cdn-loop":          true,
	"true-client-ip":    true,
	"x-real-ip":         true,
}
