package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
)

// IPUsageTracker tracks usage statistics for each IP address
type IPUsageTracker struct {
	requestCount atomic.Int32    // Number of requests made with this IP
	lastUsed     atomic.Int64    // Last time this IP was used (Unix nano)
	inUseCount   atomic.Int32    // Number of ongoing requests using this IP
	transport    *http.Transport // Cached transport for this IP
	client       *http.Client    // Cached client for this IP
	IP           string          // The IPv6 address
	Added        time.Time       // When this IP was added to the pool
}

func (t *IPUsageTracker) GetRequestCount() int32 { return t.requestCount.Load() }
func (t *IPUsageTracker) GetInUseCount() int32   { return t.inUseCount.Load() }
func (t *IPUsageTracker) GetLastUsed() time.Time { return time.Unix(0, t.lastUsed.Load()) }
func (t *IPUsageTracker) IncrementRequestCount() { t.requestCount.Add(1) }
func (t *IPUsageTracker) UpdateLastUsed()        { t.lastUsed.Store(time.Now().UnixNano()) }
func (t *IPUsageTracker) AcquireUse() bool {
	for {
		current := t.inUseCount.Load()
		if current >= MaxConcurrentPerIP {
			return false
		}
		if t.inUseCount.CompareAndSwap(current, current+1) {
			return true
		}
	}
}
func (t *IPUsageTracker) ReleaseUse() { t.inUseCount.Add(-1) }

var (
	requestCount   atomic.Int64
	defaultClient  *http.Client
	ipPool         atomic.Pointer[[]*IPUsageTracker]
	poolWriteMutex sync.Mutex
	currentIndex   atomic.Uint32
	urgentAddChan  = make(chan struct{}, UrgentAddChanSize)
	cachedLink     atomic.Pointer[netlink.Link] // Cache the netlink handle
)

var bufferPool = sync.Pool{New: func() interface{} {
	b := make([]byte, BufferSize)
	return &b
}}

// getLink returns the cached netlink handle, refreshing if needed
func getLink() (netlink.Link, error) {
	if link := cachedLink.Load(); link != nil {
		return *link, nil
	}
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		return nil, err
	}
	cachedLink.Store(&link)
	return link, nil
}

// createTransportForIP creates a transport for a specific source IP
func createTransportForIP(sourceIP net.IP) *http.Transport {
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: sourceIP, Port: 0},
		Timeout:   DialTimeout,
		KeepAlive: KeepAliveInterval,
	}
	return &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          PerIPMaxIdleConns,
		MaxIdleConnsPerHost:   PerIPMaxIdleConnsPerHost,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       IdleConnTimeout,
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		ResponseHeaderTimeout: RequestTimeout,
		DisableKeepAlives:     false,
		DisableCompression:    true,
		WriteBufferSize:       BufferSize,
		ReadBufferSize:        BufferSize,
	}
}

func createIPTracker(ip string) *IPUsageTracker {
	parsedIP := net.ParseIP(ip)
	transport := createTransportForIP(parsedIP)
	return &IPUsageTracker{
		IP:        ip,
		Added:     time.Now(),
		transport: transport,
		client: &http.Client{
			Transport: transport,
			Timeout:   RequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func normalizeIPv6(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	return ip.String()
}

func randomIPv6() string {
	hostPart1 := rand.Uint32()
	hostPart2 := rand.Uint32()

	rawIP := fmt.Sprintf("%s:%s:%x:%x:%x:%x",
		IPv6Prefix, IPv6Subnet,
		(hostPart1>>16)&0xFFFF, hostPart1&0xFFFF,
		(hostPart2>>16)&0xFFFF, hostPart2&0xFFFF)

	ip := net.ParseIP(rawIP)
	if ip == nil {
		return fmt.Sprintf("%s:%s:%04x:%04x:%04x:%04x",
			IPv6Prefix, IPv6Subnet,
			(hostPart1>>16)&0xFFFF, hostPart1&0xFFFF,
			(hostPart2>>16)&0xFFFF, hostPart2&0xFFFF)
	}
	return ip.String()
}

func addIPv6ToInterface(ipv6 string) bool {
	done := make(chan bool, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- false
			}
		}()

		link, err := getLink()
		if err != nil {
			done <- false
			return
		}

		addr, err := netlink.ParseAddr(ipv6 + "/128")
		if err != nil {
			done <- false
			return
		}

		err = netlink.AddrAdd(link, addr)
		if err != nil {
			if err.Error() == "file exists" {
				done <- true
				return
			}
			done <- false
			return
		}
		done <- true
	}()

	select {
	case result := <-done:
		return result
	case <-time.After(IPAddTimeout):
		return false
	}
}

func removeIPv6FromInterface(ipv6 string) bool {
	link, err := getLink()
	if err != nil {
		return false
	}

	addr, err := netlink.ParseAddr(ipv6 + "/128")
	if err != nil {
		return false
	}

	err = netlink.AddrDel(link, addr)
	if err == nil {
		return true
	}
	if strings.Contains(err.Error(), "cannot assign requested address") ||
		strings.Contains(err.Error(), "no such file or directory") {
		return true
	}
	return false
}

func flushAllIPAddresses() {
	link, err := getLink()
	if err != nil {
		return
	}

	addrs, err := netlink.AddrList(link, FAMILY_V6)
	if err != nil {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, IPFlushConcurrency)

	for _, addr := range addrs {
		ipStr := addr.IP.String()
		if strings.HasPrefix(ipStr, IPv6Prefix+":") && !strings.Contains(ipStr, "::") {
			wg.Add(1)
			go func(address netlink.Addr) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				netlink.AddrDel(link, &address)
			}(addr)
		}
	}

	wg.Wait()

	poolWriteMutex.Lock()
	newPool := make([]*IPUsageTracker, 0, DesiredPoolSize)
	ipPool.Store(&newPool)
	currentIndex.Store(0)
	poolWriteMutex.Unlock()
}

func periodicIPFlush() {
	ticker := time.NewTicker(IPFlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		flushAllIPAddresses()
	}
}

func flushUnusedIPs() {
	poolWriteMutex.Lock()
	defer poolWriteMutex.Unlock()

	pool := ipPool.Load()
	if pool == nil || len(*pool) == 0 {
		return
	}

	now := time.Now()
	var ipsToRemove []string
	newPool := make([]*IPUsageTracker, 0, len(*pool))

	for _, tracker := range *pool {
		if tracker.GetInUseCount() > 0 {
			newPool = append(newPool, tracker)
			continue
		}

		lastUsed := tracker.GetLastUsed()
		var inactiveTime time.Duration
		if lastUsed.IsZero() || lastUsed.Unix() == 0 {
			inactiveTime = now.Sub(tracker.Added)
		} else {
			inactiveTime = now.Sub(lastUsed)
		}

		if inactiveTime > IPInactivityThreshold && tracker.GetRequestCount() < MaxRequestsPerIP {
			ipsToRemove = append(ipsToRemove, tracker.IP)
			tracker.transport.CloseIdleConnections()
		} else {
			newPool = append(newPool, tracker)
		}
	}

	ipPool.Store(&newPool)

	if len(ipsToRemove) > 0 {
		go func(toRemove []string) {
			for _, ip := range toRemove {
				removeIPv6FromInterface(ip)
			}
		}(ipsToRemove)
	}
}

func periodicUnusedIPFlush() {
	ticker := time.NewTicker(UnusedIPFlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		flushUnusedIPs()
	}
}

func cleanupWrongSubnetIPs() {
	link, err := getLink()
	if err != nil {
		return
	}

	addrs, err := netlink.AddrList(link, FAMILY_V6)
	if err != nil {
		return
	}

	expectedPrefix := IPv6Prefix + ":" + IPv6Subnet + ":"
	var wg sync.WaitGroup

	for _, addr := range addrs {
		ipStr := addr.IP.String()
		if strings.HasPrefix(ipStr, IPv6Prefix+":") && !strings.Contains(ipStr, "::") {
			if !strings.HasPrefix(ipStr, expectedPrefix) {
				wg.Add(1)
				go func(address netlink.Addr) {
					defer wg.Done()
					netlink.AddrDel(link, &address)
				}(addr)
			}
		}
	}

	wg.Wait()
}

func ensureURLHasScheme(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return "https://" + urlStr
	}
	return urlStr
}

func logRequest(r *http.Request) {
	count := requestCount.Add(1)
	if Debug {
		fmt.Printf("\nIncoming request #%d\n", count)
	}
}

func validateAPIToken(apiToken string, userAgent string) bool {
	key := []byte(userAgent)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(SharedSecret))
	expectedHash := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(apiToken), []byte(expectedHash))
}

// getNextIPFromPool returns an IP tracker using lock-free access
func getNextIPFromPool() (*IPUsageTracker, error) {
	pool := ipPool.Load()
	if pool == nil || len(*pool) == 0 {
		return nil, fmt.Errorf("IP pool is empty")
	}

	poolLen := uint32(len(*pool))
	startIdx := currentIndex.Add(1) % poolLen

	// Fast path: find an available IP with atomic operations only
	for attempts := uint32(0); attempts < poolLen*2; attempts++ {
		idx := (startIdx + attempts) % poolLen
		tracker := (*pool)[idx]

		if tracker.GetRequestCount() >= MaxRequestsPerIP {
			continue
		}

		if !tracker.AcquireUse() {
			continue
		}

		tracker.IncrementRequestCount()
		tracker.UpdateLastUsed()

		if Debug {
			fmt.Printf("Using IP %s (usage: %d, concurrent: %d)\n",
				tracker.IP, tracker.GetRequestCount(), tracker.GetInUseCount())
		}

		return tracker, nil
	}

	// All IPs exhausted or busy — signal for more and try fallback
	select {
	case urgentAddChan <- struct{}{}:
	default:
	}

	// Last resort: try any IP ignoring MaxRequestsPerIP
	for attempts := uint32(0); attempts < poolLen; attempts++ {
		idx := (startIdx + attempts) % poolLen
		tracker := (*pool)[idx]

		if tracker.AcquireUse() {
			tracker.IncrementRequestCount()
			tracker.UpdateLastUsed()
			return tracker, nil
		}
	}

	return nil, fmt.Errorf("all IPs busy")
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	apiToken := r.Header.Get("API-Token")
	userAgent := r.Header.Get("User-Agent")

	if !validateAPIToken(apiToken, userAgent) {
		http.Error(w, "Unauthorized: i6.shark detected invalid API-Token header.", http.StatusUnauthorized)
		return
	}

	logRequest(r)

	targetURL := strings.TrimSpace(r.URL.Query().Get("url"))
	headersJSON := r.URL.Query().Get("headers")
	useNormalParam := r.URL.Query().Has("normal")

	if targetURL == "" {
		fmt.Fprintf(w, "i6.shark is working as expected (v%s).", Version)
		return
	}

	targetURL = ensureURLHasScheme(targetURL)
	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Host == "" {
		http.Error(w, fmt.Sprintf("Invalid URL: %s.", targetURL), http.StatusBadRequest)
		return
	}

	var tracker *IPUsageTracker
	var client *http.Client

	if useNormalParam {
		client = defaultClient
		if Debug {
			fmt.Println("Using system default IP as requested")
		}
	} else {
		var poolErr error
		tracker, poolErr = getNextIPFromPool()
		if poolErr != nil {
			client = defaultClient
			if Debug {
				fmt.Printf("Pool error, using default: %v\n", poolErr)
			}
		} else {
			client = tracker.client
			defer tracker.ReleaseUse()
		}
	}

	// Build forwarded headers — pre-allocate with capacity
	forwardedHeaders := make(http.Header, len(r.Header))
	for name, values := range r.Header {
		lowerName := strings.ToLower(name)
		if lowerName == "host" || headersToStripBeforeForwarding[lowerName] {
			continue
		}
		forwardedHeaders[name] = values
	}

	if headersJSON != "" {
		var customHeaders map[string]string
		if json.Unmarshal([]byte(headersJSON), &customHeaders) == nil {
			for name, value := range customHeaders {
				forwardedHeaders.Set(name, value)
			}
		}
	}

	outRequest, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating request: %v", err), http.StatusInternalServerError)
		return
	}

	if r.Body != nil && r.Body != http.NoBody && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
		outRequest.Body = r.Body
		outRequest.ContentLength = r.ContentLength
	} else {
		outRequest.Body = http.NoBody
		outRequest.ContentLength = 0
	}

	outRequest.Header = forwardedHeaders

	resp, err := client.Do(outRequest)
	if err != nil {
		if os.IsTimeout(err) || strings.Contains(err.Error(), "timeout") {
			http.Error(w, fmt.Sprintf("Request timed out connecting to %s.", parsedURL.Host), http.StatusGatewayTimeout)
		} else if strings.Contains(err.Error(), "connection") {
			http.Error(w, fmt.Sprintf("Connection error to %s: %v.", parsedURL.Host, err), http.StatusBadGateway)
		} else {
			http.Error(w, fmt.Sprintf("Error proxying request: %v.", err), http.StatusInternalServerError)
		}

		if strings.Contains(err.Error(), "bind: cannot assign requested address") {
			select {
			case urgentAddChan <- struct{}{}:
			default:
			}
		}
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	respHeader := w.Header()
	for name, values := range resp.Header {
		if !skipHeaders[strings.ToLower(name)] {
			for _, value := range values {
				respHeader.Add(name, value)
			}
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Use pooled buffer for zero-alloc streaming
	bufPtr := bufferPool.Get().(*[]byte)
	io.CopyBuffer(w, resp.Body, *bufPtr)
	bufferPool.Put(bufPtr)
}

func manageIPPool() {
	ticker := time.NewTicker(PoolManageInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-urgentAddChan:
		}

		pool := ipPool.Load()
		currentSize := 0
		availableIPs := 0
		if pool != nil {
			currentSize = len(*pool)
			for _, t := range *pool {
				if t.GetRequestCount() < MaxRequestsPerIP && t.GetInUseCount() < MaxConcurrentPerIP {
					availableIPs++
				}
			}
		}

		needToAdd := currentSize < DesiredPoolSize || availableIPs < DesiredPoolSize/4
		batchTarget := DesiredPoolSize - currentSize
		if batchTarget > PoolAddBatchSize {
			batchTarget = PoolAddBatchSize
		}
		if availableIPs < 30 {
			emergency := PoolAddBatchSize * 2
			if emergency > DesiredPoolSize-currentSize+30 {
				emergency = DesiredPoolSize - currentSize + 30
			}
			if emergency > batchTarget {
				batchTarget = emergency
			}
		}

		if needToAdd && batchTarget > 0 {
			go func(target int) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()

				var wg sync.WaitGroup
				newTrackers := make(chan *IPUsageTracker, target)
				sem := make(chan struct{}, IPAddConcurrency)

				for i := 0; i < target; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()

						select {
						case sem <- struct{}{}:
							defer func() { <-sem }()
						case <-ctx.Done():
							return
						}

						newIP := randomIPv6()
						if addIPv6ToInterface(newIP) {
							tracker := createIPTracker(normalizeIPv6(newIP))
							select {
							case newTrackers <- tracker:
							case <-ctx.Done():
							default:
							}
						}
					}()
				}

				go func() {
					wg.Wait()
					close(newTrackers)
				}()

				addedTrackers := make([]*IPUsageTracker, 0, target)
				for tracker := range newTrackers {
					addedTrackers = append(addedTrackers, tracker)
				}

				if len(addedTrackers) > 0 {
					poolWriteMutex.Lock()

					currentPool := ipPool.Load()
					var newPool []*IPUsageTracker
					if currentPool != nil {
						newPool = make([]*IPUsageTracker, 0, len(*currentPool)+len(addedTrackers))

						expectedPrefix := IPv6Prefix + ":" + IPv6Subnet + ":"
						var toFlush []string

						for _, t := range *currentPool {
							if !strings.HasPrefix(t.IP, expectedPrefix) {
								if t.GetInUseCount() == 0 {
									toFlush = append(toFlush, t.IP)
									t.transport.CloseIdleConnections()
								} else {
									newPool = append(newPool, t)
								}
							} else if t.GetRequestCount() >= MaxRequestsPerIP {
								if t.GetInUseCount() == 0 {
									toFlush = append(toFlush, t.IP)
									t.transport.CloseIdleConnections()
								} else {
									newPool = append(newPool, t)
								}
							} else {
								newPool = append(newPool, t)
							}
						}

						if len(toFlush) > 0 {
							go func(ips []string) {
								for _, ip := range ips {
									removeIPv6FromInterface(ip)
								}
							}(toFlush)
						}
					} else {
						newPool = make([]*IPUsageTracker, 0, len(addedTrackers))
					}

					newPool = append(newPool, addedTrackers...)
					ipPool.Store(&newPool)
					poolWriteMutex.Unlock()
				}
			}(batchTarget)
		}
	}
}

func checkPrivileges() bool {
	if os.Geteuid() != 0 && ListenPort < 1024 {
		log.Fatal("ERROR: Root privileges required for port 80")
		return false
	}
	return true
}

func onStartup() bool {
	if !checkPrivileges() {
		return false
	}

	link, err := getLink()
	if err != nil {
		log.Printf("WARNING: Interface %s not found: %v", Interface, err)
		return false
	}
	if (link.Attrs().Flags & net.FlagUp) == 0 {
		log.Printf("WARNING: Interface %s is down", Interface)
		return false
	}

	time.Sleep(100 * time.Millisecond)
	go flushAllIPAddresses()
	time.Sleep(500 * time.Millisecond)

	testIP := randomIPv6()
	addIPv6ToInterface(testIP)

	return true
}

func main() {
	// Use all available CPU cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	emptyPool := make([]*IPUsageTracker, 0, DesiredPoolSize)
	ipPool.Store(&emptyPool)

	defaultTransport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   DialTimeout,
			KeepAlive: KeepAliveInterval,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:       IdleConnTimeout,
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		ResponseHeaderTimeout: RequestTimeout,
		DisableKeepAlives:     false,
		DisableCompression:    true,
		WriteBufferSize:       BufferSize,
		ReadBufferSize:        BufferSize,
	}
	defaultClient = &http.Client{
		Transport: defaultTransport,
		Timeout:   RequestTimeout,
	}

	if !onStartup() {
		os.Exit(1)
	}

	go func() {
		time.Sleep(1 * time.Second)
		cleanupWrongSubnetIPs()
		manageIPPool()
	}()

	go func() {
		time.Sleep(5 * time.Second)
		periodicIPFlush()
	}()

	go func() {
		time.Sleep(3 * time.Second)
		periodicUnusedIPFlush()
	}()

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", ListenHost, ListenPort),
		Handler:           http.HandlerFunc(handleRequest),
		ReadTimeout:       ServerReadTimeout,
		WriteTimeout:      ServerWriteTimeout,
		IdleTimeout:       ServerIdleTimeout,
		ReadHeaderTimeout: ServerHeaderTimeout,
		MaxHeaderBytes:    MaxHeaderSize,
	}

	fmt.Printf("Starting i6.shark server v%s on %s (GOMAXPROCS=%d, pool=%d)\n",
		Version, server.Addr, runtime.GOMAXPROCS(0), DesiredPoolSize)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
