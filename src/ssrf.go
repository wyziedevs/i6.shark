package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"syscall"
)

// errBlockedDestination marks a request or redirect the proxy refused because
// it would reach a non-public address or a port outside allowedPorts.
var errBlockedDestination = errors.New("destination not allowed")

// blockedPrefixes are the non-public ranges not already covered by netip's
// IsLoopback / IsPrivate / IsLinkLocal* / IsMulticast / IsUnspecified checks.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this" network
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT (also Alibaba metadata 100.100.100.200)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // Reserved, incl. 255.255.255.255
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated)
	netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4-translated
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64, embeds an IPv4 address
	netip.MustParsePrefix("64:ff9b:1::/48"),  // Local-use NAT64
	netip.MustParsePrefix("100::/64"),        // Discard-only
	netip.MustParsePrefix("2001:db8::/32"),   // Documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4 (deprecated), embeds an IPv4 address
	netip.MustParsePrefix("fec0::/10"),       // Site-local (deprecated)
}

// selfPrefixes are this host's own addresses and its routed IPv6 /48. Dialling
// them reaches services on this VPS (the API, Redis, the proxy itself) just as
// loopback would. Set once by loadSelfPrefixes before the server starts.
var selfPrefixes []netip.Prefix

// isBlockedIP reports whether the proxy must never connect to ip.
// IPv4-mapped IPv6 addresses are judged by the IPv4 address they carry.
func isBlockedIP(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	for _, prefix := range selfPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// loadSelfPrefixes records the /48 the pool draws from and every address
// currently on this host's interfaces, so they are refused as destinations.
func loadSelfPrefixes() {
	selfPrefixes = nil
	if prefix, err := netip.ParsePrefix(IPv6Prefix + "::/48"); err == nil {
		selfPrefixes = append(selfPrefixes, prefix.Masked())
	} else {
		log.Printf("WARNING: IPv6Prefix %q is not a valid /48, so it is not blocked as a destination", IPv6Prefix)
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("WARNING: Could not list interface addresses: %v", err)
		return
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !isBlockedIP(ip) {
			selfPrefixes = append(selfPrefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
}

// guardedDialControl is the net.Dialer Control hook for every outbound
// connection. It runs after DNS resolution, right before connect(), on the
// address actually being dialled, so it also covers redirects, DNS rebinding
// and hostnames that resolve to internal addresses.
func guardedDialControl(network, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil || isBlockedIP(addrPort.Addr()) || !allowedPorts[addrPort.Port()] {
		if Debug {
			fmt.Printf("Blocked dial to %s (%s)\n", address, network)
		}
		return fmt.Errorf("%w: %s", errBlockedDestination, address)
	}
	return nil
}

// validateTargetURL checks what the URL alone can tell: scheme, port and IP
// literal hosts. It gives callers a clear error before any dial and is re-run
// on every redirect; guardedDialControl remains the real enforcement.
func validateTargetURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q", errBlockedDestination, u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", errBlockedDestination)
	}

	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || !allowedPorts[uint16(n)] {
		return fmt.Errorf("%w: port %s", errBlockedDestination, port)
	}

	if ip, err := netip.ParseAddr(host); err == nil && isBlockedIP(ip) {
		return fmt.Errorf("%w: address %s", errBlockedDestination, host)
	}
	return nil
}

// checkRedirect follows at most MaxRedirects redirects, and only to URLs that
// pass validateTargetURL; the dial hook still checks where each one connects.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > MaxRedirects {
		return http.ErrUseLastResponse
	}
	return validateTargetURL(req.URL)
}
