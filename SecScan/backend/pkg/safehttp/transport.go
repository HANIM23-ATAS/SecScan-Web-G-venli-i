package safehttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"syscall"
	"time"
)

var (
	ErrPrivateIPAddress = errors.New("security: attempt to connect to a private/loopback IP address detected")
)

// DefaultSafeTransport returns an http.Transport configured to block SSRF.
func DefaultSafeTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: SafeDialContext(&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// DefaultSafeClient returns an HTTP client that uses the SafeTransport.
func DefaultSafeClient() *http.Client {
	return &http.Client{
		Transport: DefaultSafeTransport(),
		Timeout:   20 * time.Second,
	}
}

// SafeDialContext wraps a dialer to resolve the IP address and check if it's safe.
func SafeDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// Resolve the host to IP addresses
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}

		for _, ip := range ips {
			if !isSafeIP(ip) {
				return nil, ErrPrivateIPAddress
			}
		}

		// Since dialer.DialContext takes an address, a malicious DNS could hypothetically
		// return a safe IP when we resolve it, but a private IP when the dialer resolves it again (DNS Rebinding).
		// To prevent this, we dial the resolved safe IP directly if available.
		// Wait, DialContext can just use the resolved IP instead of the host.
		var conn net.Conn
		var dialErr error

		// Try dialing the resolved IPs
		for _, ip := range ips {
			targetAddr := net.JoinHostPort(ip.String(), port)
			conn, dialErr = dialer.DialContext(ctx, network, targetAddr)
			if dialErr == nil {
				return conn, nil
			}
		}

		if dialErr != nil {
			return nil, dialErr
		}
		
		return nil, syscall.ECONNREFUSED
	}
}

func isSafeIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	if ip.IsUnspecified() {
		return false
	}
	return true
}
