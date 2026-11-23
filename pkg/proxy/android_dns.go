package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

const (
	AndroidCertDirsEnv        = "SSL_CERT_DIR"
	DefaultAndroidCertDirs    = "/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts:/data/misc/keychain/certs-added"
	AndroidDNSServersEnv      = "WING_ANDROID_DNS_SERVERS"
	androidFallbackDNSTimeout = 1500 * time.Millisecond
)

var defaultAndroidFallbackDNSServers = []string{
	"223.5.5.5:53",
	"119.29.29.29:53",
	"1.1.1.1:53",
	"8.8.8.8:53",
}

// EnsureAndroidCertDirs ensures Go's x509 verifier searches Android 14+ Conscrypt
// APEX CA roots in addition to legacy system certificate directories.
func EnsureAndroidCertDirs() {
	if strings.TrimSpace(os.Getenv(AndroidCertDirsEnv)) == "" {
		_ = os.Setenv(AndroidCertDirsEnv, DefaultAndroidCertDirs)
	}
}

// ParseAndroidDNSServers parses a comma/semicolon/whitespace-separated list of
// DNS server IP[:port] strings, filters loopback/VPN-TUN/invalid addresses,
// deduplicates them, and appends built-in public fallback resolvers.
func ParseAndroidDNSServers(raw string) []string {
	entries := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || unicode.IsSpace(r)
	})

	seen := make(map[string]struct{}, len(entries)+len(defaultAndroidFallbackDNSServers))
	servers := make([]string, 0, len(entries)+len(defaultAndroidFallbackDNSServers))

	appendServer := func(addr string) {
		if _, exists := seen[addr]; exists {
			return
		}
		seen[addr] = struct{}{}
		servers = append(servers, addr)
	}

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, port, err := net.SplitHostPort(entry)
		if err != nil {
			host = strings.Trim(entry, "[]")
			port = "53"
		}
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if zoneIdx := strings.IndexByte(host, '%'); zoneIdx >= 0 {
			host = host[:zoneIdx]
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if ip.String() == "172.19.0.2" {
			continue
		}
		portNum, err := strconv.Atoi(strings.TrimSpace(port))
		if err != nil || portNum < 1 || portNum > 65535 {
			continue
		}
		appendServer(net.JoinHostPort(ip.String(), strconv.Itoa(portNum)))
	}

	for _, fallback := range defaultAndroidFallbackDNSServers {
		appendServer(fallback)
	}
	return servers
}

func isAndroidLoopbackDNSAddr(address string) bool {
	trimmed := strings.TrimSpace(address)
	host, _, err := net.SplitHostPort(trimmed)
	if err != nil {
		host = strings.Trim(trimmed, "[]")
	} else {
		host = strings.Trim(host, "[]")
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NewAndroidFallbackResolverDial returns a net.Resolver.Dial implementation for
// pure-Go (!cgo) Android builds where Go defaults to 127.0.0.1:53 / [::1]:53.
// It preserves net.PacketConn on *net.UDPConn so stdlib keeps UDP DNS framing.
func NewAndroidFallbackResolverDial(servers []string, perAttemptTimeout time.Duration) func(ctx context.Context, network, address string) (net.Conn, error) {
	cleanServers := make([]string, 0, len(servers))
	for _, s := range servers {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			cleanServers = append(cleanServers, trimmed)
		}
	}
	if len(cleanServers) == 0 {
		cleanServers = append(cleanServers, defaultAndroidFallbackDNSServers...)
	}
	if perAttemptTimeout <= 0 {
		perAttemptTimeout = androidFallbackDNSTimeout
	}

	var activeIdx atomic.Uint64

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: perAttemptTimeout}
		if !isAndroidLoopbackDNSAddr(address) {
			return dialer.DialContext(ctx, network, address)
		}

		startIdx := activeIdx.Load()
		var lastErr error
		for offset := uint64(0); offset < uint64(len(cleanServers)); offset++ {
			idx := (startIdx + offset) % uint64(len(cleanServers))
			target := cleanServers[idx]

			conn, err := dialer.DialContext(ctx, network, target)
			if err != nil {
				lastErr = err
				if ctx.Err() != nil {
					return nil, lastErr
				}
				continue
			}

			if offset > 0 {
				activeIdx.CompareAndSwap(startIdx, idx)
			}
			var failOnce sync.Once
			onErr := func() {
				if ctx.Err() != nil {
					return
				}
				failOnce.Do(func() {
					activeIdx.CompareAndSwap(idx, (idx+1)%uint64(len(cleanServers)))
				})
			}

			if udpConn, ok := conn.(*net.UDPConn); ok {
				return &androidFallbackUDPConn{
					UDPConn: udpConn,
					maxWait: perAttemptTimeout,
					onErr:   onErr,
				}, nil
			}
			return &androidFallbackStreamConn{
				Conn:    conn,
				maxWait: perAttemptTimeout,
				onErr:   onErr,
			}, nil
		}

		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no Android fallback DNS servers available")
	}
}

// ConfigureAndroidFallbackResolver configures net.DefaultResolver for Android
// builds without cgo using system-discovered DNS servers and public fallbacks.
func ConfigureAndroidFallbackResolver(envValue string) {
	servers := ParseAndroidDNSServers(envValue)
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = NewAndroidFallbackResolverDial(servers, androidFallbackDNSTimeout)
	log.Printf("[Android Core] Pure-Go DNS fallback enabled (cgo disabled), servers: %v", servers)
}

func capAndroidDNSDeadline(t time.Time, maxWait time.Duration) time.Time {
	if maxWait <= 0 {
		return t
	}
	limit := time.Now().Add(maxWait)
	if t.IsZero() || t.After(limit) {
		return limit
	}
	return t
}

type androidFallbackUDPConn struct {
	*net.UDPConn
	maxWait time.Duration
	onErr   func()
}

func (c *androidFallbackUDPConn) SetDeadline(t time.Time) error {
	return c.UDPConn.SetDeadline(capAndroidDNSDeadline(t, c.maxWait))
}

func (c *androidFallbackUDPConn) SetReadDeadline(t time.Time) error {
	return c.UDPConn.SetReadDeadline(capAndroidDNSDeadline(t, c.maxWait))
}

func (c *androidFallbackUDPConn) SetWriteDeadline(t time.Time) error {
	return c.UDPConn.SetWriteDeadline(capAndroidDNSDeadline(t, c.maxWait))
}

func (c *androidFallbackUDPConn) Read(b []byte) (int, error) {
	n, err := c.UDPConn.Read(b)
	if err != nil && c.onErr != nil {
		c.onErr()
	}
	return n, err
}

func (c *androidFallbackUDPConn) Write(b []byte) (int, error) {
	n, err := c.UDPConn.Write(b)
	if err != nil && c.onErr != nil {
		c.onErr()
	}
	return n, err
}

type androidFallbackStreamConn struct {
	net.Conn
	maxWait time.Duration
	onErr   func()
}

func (c *androidFallbackStreamConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(capAndroidDNSDeadline(t, c.maxWait))
}

func (c *androidFallbackStreamConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(capAndroidDNSDeadline(t, c.maxWait))
}

func (c *androidFallbackStreamConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(capAndroidDNSDeadline(t, c.maxWait))
}

func (c *androidFallbackStreamConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && c.onErr != nil {
		c.onErr()
	}
	return n, err
}

func (c *androidFallbackStreamConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil && c.onErr != nil {
		c.onErr()
	}
	return n, err
}
