package proxy

import (
	"context"
	"net"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseAndroidDNSServers(t *testing.T) {
	raw := "192.168.1.1, 192.168.1.2:5353; 2001:4860:4860::8888 [2001:4860:4860::8844]\n[2606:4700:4700::1111]:5353 " +
		"192.168.1.1:53 1.1.1.1 127.0.0.1 [::1]:53 0.0.0.0 :: 169.254.1.1 fe80::1%wlan0 224.0.0.251 " +
		"172.19.0.2:53 dns.google:53 8.8.8.8:0 8.8.8.8:70000 8.8.8.8:abc 8.8.8.8:"

	got := ParseAndroidDNSServers(raw)
	want := []string{
		"192.168.1.1:53",
		"192.168.1.2:5353",
		"[2001:4860:4860::8888]:53",
		"[2001:4860:4860::8844]:53",
		"[2606:4700:4700::1111]:5353",
		"1.1.1.1:53",
		"223.5.5.5:53",
		"119.29.29.29:53",
		"8.8.8.8:53",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseAndroidDNSServers() = %v, want %v", got, want)
	}

	if defaults := ParseAndroidDNSServers("   "); !reflect.DeepEqual(defaults, defaultAndroidFallbackDNSServers) {
		t.Fatalf("ParseAndroidDNSServers(empty) = %v, want %v", defaults, defaultAndroidFallbackDNSServers)
	}
}

func TestIsAndroidLoopbackDNSAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{addr: "127.0.0.1:53", want: true},
		{addr: "[::1]:53", want: true},
		{addr: "127.0.0.2:1053", want: true},
		{addr: "8.8.8.8:53", want: false},
		{addr: "[2001:4860:4860::8888]:53", want: false},
		{addr: "", want: false},
	}

	for _, tc := range cases {
		if got := isAndroidLoopbackDNSAddr(tc.addr); got != tc.want {
			t.Errorf("isAndroidLoopbackDNSAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestEnsureAndroidCertDirs(t *testing.T) {
	t.Setenv(AndroidCertDirsEnv, "")
	EnsureAndroidCertDirs()
	if got := os.Getenv(AndroidCertDirsEnv); got != DefaultAndroidCertDirs {
		t.Fatalf("EnsureAndroidCertDirs() set %q, want %q", got, DefaultAndroidCertDirs)
	}

	const customDir = "/custom/certs"
	t.Setenv(AndroidCertDirsEnv, customDir)
	EnsureAndroidCertDirs()
	if got := os.Getenv(AndroidCertDirsEnv); got != customDir {
		t.Fatalf("EnsureAndroidCertDirs() overwrote custom dir with %q, want %q", got, customDir)
	}
}

func TestAndroidFallbackResolverDialUDPAndFailover(t *testing.T) {
	blackholePC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket blackhole error: %v", err)
	}
	t.Cleanup(func() { _ = blackholePC.Close() })

	var blackholeHits atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := blackholePC.ReadFrom(buf); err != nil {
				return
			}
			blackholeHits.Add(1)
		}
	}()

	healthyPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket healthy error: %v", err)
	}
	t.Cleanup(func() { _ = healthyPC.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := healthyPC.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil || len(req.Question) == 0 {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			if req.Question[0].Name == "example.test." && req.Question[0].Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   req.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: net.ParseIP("93.184.216.34"),
				})
			}
			packed, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = healthyPC.WriteTo(packed, addr)
		}
	}()

	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion("example.test.", dns.TypeA)
	queryBytes, err := queryMsg.Pack()
	if err != nil {
		t.Fatalf("Pack DNS query: %v", err)
	}

	dial := NewAndroidFallbackResolverDial(
		[]string{blackholePC.LocalAddr().String(), healthyPC.LocalAddr().String()},
		150*time.Millisecond,
	)

	// 1. First dial hits blackhole; SetDeadline should be capped and Read should fail over activeIdx.
	c1, err := dial(context.Background(), "udp", "127.0.0.1:53")
	if err != nil {
		t.Fatalf("first dial error: %v", err)
	}
	if _, ok := c1.(net.PacketConn); !ok {
		_ = c1.Close()
		t.Fatalf("expected UDP conn to preserve net.PacketConn, got %T", c1)
	}
	if err := c1.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = c1.Close()
		t.Fatalf("SetDeadline error: %v", err)
	}
	start := time.Now()
	if _, err := c1.Write(queryBytes); err != nil {
		_ = c1.Close()
		t.Fatalf("c1.Write error: %v", err)
	}
	buf := make([]byte, 2048)
	_, readErr := c1.Read(buf)
	elapsed := time.Since(start)
	_ = c1.Close()
	if readErr == nil {
		t.Fatal("expected blackhole UDP Read to time out")
	}
	if elapsed >= time.Second {
		t.Fatalf("capped UDP timeout took %v, want < 1s", elapsed)
	}

	// 2. Second dial should now go directly to the healthy mock DNS server.
	c2, err := dial(context.Background(), "udp", "[::1]:53")
	if err != nil {
		t.Fatalf("second dial error: %v", err)
	}
	if err := c2.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		_ = c2.Close()
		t.Fatalf("c2.SetDeadline error: %v", err)
	}
	if _, err := c2.Write(queryBytes); err != nil {
		_ = c2.Close()
		t.Fatalf("c2.Write error: %v", err)
	}
	n, err := c2.Read(buf)
	_ = c2.Close()
	if err != nil {
		t.Fatalf("c2.Read error: %v", err)
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(buf[:n]); err != nil {
		t.Fatalf("Unpack DNS reply error: %v", err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("got %d DNS answers, want 1", len(reply.Answer))
	}
	aRec, ok := reply.Answer[0].(*dns.A)
	if !ok || aRec.A.String() != "93.184.216.34" {
		t.Fatalf("unexpected DNS answer: %+v", reply.Answer[0])
	}

	// 3. Third dial should stick to the healthy server without hitting blackhole again.
	c3, err := dial(context.Background(), "udp", "127.0.0.1:53")
	if err != nil {
		t.Fatalf("third dial error: %v", err)
	}
	if err := c3.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		_ = c3.Close()
		t.Fatalf("c3.SetDeadline error: %v", err)
	}
	if _, err := c3.Write(queryBytes); err != nil {
		_ = c3.Close()
		t.Fatalf("c3.Write error: %v", err)
	}
	n, err = c3.Read(buf)
	_ = c3.Close()
	if err != nil {
		t.Fatalf("c3.Read error: %v", err)
	}
	reply3 := new(dns.Msg)
	if err := reply3.Unpack(buf[:n]); err != nil {
		t.Fatalf("Unpack third DNS reply error: %v", err)
	}
	if len(reply3.Answer) != 1 {
		t.Fatalf("third reply got %d answers, want 1", len(reply3.Answer))
	}
	if hits := blackholeHits.Load(); hits != 1 {
		t.Fatalf("blackhole hit count = %d, want 1 (healthy server should remain sticky)", hits)
	}
}

func TestAndroidFallbackResolverDialTCPNotPacketConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp error: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	dial := NewAndroidFallbackResolverDial([]string{ln.Addr().String()}, 150*time.Millisecond)
	conn, err := dial(context.Background(), "tcp", "127.0.0.1:53")
	if err != nil {
		t.Fatalf("TCP dial error: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, ok := conn.(net.PacketConn); ok {
		t.Fatalf("TCP conn %T must not implement net.PacketConn", conn)
	}
}
