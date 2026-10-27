package proxy

import (
	"net"
	"reflect"
	"testing"

	"wing/protocol"
)

// 192.0.2.0/24 (TEST-NET-1) 不可路由，用来模拟已下线的节点 IP。
const deadTestIP = "192.0.2.1"

func TestPickReachableNodeIPPrefersLiveTCPAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	node := protocol.Node{Type: "anytls", Server: "tcp.pick.test", Port: listener.Addr().(*net.TCPAddr).Port}
	if got := pickReachableNodeIP(node, []string{deadTestIP, "127.0.0.1"}); got != "127.0.0.1" {
		t.Fatalf("pickReachableNodeIP() = %s, want live 127.0.0.1", got)
	}
}

func TestPickReachableNodeIPProbesQUICNodes(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			// 模拟 Version Negotiation 回包
			_, _ = server.WriteTo(buf[:n], addr)
		}
	}()

	node := protocol.Node{Type: "hysteria2", Server: "quic.pick.test", Port: server.LocalAddr().(*net.UDPAddr).Port}
	if got := pickReachableNodeIP(node, []string{deadTestIP, "127.0.0.1"}); got != "127.0.0.1" {
		t.Fatalf("pickReachableNodeIP() = %s, want live 127.0.0.1", got)
	}
}

func TestPickReachableNodeIPFallsBackToFirstCandidate(t *testing.T) {
	node := protocol.Node{Type: "anytls", Server: "dead.pick.test", Port: 4430}
	candidates := []string{deadTestIP, "192.0.2.2"}
	if got := pickReachableNodeIP(node, candidates); got != deadTestIP {
		t.Fatalf("pickReachableNodeIP() = %s, want first candidate %s", got, deadTestIP)
	}
}

func TestCandidateResolvedIPsFollowsStrategy(t *testing.T) {
	ips := []string{"2001:db8::1", "198.51.100.1", "2001:db8::2", "198.51.100.2"}
	cases := map[string][]string{
		"ipv4_only":   {"198.51.100.1", "198.51.100.2"},
		"ipv6_only":   {"2001:db8::1", "2001:db8::2"},
		"prefer_ipv6": {"2001:db8::1", "2001:db8::2"},
		"":            {"198.51.100.1", "198.51.100.2"},
	}
	for strategy, want := range cases {
		if got := candidateResolvedIPs(ips, strategy); !reflect.DeepEqual(got, want) {
			t.Fatalf("candidateResolvedIPs(%q) = %v, want %v", strategy, got, want)
		}
	}
	if got := selectResolvedIP(ips, "ipv4_only"); got != "198.51.100.1" {
		t.Fatalf("selectResolvedIP() = %s", got)
	}
}
