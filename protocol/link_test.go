package protocol

import (
	"strings"
	"testing"
)

func TestExportNaiveQUICLinkRoundTrip(t *testing.T) {
	link, err := ExportNodeLink(Node{
		Type:           "naive",
		Name:           "naive-quic",
		Server:         "example.com",
		Port:           443,
		Username:       "user",
		Password:       "pass",
		TLS:            true,
		Tls:            true,
		QUIC:           true,
		QUICCongestion: "bbr",
	})
	if err != nil {
		t.Fatalf("ExportNodeLink() error = %v", err)
	}
	if !strings.HasPrefix(link, "naive+quic://") {
		t.Fatalf("ExportNodeLink() = %q, want naive+quic scheme", link)
	}

	node, err := ParseNaive(link)
	if err != nil {
		t.Fatalf("ParseNaive() error = %v", err)
	}
	if !node.QUIC {
		t.Fatalf("ParseNaive() QUIC = false, want true")
	}
	if node.Server != "example.com" || node.Username != "user" || node.Password != "pass" {
		t.Fatalf("ParseNaive() = %+v", node)
	}
}

func TestExportMieruLinkRoundTrip(t *testing.T) {
	link, err := ExportNodeLink(Node{
		Type:          "mieru",
		Name:          "default",
		Server:        "1.2.3.4",
		Port:          6666,
		Username:      "baozi",
		Password:      "manlianpenfen",
		Transport:     "TCP",
		Mtu:           1300,
		Multiplexing:  "MULTIPLEXING_HIGH",
		HandshakeMode: "HANDSHAKE_NO_WAIT",
	})
	if err != nil {
		t.Fatalf("ExportNodeLink() error = %v", err)
	}
	if !strings.HasPrefix(link, "mierus://") {
		t.Fatalf("ExportNodeLink() = %q, want mierus scheme", link)
	}

	nodes, err := ParseMieru(link)
	if err != nil {
		t.Fatalf("ParseMieru() error = %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("ParseMieru() returned %d nodes, want 1", len(nodes))
	}
	got := nodes[0]
	if got.Type != "mieru" || got.Server != "1.2.3.4" || got.Port != 6666 || got.Username != "baozi" || got.Password != "manlianpenfen" {
		t.Fatalf("ParseMieru() = %+v", got)
	}
	if got.Transport != "TCP" || got.Mtu != 1300 || got.Multiplexing != "MULTIPLEXING_HIGH" || got.HandshakeMode != "HANDSHAKE_NO_WAIT" {
		t.Fatalf("ParseMieru() transport fields = %+v", got)
	}
}

func TestExportMieruHashedPasswordUsesFullConfigLink(t *testing.T) {
	link, err := ExportNodeLink(Node{
		Type:           "mieru",
		Name:           "hashed",
		Server:         "example.com",
		PortRange:      "6000-6002",
		Username:       "user",
		HashedPassword: "hash-value",
		Transport:      "QUIC",
	})
	if err != nil {
		t.Fatalf("ExportNodeLink() error = %v", err)
	}
	if !strings.HasPrefix(link, "mieru://") {
		t.Fatalf("ExportNodeLink() = %q, want full mieru config link", link)
	}

	nodes, err := ParseMieru(link)
	if err != nil {
		t.Fatalf("ParseMieru() error = %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("ParseMieru() returned %d nodes, want 1", len(nodes))
	}
	got := nodes[0]
	if got.HashedPassword != "hash-value" || got.PortRange != "6000-6002" || got.Transport != "UDP" {
		t.Fatalf("ParseMieru() = %+v", got)
	}
}

func TestParseSingBoxBareMieruOutbound(t *testing.T) {
	nodes, err := ParseSubscriptionRaw([]byte(`{
		"type": "mieru",
		"tag": "us-mieru",
		"server": "11usmn.cloudfrontcdn.com",
		"server_port": 8088,
		"transport": "TCP",
		"username": "377e0b41-acbe-47d7-8e1f-9f302777c922",
		"password": "377e0b41-acbe-47d7-8e1f-9f302777c922",
		"domain_resolver": {
			"server": "dns_outbound_out",
			"rewrite_ttl": 43200,
			"strategy": "prefer_ipv6"
		}
	}`))
	if err != nil {
		t.Fatalf("ParseSubscriptionRaw() error = %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("ParseSubscriptionRaw() returned %d nodes, want 1", len(nodes))
	}
	got := nodes[0]
	if got.Type != "mieru" || got.Name != "us-mieru" || got.Server != "11usmn.cloudfrontcdn.com" || got.Port != 8088 {
		t.Fatalf("ParseSubscriptionRaw() = %+v", got)
	}
	if got.Transport != "TCP" || got.Username == "" || got.Password == "" || got.DomainStrategy != "prefer_ipv6" {
		t.Fatalf("ParseSubscriptionRaw() auth/transport = %+v", got)
	}
}
