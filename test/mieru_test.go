package test

import (
	"testing"

	mieruAppctl "github.com/enfein/mieru/v3/pkg/appctl"
	mieruPB "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"

	"high-mae/protocol"
)

func TestParseMieruSimpleURL(t *testing.T) {
	link := "mierus://baozi:manlianpenfen@localhost?profile=test-profile&port=8964-8965&protocol=TCP&multiplexing=MULTIPLEXING_LOW&handshake-mode=HANDSHAKE_NO_WAIT"

	nodes, err := protocol.ParseMieru(link)
	if err != nil {
		t.Fatalf("ParseMieru failed: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 mieru node, got %d", len(nodes))
	}

	node := nodes[0]
	if node.Type != "mieru" {
		t.Fatalf("type: want mieru, got %q", node.Type)
	}
	if node.PortRange != "8964-8965" {
		t.Fatalf("port-range: got %q", node.PortRange)
	}
	if node.Port != 8964 {
		t.Fatalf("port: want first port 8964, got %d", node.Port)
	}
	if node.Transport != "TCP" {
		t.Fatalf("transport: got %q", node.Transport)
	}
	if node.Username != "baozi" || node.Password != "manlianpenfen" {
		t.Fatalf("credentials mismatch: %q / %q", node.Username, node.Password)
	}
	if node.Multiplexing != "MULTIPLEXING_LOW" {
		t.Fatalf("multiplexing: got %q", node.Multiplexing)
	}
	if node.HandshakeMode != "HANDSHAKE_NO_WAIT" {
		t.Fatalf("handshake-mode: got %q", node.HandshakeMode)
	}
}

func TestParseMieruConfigURL(t *testing.T) {
	configURL, err := mieruAppctl.ClientConfigToURL(&mieruPB.ClientConfig{
		Profiles: []*mieruPB.ClientProfile{
			{
				ProfileName: proto.String("cfg-profile"),
				User: &mieruPB.User{
					Name:     proto.String("user-a"),
					Password: proto.String("pass-a"),
				},
				Servers: []*mieruPB.ServerEndpoint{
					{
						DomainName: proto.String("mieru.example.com"),
						PortBindings: []*mieruPB.PortBinding{
							{
								Port:     proto.Int32(8088),
								Protocol: mieruPB.TransportProtocol_TCP.Enum(),
							},
						},
					},
				},
			},
		},
		ActiveProfile: proto.String("cfg-profile"),
	})
	if err != nil {
		t.Fatalf("ClientConfigToURL failed: %v", err)
	}

	nodes, err := protocol.ParseMieru(configURL)
	if err != nil {
		t.Fatalf("ParseMieru config URL failed: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 mieru node, got %d", len(nodes))
	}

	node := nodes[0]
	if node.Server != "mieru.example.com" {
		t.Fatalf("server: got %q", node.Server)
	}
	if node.Port != 8088 {
		t.Fatalf("port: got %d", node.Port)
	}
	if node.Transport != "TCP" {
		t.Fatalf("transport: got %q", node.Transport)
	}
}

func TestParseClashMetaMieruNodes(t *testing.T) {
	raw := []byte(`
proxies:
  - { name: demo-mieru, type: mieru, server: 16de.cloudfrontcdn.com, port: 8088, transport: TCP, username: demo-user, password: demo-pass, multiplexing: MULTIPLEXING_LOW, traffic-pattern: CMzM1AkQABoECAEQAiIICAIQABgGIAg= }
`)

	nodes, err := protocol.ParseClashMetaNodes(raw)
	if err != nil {
		t.Fatalf("ParseClashMetaNodes failed: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}

	node := nodes[0]
	if node.Type != "mieru" {
		t.Fatalf("type: got %q", node.Type)
	}
	if node.Server != "16de.cloudfrontcdn.com" {
		t.Fatalf("server: got %q", node.Server)
	}
	if node.Port != 8088 {
		t.Fatalf("port: got %d", node.Port)
	}
	if node.Transport != "TCP" {
		t.Fatalf("transport: got %q", node.Transport)
	}
	if node.TrafficPattern == "" {
		t.Fatal("traffic-pattern should not be empty")
	}
}
