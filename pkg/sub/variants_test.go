package sub

import (
	"testing"

	"wing/protocol"
)

func TestMergeSubscriptionVariantsKeepsBaseOrderAndAddsUniqueNodes(t *testing.T) {
	clashVariant := []protocol.Node{
		{Type: "hysteria2", Name: "hy-hop", Server: "a.example.com", Port: 45143, Ports: "40000-50000", Password: "p"},
		{Type: "mieru", Name: "mieru", Server: "m.example.com", Port: 8088, Username: "u", Password: "p"},
		{Type: "anytls", Name: "anytls", Server: "a.example.com", Port: 4430, Password: "p"},
	}
	singBoxVariant := []protocol.Node{
		{Type: "hysteria2", Name: "hy-single", Server: "a.example.com", Port: 41000, Password: "p"},
		{Type: "anytls", Name: "anytls renamed", Server: "a.example.com", Port: 4430, Password: "p"},
		{Type: "naive", Name: "naive", Server: "n.example.com", Port: 443, Username: "u", Password: "p"},
	}

	merged := mergeSubscriptionVariants([][]protocol.Node{clashVariant, singBoxVariant})
	var names []string
	for _, node := range merged {
		names = append(names, node.Name)
	}
	want := []string{"hy-hop", "mieru", "anytls", "naive"}
	if len(names) != len(want) {
		t.Fatalf("merged names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("merged names = %v, want %v", names, want)
		}
	}
}

func TestAllPlaceholderNodesDetectsOutdatedClientResponse(t *testing.T) {
	placeholders := []protocol.Node{
		{Type: "ss", Name: "client too old", Server: "1.1.1.1", Port: 1080, Password: "fake_node_password"},
		{Type: "ss", Name: "docs", Server: "1.1.1.1", Port: 1080, Password: "fake_node_password"},
	}
	if !allPlaceholderNodes(placeholders) {
		t.Fatal("expected placeholder-only response to be rejected")
	}
	real := append(placeholders, protocol.Node{Type: "anytls", Server: "a.example.com", Port: 4430, Password: "p"})
	if allPlaceholderNodes(real) {
		t.Fatal("expected response with a real node to be accepted")
	}
}
