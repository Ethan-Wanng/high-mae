package test

import (
	"high-mae/pkg/sub"
	"high-mae/pkg/utils"
	"high-mae/protocol"
	"path/filepath"
	"testing"
)

func TestSaveNodesToYAML(t *testing.T) {
	nodes := []protocol.Node{
		{
			Name:   "Test Node 1",
			Type:   "vless",
			Server: "1.2.3.4",
			Port:   443,
			UUID:   "uuid-1234",
			TLS:    true,
		},
		{
			Name:     "Test Node 2",
			Type:     "hysteria2",
			Server:   "5.6.7.8",
			Port:     8443,
			Password: "pass",
		},
	}

	tempFile := filepath.Join(t.TempDir(), "test_nodes.yml")

	err := sub.SaveNodesToYAML(tempFile, nodes)
	if err != nil {
		t.Fatalf("Failed to save nodes: %v", err)
	}

	data, _ := utils.SecureReadFile(tempFile)
	t.Logf("Generated YAML:\n%s", string(data))

	// Now try to read them back using protocol.ParseNodes
	parsedNodes, err := protocol.ParseNodes(tempFile)
	if err != nil {
		t.Fatalf("Failed to parse nodes back: %v", err)
	}

	if len(parsedNodes) != len(nodes) {
		t.Fatalf("Expected %d nodes, got %d", len(nodes), len(parsedNodes))
	}

	if parsedNodes[0].Name != nodes[0].Name {
		t.Errorf("Expected node 0 name %s, got %s", nodes[0].Name, parsedNodes[0].Name)
	}

	if parsedNodes[1].Type != nodes[1].Type {
		t.Errorf("Expected node 1 type %s, got %s", nodes[1].Type, parsedNodes[1].Type)
	}
}
