package freeflow

import "testing"

const testNodeLink = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=tls&sni=example.com#env-node"

func TestNodeRequiresConfiguredLink(t *testing.T) {
	oldPackagedNodeLink := packagedNodeLink
	packagedNodeLink = ""
	t.Cleanup(func() { packagedNodeLink = oldPackagedNodeLink })
	t.Setenv(nodeLinkEnv, "")

	if _, err := Node(); err == nil {
		t.Fatal("Node() should fail when no free-flow node link is configured")
	}
}

func TestNodeUsesEnvConfiguredLink(t *testing.T) {
	oldPackagedNodeLink := packagedNodeLink
	packagedNodeLink = ""
	t.Cleanup(func() { packagedNodeLink = oldPackagedNodeLink })
	t.Setenv(nodeLinkEnv, testNodeLink)

	node, err := Node()
	if err != nil {
		t.Fatalf("Node() error = %v", err)
	}
	if node.Name != NodeName || node.SourceKey != nodeSourceKey || node.SourceName != NodeName {
		t.Fatalf("Node() metadata = name:%q sourceKey:%q sourceName:%q", node.Name, node.SourceKey, node.SourceName)
	}
	if node.Server != "example.com" {
		t.Fatalf("Node() server = %q, want example.com", node.Server)
	}
}

func TestNodeUsesPackagedLinkFallback(t *testing.T) {
	oldPackagedNodeLink := packagedNodeLink
	packagedNodeLink = testNodeLink
	t.Cleanup(func() { packagedNodeLink = oldPackagedNodeLink })
	t.Setenv(nodeLinkEnv, "")

	node, err := Node()
	if err != nil {
		t.Fatalf("Node() error = %v", err)
	}
	if node.Server != "example.com" {
		t.Fatalf("Node() server = %q, want example.com", node.Server)
	}
}
