package sub

import (
	"bytes"
	"path/filepath"
	"testing"

	"wing/pkg/secure"
	"wing/pkg/storage"
	"wing/protocol"
)

func useTempDB(t *testing.T) {
	t.Helper()
	if err := storage.Close(); err != nil {
		t.Fatalf("close existing db: %v", err)
	}
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() {
		_ = storage.Close()
	})
}

func TestSaveNodesToYAMLEncryptsStoredNodeSecrets(t *testing.T) {
	useTempDB(t)

	node := protocol.Node{
		Type:     "vless",
		Name:     "secure-node",
		Server:   "example.com",
		Port:     443,
		UUID:     "00000000-0000-0000-0000-000000000001",
		Password: "secret",
	}
	if err := SaveNodesToYAML("nodes.yml", []protocol.Node{node}); err != nil {
		t.Fatalf("SaveNodesToYAML() error = %v", err)
	}

	raw, err := storage.Read("nodes.yml")
	if err != nil {
		t.Fatalf("read raw node data: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte(secure.MagicHeaderV2)) {
		t.Fatalf("node data was not encrypted with current format: %q", raw[:min(len(raw), 32)])
	}
	if bytes.Contains(raw, []byte(node.UUID)) || bytes.Contains(raw, []byte(node.Password)) {
		t.Fatalf("node data leaked plaintext secret: %q", raw[:min(len(raw), 32)])
	}

	nodes, err := protocol.ParseNodes("nodes.yml")
	if err != nil {
		t.Fatalf("ParseNodes() error = %v", err)
	}
	if len(nodes) != 1 || nodes[0].UUID != node.UUID {
		t.Fatalf("unexpected parsed nodes: %+v", nodes)
	}
}

func TestAppendSubscriptionEncryptsStoredSubscriptionURL(t *testing.T) {
	useTempDB(t)

	if _, _, err := AppendSubscriptionWithTraffic("https://example.com/sub", nil); err != nil {
		t.Fatalf("AppendSubscriptionWithTraffic() error = %v", err)
	}

	raw, err := storage.Read(SubscriptionsFile)
	if err != nil {
		t.Fatalf("read raw subscription data: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte(secure.MagicHeaderV2)) {
		t.Fatalf("subscription data was not encrypted with current format: %q", raw[:min(len(raw), 32)])
	}
	if bytes.Contains(raw, []byte("https://example.com/sub")) {
		t.Fatalf("subscription data leaked plaintext URL: %q", raw[:min(len(raw), 32)])
	}

	links, err := ReadSubscriptions()
	if err != nil {
		t.Fatalf("ReadSubscriptions() error = %v", err)
	}
	if len(links) != 1 || links[0].URL != "https://example.com/sub" {
		t.Fatalf("unexpected subscriptions: %+v", links)
	}
}

func TestAppendSubscriptionUsesUniqueFileNamesAfterDeletion(t *testing.T) {
	useTempDB(t)

	firstFile, _, err := AppendSubscriptionWithTraffic("https://one.example/sub", nil)
	if err != nil {
		t.Fatalf("append first subscription: %v", err)
	}
	secondFile, _, err := AppendSubscriptionWithTraffic("https://two.example/sub", nil)
	if err != nil {
		t.Fatalf("append second subscription: %v", err)
	}

	DeleteSubscription("https://one.example/sub")

	thirdFile, _, err := AppendSubscriptionWithTraffic("https://three.example/sub", nil)
	if err != nil {
		t.Fatalf("append third subscription: %v", err)
	}
	if thirdFile == firstFile || thirdFile == secondFile {
		t.Fatalf("new subscription reused file name %q after deletion; existing were %q and %q", thirdFile, firstFile, secondFile)
	}

	links, err := ReadSubscriptions()
	if err != nil {
		t.Fatalf("ReadSubscriptions() error = %v", err)
	}
	seen := map[string]bool{}
	for _, link := range links {
		if seen[link.FileName] {
			t.Fatalf("duplicate subscription file name %q in %+v", link.FileName, links)
		}
		seen[link.FileName] = true
	}
}
