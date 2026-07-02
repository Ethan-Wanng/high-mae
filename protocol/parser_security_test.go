package protocol

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoadInputRejectsPlainHTTPRemoteSubscription(t *testing.T) {
	_, err := LoadInputWithUserAgentInfoContext(context.Background(), "http://example.com/sub", "wing/1.0")
	if err == nil {
		t.Fatal("expected plain HTTP subscription URL to be rejected")
	}
	if !strings.Contains(err.Error(), "明文 HTTP") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadInputRejectsPrivateHTTPSRemoteSubscription(t *testing.T) {
	_, err := LoadInputWithUserAgentInfoContext(context.Background(), "https://127.0.0.1/sub", "wing/1.0")
	if err == nil {
		t.Fatal("expected private HTTPS subscription URL to be rejected")
	}
	if !strings.Contains(err.Error(), "local or private") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadInputKeepsAuthenticatedHTTPProxyLinkAsRawInput(t *testing.T) {
	link := "http://user:pass@example.com:8080#node"
	result, err := LoadInputWithUserAgentInfoContext(context.Background(), link, "wing/1.0")
	if err != nil {
		t.Fatalf("expected authenticated HTTP proxy link to stay parseable as raw input: %v", err)
	}
	if string(result.Body) != link {
		t.Fatalf("unexpected body: %q", result.Body)
	}
}

func TestSubscriptionTransportDoesNotSkipTLSVerification(t *testing.T) {
	transport := subscriptionTransport(nil, false)
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("subscription transport must not skip TLS certificate verification")
	}
}

func TestNormalizeSubscriptionRejectsOversizedInput(t *testing.T) {
	_, err := NormalizeSubscription(bytes.Repeat([]byte("a"), maxSubscriptionResponseBytes+1))
	if err == nil {
		t.Fatal("expected oversized subscription input to be rejected")
	}
}

func TestTryGzipRejectsOversizedDecodedData(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(bytes.Repeat([]byte("a"), maxSubscriptionGzipBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := tryGzip(compressed.Bytes()); err == nil {
		t.Fatal("expected oversized gzip payload to be rejected")
	}
}

func TestParseVMessRejectsMissingServerOrUUID(t *testing.T) {
	raw := base64.StdEncoding.EncodeToString([]byte(`{"ps":"bad","add":"example.com","port":"443"}`))
	if _, err := ParseVMess("vmess://" + raw); err == nil {
		t.Fatal("expected vmess without uuid to be rejected")
	}

	raw = base64.StdEncoding.EncodeToString([]byte(`{"ps":"bad","id":"uuid","port":"443"}`))
	if _, err := ParseVMess("vmess://" + raw); err == nil {
		t.Fatal("expected vmess without server to be rejected")
	}
}

func TestParseSSSupportsBracketedIPv6(t *testing.T) {
	node, err := ParseSS("ss://aes-128-gcm:secret@[2001:db8::1]:8388#v6")
	if err != nil {
		t.Fatalf("ParseSS returned error: %v", err)
	}
	if node.Server != "2001:db8::1" || node.Port != 8388 {
		t.Fatalf("unexpected node endpoint: %+v", node)
	}
}

func TestParseSSocksSupportsBracketedIPv6(t *testing.T) {
	node, err := ParseSSocks("ssocks://user:pass@[2001:db8::2]:1080?remarks=v6")
	if err != nil {
		t.Fatalf("ParseSSocks returned error: %v", err)
	}
	if node.Server != "2001:db8::2" || node.Port != 1080 || node.SNI != "2001:db8::2" {
		t.Fatalf("unexpected node endpoint: %+v", node)
	}
}
