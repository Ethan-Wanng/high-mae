package protocol

import (
	"context"
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
