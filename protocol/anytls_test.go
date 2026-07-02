package protocol

import (
	"strings"
	"testing"
)

func TestParseAnyTLSDefaultsToCertificateVerification(t *testing.T) {
	node, err := ParseAnyTLS("anytls://secret@example.com:4430?sni=front.example#secure")
	if err != nil {
		t.Fatalf("ParseAnyTLS() error = %v", err)
	}
	if node.SkipCertVerify {
		t.Fatal("AnyTLS should verify certificates by default")
	}
}

func TestParseAnyTLSAllowsExplicitInsecureMode(t *testing.T) {
	tests := []string{
		"anytls://secret@example.com:4430?skip_cert_verify=true#insecure",
		"anytls://secret@example.com:4430?allow_insecure=1#insecure",
		"anytls://secret@example.com:4430?allowInsecure=1#insecure",
		"anytls://secret@example.com:4430?insecure=1#insecure",
	}

	for _, link := range tests {
		node, err := ParseAnyTLS(link)
		if err != nil {
			t.Fatalf("ParseAnyTLS(%q) error = %v", link, err)
		}
		if !node.SkipCertVerify {
			t.Fatalf("ParseAnyTLS(%q) did not preserve explicit insecure mode", link)
		}
	}
}

func TestExportAnyTLSRoundTripsSkipCertVerify(t *testing.T) {
	link, err := ExportNodeLink(Node{
		Type:           "anytls",
		Name:           "insecure",
		Server:         "example.com",
		Port:           4430,
		Password:       "secret",
		SNI:            "front.example",
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("ExportNodeLink() error = %v", err)
	}
	if !strings.Contains(link, "skip_cert_verify=true") {
		t.Fatalf("exported AnyTLS link %q does not encode explicit insecure mode", link)
	}

	node, err := ParseAnyTLS(link)
	if err != nil {
		t.Fatalf("ParseAnyTLS(exported link) error = %v", err)
	}
	if !node.SkipCertVerify {
		t.Fatal("AnyTLS insecure mode was not preserved after export/import")
	}
}

func TestExportAnyTLSSecureModeOmitsInsecureFlag(t *testing.T) {
	link, err := ExportNodeLink(Node{
		Type:     "anytls",
		Name:     "secure",
		Server:   "example.com",
		Port:     4430,
		Password: "secret",
		SNI:      "front.example",
	})
	if err != nil {
		t.Fatalf("ExportNodeLink() error = %v", err)
	}
	if strings.Contains(link, "skip_cert_verify") {
		t.Fatalf("secure AnyTLS link %q unexpectedly includes skip_cert_verify", link)
	}

	node, err := ParseAnyTLS(link)
	if err != nil {
		t.Fatalf("ParseAnyTLS(exported link) error = %v", err)
	}
	if node.SkipCertVerify {
		t.Fatal("AnyTLS secure mode became insecure after export/import")
	}
}
