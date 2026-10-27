package protocol

import "testing"

func TestParseHysteria2PinnedCertificateSkipsCAVerification(t *testing.T) {
	link := "hysteria2://secret@198.51.100.7:50000?insecure=false&sni=www.microsoft.com" +
		"&pinSHA256=B4:6E:09:C2&mport=50000-53000#pinned"
	node, err := ParseHysteria2(link)
	if err != nil {
		t.Fatalf("ParseHysteria2() error = %v", err)
	}
	if !node.SkipCertVerify || node.CertificateFingerprint != "b46e09c2" {
		t.Fatalf("pinned node: skip=%v fingerprint=%q, want skip with normalized pin", node.SkipCertVerify, node.CertificateFingerprint)
	}
	if node.PortRange != "50000-53000" || node.SNI != "www.microsoft.com" {
		t.Fatalf("pinned node: portRange=%q sni=%q", node.PortRange, node.SNI)
	}
}

func TestParseHysteria2InsecureFlagVariants(t *testing.T) {
	for query, want := range map[string]bool{
		"insecure=1":    true,
		"insecure=true": true,
		"insecure=0":    false,
		"":              false,
	} {
		node, err := ParseHysteria2("hysteria2://secret@198.51.100.7:443?" + query + "#n")
		if err != nil {
			t.Fatalf("ParseHysteria2(%q) error = %v", query, err)
		}
		if node.SkipCertVerify != want {
			t.Fatalf("ParseHysteria2(%q) SkipCertVerify = %v, want %v", query, node.SkipCertVerify, want)
		}
	}
}
