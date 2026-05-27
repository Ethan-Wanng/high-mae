package proxy

import (
	"errors"
	"testing"

	"wing/protocol"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/metadata"
)

func TestBuildSingBoxOptionsNaiveUsesNaiveOutbound(t *testing.T) {
	opts, err := buildSingBoxOptions(protocol.Node{
		Type:                "naive",
		Server:              "example.com",
		Port:                443,
		Username:            "user",
		Password:            "pass",
		SNI:                 "sni.example.com",
		QUIC:                true,
		QUICCongestion:      "bbr",
		InsecureConcurrency: 4,
		ExtraHeaders: map[string]string{
			"X-Test": "1",
		},
	}, "")
	if err != nil {
		t.Fatalf("buildSingBoxOptions() error = %v", err)
	}
	if len(opts.Outbounds) != 1 {
		t.Fatalf("len(Outbounds) = %d, want 1", len(opts.Outbounds))
	}
	if opts.Outbounds[0].Type != "naive" {
		t.Fatalf("outbound type = %q, want naive", opts.Outbounds[0].Type)
	}

	naive, ok := opts.Outbounds[0].Options.(*option.NaiveOutboundOptions)
	if !ok {
		t.Fatalf("outbound options type = %T, want *option.NaiveOutboundOptions", opts.Outbounds[0].Options)
	}
	if !naive.QUIC {
		t.Fatalf("naive.QUIC = false, want true")
	}
	if naive.QUICCongestionControl != "bbr" {
		t.Fatalf("QUICCongestionControl = %q, want bbr", naive.QUICCongestionControl)
	}
	if naive.TLS == nil || !naive.TLS.Enabled || naive.TLS.ServerName != "sni.example.com" {
		t.Fatalf("TLS options = %+v", naive.TLS)
	}
	if got := naive.ExtraHeaders["X-Test"]; len(got) != 1 || got[0] != "1" {
		t.Fatalf("ExtraHeaders = %#v", badoption.HTTPHeader(naive.ExtraHeaders))
	}
}

func TestBuildSingBoxOptionsUsesResolvedServerAddress(t *testing.T) {
	opts, err := buildSingBoxOptions(protocol.Node{
		Type:           "trojan",
		Server:         "edge.example.com",
		Port:           443,
		Password:       "pass",
		SNI:            "edge.example.com",
		SkipCertVerify: true,
	}, "203.0.113.8")
	if err != nil {
		t.Fatalf("buildSingBoxOptions() error = %v", err)
	}

	trojan, ok := opts.Outbounds[0].Options.(*option.TrojanOutboundOptions)
	if !ok {
		t.Fatalf("outbound options type = %T, want *option.TrojanOutboundOptions", opts.Outbounds[0].Options)
	}
	if trojan.Server != "203.0.113.8" {
		t.Fatalf("Server = %q, want resolved IP", trojan.Server)
	}
	if trojan.TLS == nil || trojan.TLS.ServerName != "edge.example.com" {
		t.Fatalf("TLS ServerName = %+v, want original domain", trojan.TLS)
	}
}

func TestParseMieruTransportAcceptsQUICAlias(t *testing.T) {
	transport, err := parseMieruTransport("QUIC")
	if err != nil {
		t.Fatalf("parseMieruTransport() error = %v", err)
	}
	if transport.String() != "UDP" {
		t.Fatalf("parseMieruTransport() = %s, want UDP", transport.String())
	}
}

func TestSelectResolvedIPHonorsPreferIPv6(t *testing.T) {
	got := selectResolvedIP([]string{"192.0.2.10", "2001:db8::10"}, "prefer_ipv6")
	if got != "2001:db8::10" {
		t.Fatalf("selectResolvedIP() = %q, want IPv6", got)
	}
}

func TestSelectResolvedIPDefaultsToIPv4(t *testing.T) {
	got := selectResolvedIP([]string{"2001:db8::10", "192.0.2.10"}, "")
	if got != "192.0.2.10" {
		t.Fatalf("selectResolvedIP() = %q, want IPv4", got)
	}
}

func TestMieruResolvedDestinationFallback(t *testing.T) {
	fallback, ok := mieruResolvedDestinationAddr(
		metadata.ParseSocksaddr("localhost:80"),
		errors.New("failed to read socks5 connection response from the server: EOF"),
	)
	if !ok {
		t.Fatalf("mieruResolvedDestinationAddr() ok = false, want true")
	}
	if fallback.IP == nil || fallback.FQDN != "" || fallback.Port != 80 {
		t.Fatalf("fallback = %+v, want resolved IP destination on port 80", fallback)
	}
}

func TestMieruResolvedDestinationFallbackIgnoresGenericError(t *testing.T) {
	_, ok := mieruResolvedDestinationAddr(
		metadata.ParseSocksaddr("localhost:80"),
		errors.New("some other error"),
	)
	if ok {
		t.Fatalf("mieruResolvedDestinationAddr() ok = true, want false")
	}
}
