package proxy

import (
	"net/netip"
	"testing"
	"time"
	"wing/pkg/common"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func TestToggleTunModeState(t *testing.T) {
	common.SetTunModeOn(false)

	// Verify that state changes are instant and do not lock or throw errors
	common.SetTunModeOn(true)
	if !common.GetTunModeOn() {
		t.Errorf("Expected IsTunModeOn to be true")
	}

	common.SetTunModeOn(false)
	if common.GetTunModeOn() {
		t.Errorf("Expected IsTunModeOn to be false")
	}
}

func TestBuildTunBoxOptionsUsesInternalTunAndLocalSocks(t *testing.T) {
	oldConfig := GlobalSystemConfig
	GlobalSystemConfig.PreferIPv6 = false
	t.Cleanup(func() { GlobalSystemConfig = oldConfig })

	opts, err := buildTunBoxOptions("203.0.113.8")
	if err != nil {
		t.Fatalf("buildTunBoxOptions() error = %v", err)
	}

	if opts.Log == nil || !opts.Log.Disabled || opts.Log.Level != "error" {
		t.Fatalf("log options = %+v, want disabled error logging", opts.Log)
	}
	if opts.DNS == nil || len(opts.DNS.Servers) != 1 || opts.DNS.Final != tunLocalDNSTag {
		t.Fatalf("DNS options = %+v, want local DNS server as final", opts.DNS)
	}
	if opts.DNS.Strategy != option.DomainStrategy(C.DomainStrategyIPv4Only) {
		t.Fatalf("DNS strategy = %d, want IPv4 only", opts.DNS.Strategy)
	}
	dnsOptions, ok := opts.DNS.Servers[0].Options.(*option.RemoteDNSServerOptions)
	if !ok {
		t.Fatalf("DNS server options type = %T, want *option.RemoteDNSServerOptions", opts.DNS.Servers[0].Options)
	}
	if opts.DNS.Servers[0].Type != C.DNSTypeUDP || opts.DNS.Servers[0].Tag != tunLocalDNSTag ||
		dnsOptions.Server != "127.0.0.2" || dnsOptions.ServerPort != 53 {
		t.Fatalf("DNS server = %+v/%+v, want UDP 127.0.0.2:53", opts.DNS.Servers[0], dnsOptions)
	}

	if len(opts.Inbounds) != 1 {
		t.Fatalf("len(Inbounds) = %d, want 1", len(opts.Inbounds))
	}
	if opts.Inbounds[0].Type != C.TypeTun || opts.Inbounds[0].Tag != tunInboundTag {
		t.Fatalf("inbound = %+v, want tagged TUN inbound", opts.Inbounds[0])
	}
	tunOptions, ok := opts.Inbounds[0].Options.(*option.TunInboundOptions)
	if !ok {
		t.Fatalf("inbound options type = %T, want *option.TunInboundOptions", opts.Inbounds[0].Options)
	}
	if tunOptions.InterfaceName != tunInterfaceName {
		t.Fatalf("InterfaceName = %q, want %q", tunOptions.InterfaceName, tunInterfaceName)
	}
	if tunOptions.MTU != tunMTU {
		t.Fatalf("MTU = %d, want %d", tunOptions.MTU, tunMTU)
	}
	wantTunAddress := netip.MustParsePrefix(tunInterfaceAddress)
	if len(tunOptions.Address) != 1 || tunOptions.Address[0] != wantTunAddress {
		t.Fatalf("Address = %v, want [%s]", tunOptions.Address, wantTunAddress)
	}
	if !tunOptions.AutoRoute || !tunOptions.StrictRoute {
		t.Fatalf("AutoRoute/StrictRoute = %v/%v, want true/true", tunOptions.AutoRoute, tunOptions.StrictRoute)
	}
	if tunOptions.Stack != tunStack {
		t.Fatalf("Stack = %q, want %q", tunOptions.Stack, tunStack)
	}
	if time.Duration(tunOptions.UDPTimeout) != tunUDPTimeout {
		t.Fatalf("UDPTimeout = %s, want %s", time.Duration(tunOptions.UDPTimeout), tunUDPTimeout)
	}
	if tunOptions.Detour != "" {
		t.Fatalf("Detour = %q, want empty; routing is handled by explicit rules", tunOptions.Detour)
	}
	wantExclude := netip.MustParsePrefix("203.0.113.8/32")
	if len(tunOptions.RouteExcludeAddress) != 1 || tunOptions.RouteExcludeAddress[0] != wantExclude {
		t.Fatalf("RouteExcludeAddress = %v, want [%s]", tunOptions.RouteExcludeAddress, wantExclude)
	}

	if len(opts.Outbounds) != 1 {
		t.Fatalf("len(Outbounds) = %d, want 1", len(opts.Outbounds))
	}
	if opts.Outbounds[0].Type != C.TypeSOCKS || opts.Outbounds[0].Tag != tunLocalSocksTag {
		t.Fatalf("outbound = %+v, want tagged SOCKS outbound", opts.Outbounds[0])
	}
	socksOptions, ok := opts.Outbounds[0].Options.(*option.SOCKSOutboundOptions)
	if !ok {
		t.Fatalf("outbound options type = %T, want *option.SOCKSOutboundOptions", opts.Outbounds[0].Options)
	}
	if socksOptions.Server != "127.0.0.1" || socksOptions.ServerPort != 10810 || socksOptions.Version != "5" {
		t.Fatalf("SOCKS options = %+v, want local SOCKS5 on 127.0.0.1:10810", socksOptions)
	}
	if opts.Route == nil || opts.Route.Final != tunLocalSocksTag || !opts.Route.AutoDetectInterface {
		t.Fatalf("route options = %+v, want final local SOCKS with auto interface detection", opts.Route)
	}
	if len(opts.Route.Rules) != 3 {
		t.Fatalf("len(Route.Rules) = %d, want 3", len(opts.Route.Rules))
	}
	dnsRule := opts.Route.Rules[0].DefaultOptions
	if len(dnsRule.Inbound) != 1 || dnsRule.Inbound[0] != tunInboundTag ||
		len(dnsRule.Port) != 1 || dnsRule.Port[0] != 53 ||
		dnsRule.Action != C.RuleActionTypeHijackDNS {
		t.Fatalf("DNS rule = %+v, want TUN port 53 hijack", dnsRule)
	}
	icmpRule := opts.Route.Rules[1].DefaultOptions
	if len(icmpRule.Inbound) != 1 || icmpRule.Inbound[0] != tunInboundTag ||
		len(icmpRule.Network) != 1 || icmpRule.Network[0] != N.NetworkICMP ||
		icmpRule.Action != C.RuleActionTypeReject {
		t.Fatalf("ICMP rule = %+v, want TUN ICMP reject", icmpRule)
	}
	proxyRule := opts.Route.Rules[2].DefaultOptions
	if len(proxyRule.Inbound) != 1 || proxyRule.Inbound[0] != tunInboundTag ||
		len(proxyRule.Network) != 2 || proxyRule.Network[0] != N.NetworkTCP || proxyRule.Network[1] != N.NetworkUDP ||
		proxyRule.Action != C.RuleActionTypeRoute ||
		proxyRule.RouteOptions.Outbound != tunLocalSocksTag {
		t.Fatalf("proxy rule = %+v, want TUN route to local SOCKS", proxyRule)
	}
}

func TestBuildTunBoxOptionsUsesPreferIPv6WhenEnabled(t *testing.T) {
	oldConfig := GlobalSystemConfig
	GlobalSystemConfig.PreferIPv6 = true
	t.Cleanup(func() { GlobalSystemConfig = oldConfig })

	opts, err := buildTunBoxOptions("203.0.113.8")
	if err != nil {
		t.Fatalf("buildTunBoxOptions() error = %v", err)
	}
	if opts.DNS.Strategy != option.DomainStrategy(C.DomainStrategyPreferIPv6) {
		t.Fatalf("DNS strategy = %d, want prefer IPv6", opts.DNS.Strategy)
	}
}

func TestBuildTunBoxOptionsCanCreateSingBoxInstance(t *testing.T) {
	opts, err := buildTunBoxOptions("203.0.113.8")
	if err != nil {
		t.Fatalf("buildTunBoxOptions() error = %v", err)
	}
	instance, err := box.New(box.Options{
		Options: opts,
		Context: getRegistryContext(),
	})
	if err != nil {
		t.Fatalf("box.New() error = %v", err)
	}
	_ = instance.Close()
}

func TestBuildTunBoxOptionsSkipsInvalidNodeExclude(t *testing.T) {
	opts, err := buildTunBoxOptions("not-an-ip")
	if err != nil {
		t.Fatalf("buildTunBoxOptions() error = %v", err)
	}
	tunOptions, ok := opts.Inbounds[0].Options.(*option.TunInboundOptions)
	if !ok {
		t.Fatalf("inbound options type = %T, want *option.TunInboundOptions", opts.Inbounds[0].Options)
	}
	if len(tunOptions.RouteExcludeAddress) != 0 {
		t.Fatalf("RouteExcludeAddress = %v, want empty", tunOptions.RouteExcludeAddress)
	}
}

func TestTunNodeRoutePrefixOnlyAcceptsIPv4(t *testing.T) {
	prefix, ok := tunNodeRoutePrefix("198.51.100.9")
	if !ok || prefix != netip.MustParsePrefix("198.51.100.9/32") {
		t.Fatalf("tunNodeRoutePrefix IPv4 = %s/%v, want 198.51.100.9/32 true", prefix, ok)
	}
	if _, ok := tunNodeRoutePrefix("2001:db8::1"); ok {
		t.Fatalf("tunNodeRoutePrefix IPv6 ok = true, want false")
	}
	if _, ok := tunNodeRoutePrefix("bad ip"); ok {
		t.Fatalf("tunNodeRoutePrefix invalid ok = true, want false")
	}
}
