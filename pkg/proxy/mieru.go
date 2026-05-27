package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	mieruClient "github.com/enfein/mieru/v3/apis/client"
	mieruConstant "github.com/enfein/mieru/v3/apis/constant"
	mieruModel "github.com/enfein/mieru/v3/apis/model"
	mieruTraffic "github.com/enfein/mieru/v3/apis/trafficpattern"
	mieruCommon "github.com/enfein/mieru/v3/apis/common"
	mieruAppctlCommon "github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	mieruPB "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mieruProtocol "github.com/enfein/mieru/v3/pkg/protocol"
	mieruSocks5 "github.com/enfein/mieru/v3/pkg/socks5"
	"github.com/sagernet/sing/common/metadata"
	"google.golang.org/protobuf/proto"

	"high-mae/pkg/common"
	"high-mae/pkg/utils"
	"high-mae/protocol"
)

type mieruRuntime interface {
	common.GenericClient
	Close() error
}

var currentMieru mieruRuntime

type MieruClientAdapter struct {
	client mieruClient.Client
}

type MieruSocks5Adapter struct {
	mux       *mieruProtocol.Mux
	server    *mieruSocks5.Server
	listener  net.Listener
	serveDone chan struct{}
	dial      func(string, string) (net.Conn, error)
}

func (m *MieruClientAdapter) CreateProxy(ctx context.Context, destination metadata.Socksaddr) (net.Conn, error) {
	if m == nil || m.client == nil {
		return nil, fmt.Errorf("mieru client is nil")
	}

	addr := mieruDestinationAddr(destination)
	conn, err := m.client.DialContext(ctx, addr)
	if err == nil {
		return conn, nil
	}

	if fallback, ok := mieruResolvedDestinationAddr(destination, err); ok {
		retryConn, retryErr := m.client.DialContext(ctx, fallback)
		if retryErr == nil {
			return retryConn, nil
		}
		return nil, fmt.Errorf("%w; retry with resolved destination %s failed: %v", err, fallback.String(), retryErr)
	}

	return nil, err
}

func mieruDestinationAddr(destination metadata.Socksaddr) mieruModel.NetAddrSpec {
	addr := mieruModel.NetAddrSpec{
		Net: "tcp",
	}
	if destination.IsIP() {
		addr.IP = net.IP(destination.Addr.AsSlice())
	} else {
		addr.FQDN = destination.Fqdn
	}
	addr.Port = int(destination.Port)
	return addr
}

func mieruResolvedDestinationAddr(destination metadata.Socksaddr, err error) (mieruModel.NetAddrSpec, bool) {
	if err == nil || destination.IsIP() || strings.TrimSpace(destination.Fqdn) == "" {
		return mieruModel.NetAddrSpec{}, false
	}

	msg := err.Error()
	if !strings.Contains(msg, "failed to read socks5 connection response") && !strings.Contains(msg, "server returned socks5 error code") {
		return mieruModel.NetAddrSpec{}, false
	}

	resolved := ResolveDirect(destination.Fqdn)
	if resolved == "" {
		return mieruModel.NetAddrSpec{}, false
	}
	ip := net.ParseIP(resolved)
	if ip == nil {
		return mieruModel.NetAddrSpec{}, false
	}

	return mieruModel.NetAddrSpec{
		Net:      "tcp",
		AddrSpec: mieruModel.AddrSpec{IP: ip, Port: int(destination.Port)},
	}, true
}

func (m *MieruClientAdapter) Close() error {
	if m == nil || m.client == nil {
		return nil
	}
	return m.client.Stop()
}

func newMieruClientAdapter(node protocol.Node) (*MieruClientAdapter, error) {
	profile, err := buildMieruProfile(node)
	if err != nil {
		return nil, err
	}

	config := &mieruClient.ClientConfig{
		Profile:  profile,
		Resolver: mieruResolver{strategy: node.DomainStrategy},
		DNSConfig: &mieruCommon.ClientDNSConfig{
			BypassDialerDNS: false,
		},
	}
	if dialer, packetDialer := newMieruBypassDialers(); dialer != nil {
		config.Dialer = dialer
		config.PacketDialer = packetDialer
	}

	client := mieruClient.NewClient()
	if err := client.Store(config); err != nil {
		return nil, err
	}
	if err := client.Start(); err != nil {
		return nil, err
	}

	return &MieruClientAdapter{client: client}, nil
}

func newMieruSocks5Adapter(node protocol.Node, forceNoWait bool) (*MieruSocks5Adapter, error) {
	profile, err := buildMieruProfile(node)
	if err != nil {
		return nil, err
	}
	if forceNoWait {
		profile.HandshakeMode = mieruPB.HandshakeMode_HANDSHAKE_NO_WAIT.Enum()
	}

	dialer, packetDialer := newMieruBypassDialers()
	resolver := mieruResolver{strategy: node.DomainStrategy}
	var mux *mieruProtocol.Mux
	if dialer != nil {
		mux, err = mieruAppctlCommon.NewClientMuxFromProfile(profile, dialer, packetDialer, resolver, nil)
	} else {
		mux, err = mieruAppctlCommon.NewClientMuxFromProfile(profile, nil, nil, resolver, nil)
	}
	if err != nil {
		return nil, err
	}

	server, err := mieruSocks5.New(&mieruSocks5.Config{
		UseProxy: true,
		AuthOpts: mieruSocks5.Auth{
			ClientSideAuthentication: true,
		},
		ProxyMux:         mux,
		Resolver:         &net.Resolver{},
		HandshakeTimeout: 10 * time.Second,
		HandshakeNoWait:  forceNoWait || profile.GetHandshakeMode() == mieruPB.HandshakeMode_HANDSHAKE_NO_WAIT,
	})
	if err != nil {
		mux.Close()
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		mux.Close()
		return nil, err
	}

	adapter := &MieruSocks5Adapter{
		mux:       mux,
		server:    server,
		listener:  listener,
		serveDone: make(chan struct{}),
		dial:      mieruSocks5.Dial("socks5://"+listener.Addr().String()+"?timeout=12s", mieruConstant.Socks5ConnectCmd),
	}

	go func() {
		defer close(adapter.serveDone)
		_ = server.Serve(listener)
	}()

	return adapter, nil
}

func (m *MieruSocks5Adapter) CreateProxy(ctx context.Context, destination metadata.Socksaddr) (net.Conn, error) {
	if m == nil || m.dial == nil {
		return nil, fmt.Errorf("mieru socks5 adapter is nil")
	}

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := m.dial("tcp", destination.String())
		ch <- result{conn: conn, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.err == nil {
			return res.conn, nil
		}
		if fallback, ok := mieruResolvedDestinationAddr(destination, res.err); ok {
			conn, err := m.dial("tcp", fallback.String())
			if err == nil {
				return conn, nil
			}
			return nil, fmt.Errorf("%w; retry with resolved destination %s failed: %v", res.err, fallback.String(), err)
		}
		return nil, res.err
	}
}

func (m *MieruSocks5Adapter) Close() error {
	if m == nil {
		return nil
	}
	if m.server != nil {
		_ = m.server.Close()
	}
	if m.listener != nil {
		_ = m.listener.Close()
	}
	if m.mux != nil {
		m.mux.Close()
	}
	if m.serveDone != nil {
		select {
		case <-m.serveDone:
		case <-time.After(time.Second):
		}
	}
	return nil
}

func newMieruBypassDialers() (*net.Dialer, *mieruPacketDialer) {

	realIP := common.RealLocalIPBeforeTun
	if realIP == "" {
		realIP = utils.GetRealLocalIP()
	}
	if realIP == "" || realIP == common.TunIP {
		return nil, nil
	}

	ip := net.ParseIP(realIP)
	if ip == nil {
		return nil, nil
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: 0}
	return dialer, &mieruPacketDialer{localIP: ip}
}

type mieruPacketDialer struct {
	localIP net.IP
}

func (d *mieruPacketDialer) ListenPacket(ctx context.Context, network, laddr, raddr string) (net.PacketConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, net.UnknownNetworkError(network)
	}

	var localAddr *net.UDPAddr
	if strings.TrimSpace(laddr) != "" {
		addr, err := net.ResolveUDPAddr(network, laddr)
		if err != nil {
			return nil, fmt.Errorf("resolve UDP local address failed: %w", err)
		}
		localAddr = addr
	} else if d != nil && d.localIP != nil {
		localAddr = &net.UDPAddr{IP: d.localIP, Port: 0}
	}

	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, udpListenAddress(localAddr))
}

func udpListenAddress(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func buildMieruProfile(node protocol.Node) (*mieruPB.ClientProfile, error) {
	if node.Server == "" {
		return nil, fmt.Errorf("mieru server is empty")
	}
	if node.Username == "" {
		return nil, fmt.Errorf("mieru username is empty")
	}
	if node.Password == "" && node.HashedPassword == "" {
		return nil, fmt.Errorf("mieru password is empty")
	}
	if node.Port <= 0 && node.PortRange == "" {
		return nil, fmt.Errorf("mieru port is empty")
	}

	transport, err := parseMieruTransport(node.Transport)
	if err != nil {
		return nil, err
	}

	binding := &mieruPB.PortBinding{
		Protocol: transport.Enum(),
	}
	if node.PortRange != "" {
		binding.PortRange = proto.String(node.PortRange)
	} else {
		binding.Port = proto.Int32(int32(node.Port))
	}

	server := &mieruPB.ServerEndpoint{
		PortBindings: []*mieruPB.PortBinding{binding},
	}
	if ip := net.ParseIP(node.Server); ip != nil {
		server.IpAddress = proto.String(ip.String())
	} else {
		server.DomainName = proto.String(node.Server)
	}

	user := &mieruPB.User{
		Name: proto.String(node.Username),
	}
	if node.Password != "" {
		user.Password = proto.String(node.Password)
	}
	if node.HashedPassword != "" {
		user.HashedPassword = proto.String(node.HashedPassword)
	}

	profileName := node.Name
	if profileName == "" {
		profileName = node.Server
	}

	profile := &mieruPB.ClientProfile{
		ProfileName: proto.String(profileName),
		User:        user,
		Servers:     []*mieruPB.ServerEndpoint{server},
	}
	if node.Mtu > 0 {
		profile.Mtu = proto.Int32(int32(node.Mtu))
	}

	if node.Multiplexing != "" {
		if multiplexing, ok := parseMieruMultiplexing(node.Multiplexing); ok {
			profile.Multiplexing = &mieruPB.MultiplexingConfig{
				Level: multiplexing.Enum(),
			}
		}
	}

	if handshakeMode, ok := parseMieruHandshakeMode(node.HandshakeMode); ok {
		profile.HandshakeMode = handshakeMode.Enum()
	}

	if node.TrafficPattern != "" {
		pattern, err := mieruTraffic.Decode(node.TrafficPattern)
		if err != nil {
			return nil, fmt.Errorf("decode mieru traffic pattern failed: %w", err)
		}
		profile.TrafficPattern = pattern
	}

	return profile, nil
}

func parseMieruTransport(value string) (mieruPB.TransportProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "TCP":
		return mieruPB.TransportProtocol_TCP, nil
	case "UDP", "QUIC":
		return mieruPB.TransportProtocol_UDP, nil
	default:
		return mieruPB.TransportProtocol_UNKNOWN_TRANSPORT_PROTOCOL, fmt.Errorf("unsupported mieru transport: %s", value)
	}
}

func parseMieruMultiplexing(value string) (mieruPB.MultiplexingLevel, bool) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "MULTIPLEXING_DEFAULT":
		return mieruPB.MultiplexingLevel_MULTIPLEXING_DEFAULT, false
	case "OFF", "MULTIPLEXING_OFF":
		return mieruPB.MultiplexingLevel_MULTIPLEXING_OFF, true
	case "LOW", "MULTIPLEXING_LOW":
		return mieruPB.MultiplexingLevel_MULTIPLEXING_LOW, true
	case "MIDDLE", "MULTIPLEXING_MIDDLE":
		return mieruPB.MultiplexingLevel_MULTIPLEXING_MIDDLE, true
	case "HIGH", "MULTIPLEXING_HIGH":
		return mieruPB.MultiplexingLevel_MULTIPLEXING_HIGH, true
	default:
		return mieruPB.MultiplexingLevel_MULTIPLEXING_DEFAULT, false
	}
}

func parseMieruHandshakeMode(value string) (mieruPB.HandshakeMode, bool) {
	switch strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(value, "-", "_"))) {
	case "", "HANDSHAKE_DEFAULT":
		return mieruPB.HandshakeMode_HANDSHAKE_DEFAULT, false
	case "STANDARD", "HANDSHAKE_STANDARD":
		return mieruPB.HandshakeMode_HANDSHAKE_STANDARD, true
	case "NO_WAIT", "HANDSHAKE_NO_WAIT":
		return mieruPB.HandshakeMode_HANDSHAKE_NO_WAIT, true
	default:
		return mieruPB.HandshakeMode_HANDSHAKE_DEFAULT, false
	}
}

type mieruResolver struct {
	strategy string
}

func (r mieruResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	resolved := ResolveDirectWithStrategy(host, r.strategy)
	if resolved == "" {
		return nil, fmt.Errorf("failed to resolve %s", host)
	}
	ip := net.ParseIP(resolved)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", resolved)
	}
	return []net.IP{ip}, nil
}

