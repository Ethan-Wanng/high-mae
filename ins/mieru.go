package ins

import (
	"context"
	"fmt"
	"net"
	"strings"

	mieruClient "github.com/enfein/mieru/v3/apis/client"
	mieruModel "github.com/enfein/mieru/v3/apis/model"
	mieruTraffic "github.com/enfein/mieru/v3/apis/trafficpattern"
	mieruPB "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing/common/metadata"
	"google.golang.org/protobuf/proto"

	"high-mae/protocol"
)

var currentMieru *MieruClientAdapter

type MieruClientAdapter struct {
	client mieruClient.Client
}

func (m *MieruClientAdapter) CreateProxy(ctx context.Context, destination metadata.Socksaddr) (net.Conn, error) {
	if m == nil || m.client == nil {
		return nil, fmt.Errorf("mieru client is nil")
	}

	addr := mieruModel.NetAddrSpec{
		Net: "tcp",
	}
	if destination.IsIP() {
		addr.IP = net.IP(destination.Addr.AsSlice())
	} else {
		addr.FQDN = destination.Fqdn
	}
	addr.Port = int(destination.Port)

	return m.client.DialContext(ctx, addr)
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

	client := mieruClient.NewClient()
	if err := client.Store(&mieruClient.ClientConfig{Profile: profile}); err != nil {
		return nil, err
	}
	if err := client.Start(); err != nil {
		return nil, err
	}

	return &MieruClientAdapter{client: client}, nil
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
		// 已经是 IP，直接使用
		server.IpAddress = proto.String(ip.String())
	} else {
		// 域名：必须预解析为 IP，因为 mieru 内部的 ResolveTCPAddr() 不支持域名解析
		resolved := resolveDirect(node.Server)
		if resolved != "" {
			server.IpAddress = proto.String(resolved)
		} else {
			// 解析失败仍然使用域名，让 mieru 尝试（大概率会失败，但至少报错更明确）
			server.DomainName = proto.String(node.Server)
		}
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

	if multiplexing, ok := parseMieruMultiplexing(node.Multiplexing); ok {
		profile.Multiplexing = &mieruPB.MultiplexingConfig{
			Level: multiplexing.Enum(),
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
	case "UDP":
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
