package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	mieruTraffic "github.com/enfein/mieru/v3/apis/trafficpattern"
	mieruAppctl "github.com/enfein/mieru/v3/pkg/appctl"
	mieruPB "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

func ExportNodeLink(node Node) (string, error) {
	host := net.JoinHostPort(node.Server, strconv.Itoa(node.Port))
	name := node.Name
	sni := firstNonEmpty(node.SNI, node.ServerName)

	switch strings.ToLower(node.Type) {
	case "vless":
		u := url.URL{Scheme: "vless", Host: host, Fragment: name}
		u.User = url.User(node.UUID)
		q := u.Query()
		network := firstNonEmpty(node.Network, "tcp")
		q.Set("type", network)
		if node.RealityOpts != nil && node.RealityOpts.PublicKey != "" {
			q.Set("security", "reality")
			q.Set("pbk", node.RealityOpts.PublicKey)
			if node.RealityOpts.ShortID != "" {
				q.Set("sid", node.RealityOpts.ShortID)
			}
		} else if node.TLS || node.Tls {
			q.Set("security", "tls")
		}
		setQuery(q, "flow", node.Flow)
		setQuery(q, "fp", node.ClientFingerprint)
		setQuery(q, "sni", sni)
		if node.SkipCertVerify {
			q.Set("allowInsecure", "1")
		}
		if network == "ws" || network == "websocket" {
			setQuery(q, "path", firstNonEmpty(node.WSOpts.Path, node.WSPath))
			setQuery(q, "host", firstHeaderValue(node.WSOpts.Headers, node.WSHeaders, node.Host))
		}
		if network == "grpc" {
			setQuery(q, "serviceName", firstNonEmpty(node.GrpcOpts["grpc-service-name"], node.WSOpts.Path))
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	case "trojan":
		u := url.URL{Scheme: "trojan", Host: host, Fragment: name}
		u.User = url.User(node.Password)
		q := u.Query()
		setQuery(q, "sni", sni)
		if node.SkipCertVerify {
			q.Set("allowInsecure", "1")
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	case "hysteria2", "hy2":
		u := url.URL{Scheme: "hysteria2", Host: host, Fragment: name}
		u.User = url.User(node.Password)
		q := u.Query()
		setQuery(q, "sni", sni)
		setQuery(q, "mport", firstNonEmpty(node.PortRange, node.Ports, node.MPort))
		setQuery(q, "obfs", node.Obfs)
		setQuery(q, "obfs-password", node.ObfsPassword)
		if node.SkipCertVerify {
			q.Set("insecure", "1")
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	case "tuic":
		u := url.URL{Scheme: "tuic", Host: host, Fragment: name}
		u.User = url.UserPassword(node.UUID, node.Password)
		q := u.Query()
		setQuery(q, "sni", sni)
		if len(node.ALPN) > 0 {
			setQuery(q, "alpn", node.ALPN[0])
		}
		setQuery(q, "congestion_control", node.CongestionControl)
		setQuery(q, "udp_relay_mode", node.UDPRelayMode)
		if node.SkipCertVerify {
			q.Set("allow_insecure", "1")
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	case "anytls":
		u := url.URL{Scheme: "anytls", Host: host, Fragment: name}
		u.User = url.User(node.Password)
		q := u.Query()
		setQuery(q, "sni", sni)
		if !node.SkipCertVerify {
			q.Set("skip_cert_verify", "false")
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	case "ss":
		method := firstNonEmpty(node.Method, node.Cipher)
		if method == "" || node.Password == "" {
			return "", fmt.Errorf("ss 节点缺少加密方式或密码")
		}
		auth := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + node.Password))
		return "ss://" + auth + "@" + host + "#" + url.QueryEscape(name), nil
	case "vmess":
		network := node.Network
		if network == "" {
			network = "tcp"
		}
		v := map[string]string{
			"v":    "2",
			"ps":   name,
			"add":  node.Server,
			"port": strconv.Itoa(node.Port),
			"id":   node.UUID,
			"aid":  strconv.Itoa(node.AlterId),
			"scy":  firstNonEmpty(node.Cipher, "auto"),
			"net":  network,
			"type": "none",
		}
		if node.TLS || node.Tls {
			v["tls"] = "tls"
		}
		setMap(v, "sni", sni)
		setMap(v, "path", firstNonEmpty(node.WSOpts.Path, node.WSPath))
		setMap(v, "host", firstHeaderValue(node.WSOpts.Headers, node.WSHeaders, node.Host))
		setMap(v, "grpc-service-name", node.GrpcOpts["grpc-service-name"])
		raw, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil
	case "http", "https", "socks", "socks5":
		scheme := strings.ToLower(node.Type)
		if scheme == "socks" {
			scheme = "socks5"
		}
		if scheme == "http" && (node.TLS || node.Tls || node.Port == 443) {
			scheme = "https"
		}
		u := url.URL{Scheme: scheme, Host: host, Fragment: name}
		if node.Username != "" || node.Password != "" {
			u.User = url.UserPassword(node.Username, node.Password)
		}
		q := u.Query()
		setQuery(q, "sni", sni)
		u.RawQuery = q.Encode()
		return u.String(), nil
	case "naive":
		scheme := "naive+https"
		if node.QUIC {
			scheme = "naive+quic"
		} else if !node.TLS && !node.Tls {
			scheme = "naive+http"
		}
		u := url.URL{Scheme: scheme, Host: host, Fragment: name}
		if node.Username != "" || node.Password != "" {
			u.User = url.UserPassword(node.Username, node.Password)
		}
		q := u.Query()
		setQuery(q, "sni", sni)
		if node.SkipCertVerify {
			q.Set("insecure", "1")
		}
		if node.QUIC {
			q.Set("quic", "1")
		}
		if node.QUICCongestion != "" {
			q.Set("quic_congestion_control", node.QUICCongestion)
		}
		if node.InsecureConcurrency > 0 {
			q.Set("insecure_concurrency", strconv.Itoa(node.InsecureConcurrency))
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	case "mieru":
		return exportMieruLink(node)
	default:
		return "", fmt.Errorf("暂不支持导出 %s 节点链接", node.Type)
	}
}

func exportMieruLink(node Node) (string, error) {
	profile, err := nodeToMieruClientProfile(node)
	if err != nil {
		return "", err
	}
	if node.Password != "" {
		if urls, err := mieruAppctl.ClientProfileToMultiURLs(profile); err == nil && len(urls) > 0 {
			return urls[0], nil
		}
	}
	config := &mieruPB.ClientConfig{
		Profiles:      []*mieruPB.ClientProfile{profile},
		ActiveProfile: proto.String(profile.GetProfileName()),
	}
	return mieruAppctl.ClientConfigToURL(config)
}

func nodeToMieruClientProfile(node Node) (*mieruPB.ClientProfile, error) {
	if node.Server == "" {
		return nil, fmt.Errorf("mieru 节点缺少服务器")
	}
	if node.Username == "" {
		return nil, fmt.Errorf("mieru 节点缺少用户名")
	}
	if node.Password == "" && node.HashedPassword == "" {
		return nil, fmt.Errorf("mieru 节点缺少密码")
	}
	if node.Port <= 0 && node.PortRange == "" {
		return nil, fmt.Errorf("mieru 节点缺少端口")
	}

	profileName := node.Name
	if profileName == "" {
		profileName = node.Server
	}

	transport, err := mieruTransportFromNode(node.Transport)
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

	profile := &mieruPB.ClientProfile{
		ProfileName: proto.String(profileName),
		User:        user,
		Servers:     []*mieruPB.ServerEndpoint{server},
	}
	if node.Mtu > 0 {
		profile.Mtu = proto.Int32(int32(node.Mtu))
	}
	if multiplexing, ok := mieruMultiplexingFromNode(node.Multiplexing); ok {
		profile.Multiplexing = &mieruPB.MultiplexingConfig{
			Level: multiplexing.Enum(),
		}
	}
	if handshakeMode, ok := mieruHandshakeModeFromNode(node.HandshakeMode); ok {
		profile.HandshakeMode = handshakeMode.Enum()
	}
	if node.TrafficPattern != "" {
		pattern, err := mieruTraffic.Decode(node.TrafficPattern)
		if err != nil {
			return nil, fmt.Errorf("解析 mieru traffic pattern 失败: %w", err)
		}
		profile.TrafficPattern = pattern
	}

	return profile, nil
}

func mieruTransportFromNode(value string) (mieruPB.TransportProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "TCP":
		return mieruPB.TransportProtocol_TCP, nil
	case "UDP", "QUIC":
		return mieruPB.TransportProtocol_UDP, nil
	default:
		return mieruPB.TransportProtocol_UNKNOWN_TRANSPORT_PROTOCOL, fmt.Errorf("不支持的 mieru 传输协议: %s", value)
	}
}

func mieruMultiplexingFromNode(value string) (mieruPB.MultiplexingLevel, bool) {
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

func mieruHandshakeModeFromNode(value string) (mieruPB.HandshakeMode, bool) {
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func setQuery(q url.Values, key, value string) {
	if value != "" {
		q.Set(key, value)
	}
}

func setMap(m map[string]string, key, value string) {
	if value != "" {
		m[key] = value
	}
}

func firstHeaderValue(primary map[string]string, fallback map[string]string, plain string) string {
	for _, headers := range []map[string]string{primary, fallback} {
		for k, v := range headers {
			if strings.EqualFold(k, "host") && v != "" {
				return v
			}
		}
	}
	return plain
}
