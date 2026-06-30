package protocol

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	mieruTraffic "github.com/enfein/mieru/v3/apis/trafficpattern"
	mieruAppctl "github.com/enfein/mieru/v3/pkg/appctl"
	mieruPB "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"gopkg.in/yaml.v3"
)

type clashSubscription struct {
	Proxies []Node `yaml:"proxies"`
}

func ParseSubscriptionRaw(raw []byte) ([]Node, error) {
	if nodes, err := ParseClashMetaNodes(raw); err == nil && len(nodes) > 0 {
		return nodes, nil
	}

	if nodes, err := ParseSingBoxNodes(raw); err == nil && len(nodes) > 0 {
		return nodes, nil
	}

	content, err := NormalizeSubscription(raw)
	if err != nil {
		return nil, err
	}

	return parseLinkNodes(content), nil
}

func ParseClashMetaNodes(raw []byte) ([]Node, error) {
	var wrapper clashSubscription
	if err := yaml.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Proxies) > 0 {
		return normalizeYAMLNodes(wrapper.Proxies), nil
	}

	var nodes []Node
	if err := yaml.Unmarshal(raw, &nodes); err == nil && len(nodes) > 0 {
		return normalizeYAMLNodes(nodes), nil
	}

	if nodes := parseClashProxyMaps(raw); len(nodes) > 0 {
		return normalizeYAMLNodes(nodes), nil
	}

	return nil, fmt.Errorf("not a clash-style subscription")
}

func ParseSingBoxNodes(raw []byte) ([]Node, error) {
	var wrapper struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Outbounds) > 0 {
		return singBoxOutboundsToNodes(wrapper.Outbounds)
	}

	var outbounds []map[string]any
	if err := json.Unmarshal(raw, &outbounds); err == nil && len(outbounds) > 0 {
		return singBoxOutboundsToNodes(outbounds)
	}

	var outbound map[string]any
	if err := json.Unmarshal(raw, &outbound); err != nil || len(outbound) == 0 {
		return nil, fmt.Errorf("not a sing-box subscription")
	}
	return singBoxOutboundsToNodes([]map[string]any{outbound})
}

func singBoxOutboundsToNodes(outbounds []map[string]any) ([]Node, error) {
	nodes := make([]Node, 0, len(outbounds))
	for _, outbound := range outbounds {
		node, ok := singBoxOutboundToNode(outbound)
		if ok {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("sing-box config has no supported outbound")
	}
	return normalizeYAMLNodes(nodes), nil
}

func singBoxOutboundToNode(outbound map[string]any) (Node, bool) {
	outType := strings.ToLower(getString(outbound, "type"))
	node := Node{
		Type:      singBoxNodeType(outType),
		Name:      firstNonEmpty(getString(outbound, "tag"), getString(outbound, "name")),
		Server:    getString(outbound, "server"),
		UUID:      getString(outbound, "uuid"),
		Username:  getString(outbound, "username"),
		Password:  getString(outbound, "password"),
		Method:    getString(outbound, "method"),
		Cipher:    firstNonEmpty(getString(outbound, "method"), getString(outbound, "security")),
		Network:   singBoxNetwork(outbound["network"]),
		Flow:      getString(outbound, "flow"),
		Transport: firstNonEmpty(getString(outbound, "transport"), getString(outbound, "protocol")),
		PortRange: firstNonEmpty(getString(outbound, "server_ports"), getString(outbound, "port_range"), getString(outbound, "ports")),
	}
	if node.Type == "" || node.Server == "" {
		return Node{}, false
	}
	if port, err := getPort(outbound["server_port"]); err == nil {
		node.Port = port
	} else if port, err := getPort(outbound["port"]); err == nil {
		node.Port = port
	}
	if alterID, err := getPort(outbound["alter_id"]); err == nil {
		node.AlterId = alterID
	}
	if tlsMap, ok := outbound["tls"].(map[string]any); ok {
		node.TLS = truthy(tlsMap["enabled"])
		node.Tls = node.TLS
		node.SNI = firstNonEmpty(getString(tlsMap, "server_name"), getString(tlsMap, "sni"))
		node.ServerName = node.SNI
		node.Insecure = truthy(tlsMap["insecure"])
		node.AllowInsecure = node.Insecure
		node.SkipCertVerify = node.Insecure
		node.ClientFingerprint = getString(tlsMap, "utls")
	}
	if node.Type == "tuic" {
		node.CongestionControl = getString(outbound, "congestion_control")
		node.UDPRelayMode = getString(outbound, "udp_relay_mode")
	}
	if node.Type == "hysteria2" {
		node.UDP = true
		node.Password = firstNonEmpty(node.Password, getString(outbound, "auth"), getString(outbound, "auth_str"))
		if obfsMap, ok := outbound["obfs"].(map[string]any); ok {
			node.Obfs = firstNonEmpty(getString(obfsMap, "type"), getString(outbound, "obfs"))
			node.ObfsPassword = firstNonEmpty(getString(obfsMap, "password"), getString(outbound, "obfs_password"))
		} else {
			node.Obfs = firstNonEmpty(getString(outbound, "obfs"), getString(outbound, "obfs_type"))
			node.ObfsPassword = firstNonEmpty(getString(outbound, "obfs_password"), getString(outbound, "obfs-password"))
		}
	}
	if node.Type == "mieru" {
		node.Username = firstNonEmpty(node.Username, getString(outbound, "user"), getString(outbound, "username"))
		node.HashedPassword = getString(outbound, "hashed_password")
		node.Transport = normalizeMieruTransport(node.Transport)
		node.Multiplexing = firstNonEmpty(getString(outbound, "multiplexing"), getString(outbound, "multiplexing_level"))
		node.HandshakeMode = firstNonEmpty(getString(outbound, "handshake_mode"), getString(outbound, "handshake-mode"))
		node.TrafficPattern = firstNonEmpty(getString(outbound, "traffic_pattern"), getString(outbound, "traffic-pattern"))
		node.DomainStrategy = firstNonEmpty(getString(outbound, "domain_strategy"), getString(outbound, "domain-strategy"))
		if resolverMap, ok := outbound["domain_resolver"].(map[string]any); ok {
			node.DomainStrategy = firstNonEmpty(node.DomainStrategy, getString(resolverMap, "strategy"))
		}
		if mtu, err := getPort(outbound["mtu"]); err == nil {
			node.Mtu = mtu
		}
	}
	if node.Type == "naive" {
		node.TLS = true
		node.Tls = true
		node.QUIC = truthy(outbound["quic"])
		node.QUICCongestion = getString(outbound, "quic_congestion_control")
		if concurrent, err := getPort(outbound["insecure_concurrency"]); err == nil {
			node.InsecureConcurrency = concurrent
		}
		node.ExtraHeaders = stringMap(outbound["extra_headers"])
	}
	if node.Name == "" {
		node.Name = node.Server
	}
	return node, true
}

func singBoxNodeType(outType string) string {
	return normalizeNodeType(outType)
}

func normalizeNodeType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "shadowsocks":
		return "ss"
	case "hysteria", "hysteria2", "hy2":
		return "hysteria2"
	case "vmess", "tuic", "trojan", "vless", "anytls", "mieru", "naive", "ss", "ssocks", "http", "https", "socks", "socks5":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func normalizeMieruTransport(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "udp", "quic":
		return "UDP"
	default:
		return "TCP"
	}
}

func singBoxNetwork(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case map[string]any:
		return getString(v, "type")
	default:
		return ""
	}
}

func parseClashProxyMaps(raw []byte) []Node {
	var wrapper struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(raw, &wrapper); err != nil || len(wrapper.Proxies) == 0 {
		return nil
	}

	nodes := make([]Node, 0, len(wrapper.Proxies))
	for _, proxy := range wrapper.Proxies {
		node, ok := clashProxyMapToNode(proxy)
		if ok {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func clashProxyMapToNode(proxy map[string]any) (Node, bool) {
	node := Node{
		Type:              normalizeNodeType(getString(proxy, "type")),
		Name:              getString(proxy, "name"),
		Server:            getString(proxy, "server"),
		UUID:              getString(proxy, "uuid"),
		Username:          firstNonEmpty(getString(proxy, "username"), getString(proxy, "user")),
		Password:          firstNonEmpty(getString(proxy, "password"), getString(proxy, "auth"), getString(proxy, "auth-str"), getString(proxy, "auth_str")),
		HashedPassword:    firstNonEmpty(getString(proxy, "hashed-password"), getString(proxy, "hashed_password")),
		Method:            firstNonEmpty(getString(proxy, "method"), getString(proxy, "cipher")),
		Cipher:            firstNonEmpty(getString(proxy, "cipher"), getString(proxy, "method")),
		SNI:               firstNonEmpty(getString(proxy, "sni"), getString(proxy, "servername")),
		ServerName:        getString(proxy, "servername"),
		Network:           getString(proxy, "network"),
		Flow:              getString(proxy, "flow"),
		ClientFingerprint: firstNonEmpty(getString(proxy, "client-fingerprint"), getString(proxy, "fp")),
		Transport:         firstNonEmpty(getString(proxy, "transport"), getString(proxy, "protocol")),
		Multiplexing:      firstNonEmpty(getString(proxy, "multiplexing"), getString(proxy, "multiplexing-level"), getString(proxy, "multiplexing_level")),
		HandshakeMode:     firstNonEmpty(getString(proxy, "handshake-mode"), getString(proxy, "handshake_mode")),
		TrafficPattern:    firstNonEmpty(getString(proxy, "traffic-pattern"), getString(proxy, "traffic_pattern")),
		DomainStrategy:    firstNonEmpty(getString(proxy, "domain-strategy"), getString(proxy, "domain_strategy")),
		QUIC:              truthy(proxy["quic"]),
		QUICCongestion:    firstNonEmpty(getString(proxy, "quic-congestion-control"), getString(proxy, "quic_congestion_control")),
		ExtraHeaders:      stringMap(firstMapValue(proxy, "extra-headers", "extra_headers")),
		Obfs:              getString(proxy, "obfs"),
		ObfsPassword:      firstNonEmpty(getString(proxy, "obfs-password"), getString(proxy, "obfs_password"), getString(proxy, "obfs.password")),
	}
	if node.Type == "" {
		return Node{}, false
	}
	if port, err := getPort(proxy["port"]); err == nil {
		node.Port = port
	}
	node.PortRange = firstNonEmpty(getString(proxy, "port-range"), getString(proxy, "ports"), getString(proxy, "mport"))
	node.Ports = getString(proxy, "ports")
	node.MPort = getString(proxy, "mport")
	node.TLS = truthy(proxy["tls"])
	node.Tls = node.TLS
	node.UDP = truthy(proxy["udp"])
	node.TFO = truthy(proxy["tfo"])
	node.SkipCertVerify = truthy(proxy["skip-cert-verify"]) || truthy(proxy["insecure"]) || truthy(proxy["allow-insecure"])
	node.Insecure = truthy(proxy["insecure"])
	node.AllowInsecure = truthy(proxy["allow-insecure"])
	if node.Type == "hysteria2" {
		node.UDP = true
	}
	if node.Type == "mieru" {
		node.Transport = normalizeMieruTransport(node.Transport)
		if mtu, err := getPort(proxy["mtu"]); err == nil {
			node.Mtu = mtu
		}
	}
	if node.Type == "naive" {
		node.TLS = true
		node.Tls = true
		if concurrent, err := getPort(firstMapValue(proxy, "insecure-concurrency", "insecure_concurrency")); err == nil {
			node.InsecureConcurrency = concurrent
		}
	}
	if node.Name == "" {
		node.Name = node.Server
	}
	return node, node.Server != "" || node.Type == "mieru"
}

func truthy(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "y":
			return true
		}
	case int:
		return v != 0
	case float64:
		return v != 0
	}
	return false
}

func ParseMieru(link string) ([]Node, error) {
	lower := strings.ToLower(strings.TrimSpace(link))

	switch {
	case strings.HasPrefix(lower, "mierus://"):
		profile, err := mieruAppctl.URLToClientProfile(link)
		if err != nil {
			return nil, err
		}
		return clientProfileToNodes(profile), nil
	case strings.HasPrefix(lower, "mieru://"):
		config, err := mieruAppctl.URLToClientConfig(link)
		if err != nil {
			return nil, err
		}
		var nodes []Node
		for _, profile := range config.GetProfiles() {
			nodes = append(nodes, clientProfileToNodes(profile)...)
		}
		if len(nodes) == 0 {
			return nil, fmt.Errorf("mieru config has no usable profile")
		}
		return nodes, nil
	default:
		return nil, fmt.Errorf("unsupported mieru scheme")
	}
}

func parseLinkNodes(content string) []Node {
	lines := strings.Split(content, "\n")
	var nodes []Node

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "vmess://"):
			if n, err := ParseVMess(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "ss://"):
			if n, err := ParseSS(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "ssocks://"):
			if n, err := ParseSSocks(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "trojan://"):
			if n, err := ParseTrojan(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "anytls://"):
			if n, err := ParseAnyTLS(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "tuic://"):
			if n, err := ParseTUIC(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "vless://"):
			if n, err := ParseVLESS(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "hy2://") || strings.HasPrefix(line, "hysteria2://") || strings.HasPrefix(line, "hysteria://"):
			if strings.HasPrefix(line, "hysteria://") {
				line = "hysteria2://" + strings.TrimPrefix(line, "hysteria://")
			}
			if n, err := ParseHysteria2(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") || strings.HasPrefix(line, "socks://") || strings.HasPrefix(line, "socks5://") || strings.HasPrefix(line, "tls://"):
			if n, err := ParseHTTPLike(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "mieru://") || strings.HasPrefix(line, "mierus://"):
			if parsed, err := ParseMieru(line); err == nil {
				nodes = append(nodes, parsed...)
			}
		case strings.HasPrefix(line, "naive://") || strings.HasPrefix(line, "naive+http://") || strings.HasPrefix(line, "naive+https://") || strings.HasPrefix(line, "naive+quic://"):
			if n, err := ParseNaive(line); err == nil {
				nodes = append(nodes, n)
			}
		default:
			fmt.Printf("⚠️ 跳过不支持的链接格式: %s\n", redactedLinkSummary(line))
		}
	}

	return nodes
}

func redactedLinkSummary(raw string) string {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "<empty>"
	}
	if idx := strings.Index(clean, "://"); idx > 0 {
		return clean[:idx] + "://<redacted>"
	}
	return fmt.Sprintf("<redacted, %d bytes>", len(clean))
}

func normalizeYAMLNodes(nodes []Node) []Node {
	out := make([]Node, 0, len(nodes))
	for _, node := range nodes {
		node.Type = normalizeNodeType(node.Type)
		if node.Type == "" {
			continue
		}
		if node.Name == "" {
			node.Name = node.Server
		}
		// 统一不安全连接标志
		if node.Insecure || node.AllowInsecure {
			node.SkipCertVerify = true
		}
		if node.Type == "hysteria2" {
			node.UDP = true
		}
		if node.Type == "mieru" {
			node.Transport = normalizeMieruTransport(node.Transport)
		}
		if node.Type == "naive" {
			node.TLS = true
			node.Tls = true
			if node.Port == 0 {
				node.Port = 443
			}
		}
		out = append(out, node)
	}
	return out
}

func firstMapValue(m map[string]any, keys ...string) any {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return nil
}

func stringMap(value any) map[string]string {
	if value == nil {
		return nil
	}
	out := make(map[string]string)
	switch m := value.(type) {
	case map[string]any:
		for key, v := range m {
			out[key] = fmt.Sprintf("%v", v)
		}
	case map[any]any:
		for key, v := range m {
			out[fmt.Sprintf("%v", key)] = fmt.Sprintf("%v", v)
		}
	case map[string]string:
		for key, v := range m {
			out[key] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func clientProfileToNodes(profile *mieruPB.ClientProfile) []Node {
	if profile == nil {
		return nil
	}

	baseName := profile.GetProfileName()
	if baseName == "" {
		baseName = "mieru"
	}

	user := profile.GetUser()
	username := user.GetName()
	password := user.GetPassword()
	hashedPassword := user.GetHashedPassword()

	multiplexing := ""
	if profile.Multiplexing != nil && profile.Multiplexing.Level != nil {
		multiplexing = profile.GetMultiplexing().GetLevel().String()
	}

	handshakeMode := ""
	if profile.HandshakeMode != nil {
		handshakeMode = profile.GetHandshakeMode().String()
	}

	trafficPattern := ""
	if profile.GetTrafficPattern() != nil {
		trafficPattern = mieruTraffic.Encode(profile.GetTrafficPattern())
	}
	mtu := int(profile.GetMtu())

	totalBindings := 0
	for _, server := range profile.GetServers() {
		totalBindings += len(server.GetPortBindings())
	}

	var nodes []Node
	for _, server := range profile.GetServers() {
		host := server.GetDomainName()
		if host == "" {
			host = server.GetIpAddress()
		}
		if host == "" {
			continue
		}

		for _, binding := range server.GetPortBindings() {
			transport := binding.GetProtocol().String()
			if transport == "UNKNOWN_TRANSPORT_PROTOCOL" || transport == "" {
				transport = "TCP"
			}

			node := Node{
				Type:           "mieru",
				Name:           baseName,
				Server:         host,
				Username:       username,
				Password:       password,
				HashedPassword: hashedPassword,
				Transport:      transport,
				Mtu:            mtu,
				Multiplexing:   multiplexing,
				HandshakeMode:  handshakeMode,
				TrafficPattern: trafficPattern,
			}

			if binding.GetPortRange() != "" {
				node.PortRange = binding.GetPortRange()
				node.Port = firstPortFromRange(binding.GetPortRange())
			} else {
				node.Port = int(binding.GetPort())
			}

			if totalBindings > 1 || len(profile.GetServers()) > 1 {
				suffix := bindingLabel(node)
				if len(profile.GetServers()) > 1 {
					suffix = host + " " + suffix
				}
				node.Name = fmt.Sprintf("%s [%s]", baseName, strings.TrimSpace(suffix))
			}

			nodes = append(nodes, node)
		}
	}

	return nodes
}

func bindingLabel(node Node) string {
	portLabel := node.PortRange
	if portLabel == "" && node.Port > 0 {
		portLabel = strconv.Itoa(node.Port)
	}
	if portLabel == "" {
		return node.Transport
	}
	if node.Transport == "" {
		return portLabel
	}
	return portLabel + " " + node.Transport
}

func firstPortFromRange(portRange string) int {
	parts := strings.SplitN(portRange, "-", 2)
	if len(parts) == 0 {
		return 0
	}
	port, _ := strconv.Atoi(parts[0])
	return port
}
