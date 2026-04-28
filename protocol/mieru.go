package protocol

import (
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

	return nil, fmt.Errorf("not a clash-style subscription")
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
		case strings.HasPrefix(line, "hy2://") || strings.HasPrefix(line, "hysteria2://"):
			if n, err := ParseHysteria2(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://"):
			if n, err := ParseHTTPLike(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "mieru://") || strings.HasPrefix(line, "mierus://"):
			if parsed, err := ParseMieru(line); err == nil {
				nodes = append(nodes, parsed...)
			}
		default:
			fmt.Printf("⚠️ 跳过不支持的链接格式: %s\n", line)
		}
	}

	return nodes
}

func normalizeYAMLNodes(nodes []Node) []Node {
	out := make([]Node, 0, len(nodes))
	for _, node := range nodes {
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
		out = append(out, node)
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
