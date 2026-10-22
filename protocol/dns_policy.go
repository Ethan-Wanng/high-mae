package protocol

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// 部分机场的节点域名只能通过订阅里声明的专用 DoH 解析（公共 DNS 会返回占位 IP），
// Clash 通过 dns.nameserver-policy、sing-box 通过 dns.rules / domain_resolver 声明。
// 这里把命中策略的 DoH 地址写入 Node.DNSServers，由代理核心在解析节点地址时使用。

type dnsPolicyRule struct {
	pattern string
	servers []string
}

// ApplySubscriptionDNSPolicy 读取订阅原文中的节点域名 DNS 策略并写入匹配节点。
func ApplySubscriptionDNSPolicy(raw []byte, nodes []Node) []Node {
	if len(nodes) == 0 {
		return nodes
	}
	rules, byTag := singBoxDNSPolicy(raw)
	if len(rules) == 0 && len(byTag) == 0 {
		rules = clashDNSPolicy(raw)
	}
	if len(rules) == 0 && len(byTag) == 0 {
		return nodes
	}
	for i := range nodes {
		if len(nodes[i].DNSServers) > 0 {
			continue
		}
		if servers := byTag[nodes[i].Name]; len(servers) > 0 {
			nodes[i].DNSServers = append([]string(nil), servers...)
			continue
		}
		host := strings.ToLower(strings.Trim(strings.TrimSpace(nodes[i].Server), "[]."))
		if host == "" || net.ParseIP(host) != nil {
			continue
		}
		for _, rule := range rules {
			if matchDNSPolicyDomain(rule.pattern, host) {
				nodes[i].DNSServers = append([]string(nil), rule.servers...)
				break
			}
		}
	}
	return nodes
}

func clashDNSPolicy(raw []byte) []dnsPolicyRule {
	var config struct {
		DNS struct {
			NameserverPolicy yaml.Node `yaml:"nameserver-policy"`
		} `yaml:"dns"`
	}
	if err := yaml.Unmarshal(raw, &config); err != nil {
		return nil
	}
	policy := config.DNS.NameserverPolicy
	if policy.Kind != yaml.MappingNode {
		return nil
	}
	var rules []dnsPolicyRule
	// MappingNode 的 Content 按 key/value 交替排列，保持订阅中的声明顺序。
	for i := 0; i+1 < len(policy.Content); i += 2 {
		servers := clashPolicyServers(policy.Content[i+1])
		if len(servers) == 0 {
			continue
		}
		for _, pattern := range strings.Split(policy.Content[i].Value, ",") {
			pattern = strings.ToLower(strings.TrimSpace(pattern))
			// geosite:/rule-set: 等需要外部规则集，节点地址解析不处理。
			if pattern == "" || strings.Contains(pattern, ":") {
				continue
			}
			rules = append(rules, dnsPolicyRule{pattern: pattern, servers: servers})
		}
	}
	return rules
}

func clashPolicyServers(value *yaml.Node) []string {
	var candidates []string
	switch value.Kind {
	case yaml.ScalarNode:
		candidates = strings.Split(value.Value, ",")
	case yaml.SequenceNode:
		for _, item := range value.Content {
			candidates = append(candidates, item.Value)
		}
	}
	var servers []string
	for _, candidate := range candidates {
		if server := normalizeDoHServer(candidate); server != "" {
			servers = append(servers, server)
		}
	}
	return servers
}

// normalizeDoHServer 只保留 https:// DoH 地址，并把 Clash 的 #skip-cert-verify=true 参数统一成固定写法。
func normalizeDoHServer(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, "'\""))
	parsed, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return ""
	}
	insecure := false
	if params, err := url.ParseQuery(parsed.Fragment); err == nil {
		insecure = truthy(params.Get("skip-cert-verify"))
	}
	return buildDoHServer(parsed.Host, parsed.EscapedPath(), insecure)
}

func buildDoHServer(hostPort string, path string, insecure bool) string {
	if path == "" {
		path = "/dns-query"
	}
	server := "https://" + hostPort + path
	if insecure {
		server += "#skip-cert-verify=true"
	}
	return server
}

func singBoxDNSPolicy(raw []byte) ([]dnsPolicyRule, map[string][]string) {
	var config struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
		} `json:"dns"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, nil
	}
	serversByTag := make(map[string]string)
	for _, server := range config.DNS.Servers {
		tag := getString(server, "tag")
		if tag == "" {
			continue
		}
		if doh := singBoxDoHServer(server); doh != "" {
			serversByTag[tag] = doh
		}
	}
	if len(serversByTag) == 0 {
		return nil, nil
	}

	var rules []dnsPolicyRule
	for _, rule := range config.DNS.Rules {
		action := getString(rule, "action")
		if action != "" && action != "route" {
			continue
		}
		doh := serversByTag[getString(rule, "server")]
		if doh == "" {
			continue
		}
		for _, suffix := range stringList(rule["domain_suffix"]) {
			suffix = strings.ToLower(strings.Trim(strings.TrimSpace(suffix), "."))
			if suffix != "" {
				rules = append(rules, dnsPolicyRule{pattern: "+." + suffix, servers: []string{doh}})
			}
		}
		for _, domain := range stringList(rule["domain"]) {
			domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
			if domain != "" {
				rules = append(rules, dnsPolicyRule{pattern: domain, servers: []string{doh}})
			}
		}
	}

	byTag := make(map[string][]string)
	for _, outbound := range config.Outbounds {
		tag := getString(outbound, "tag")
		resolverTag := ""
		switch resolver := outbound["domain_resolver"].(type) {
		case string:
			resolverTag = resolver
		case map[string]any:
			resolverTag = getString(resolver, "server")
		}
		if doh := serversByTag[resolverTag]; tag != "" && doh != "" {
			byTag[tag] = []string{doh}
		}
	}
	return rules, byTag
}

func singBoxDoHServer(server map[string]any) string {
	// 旧版格式: {"address": "https://host/dns-query"}
	if address := getString(server, "address"); address != "" {
		return normalizeDoHServer(address)
	}
	if !strings.EqualFold(getString(server, "type"), "https") {
		return ""
	}
	host := getString(server, "server")
	if host == "" {
		return ""
	}
	hostPort := host
	if port, err := getPort(server["server_port"]); err == nil && port > 0 && port != 443 {
		hostPort = net.JoinHostPort(host, strconv.Itoa(port))
	} else if strings.Contains(host, ":") {
		hostPort = "[" + host + "]"
	}
	insecure := false
	if tlsMap, ok := server["tls"].(map[string]any); ok {
		insecure = truthy(tlsMap["insecure"])
	}
	return buildDoHServer(hostPort, getString(server, "path"), insecure)
}

func stringList(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// matchDNSPolicyDomain 实现 Clash nameserver-policy 的域名通配语义：
// "+.a.com" 匹配 a.com 及其子域名，"*.a.com" 匹配一级子域名，".a.com" 匹配所有子域名。
func matchDNSPolicyDomain(pattern string, host string) bool {
	switch {
	case strings.HasPrefix(pattern, "+."):
		base := pattern[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	case strings.HasPrefix(pattern, "*."):
		base := pattern[2:]
		if !strings.HasSuffix(host, "."+base) {
			return false
		}
		return !strings.Contains(strings.TrimSuffix(host, "."+base), ".")
	case strings.HasPrefix(pattern, "."):
		return strings.HasSuffix(host, pattern)
	default:
		return host == pattern
	}
}
