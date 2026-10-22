package protocol

import (
	"reflect"
	"testing"
)

func TestClashNameserverPolicyAppliesDoHToMatchingNodes(t *testing.T) {
	raw := []byte(`
dns:
  nameserver-policy:
    '+.example.com': ['https://doh.example.net:2096/dns-query/token#skip-cert-verify=true', 'tls://1.2.3.4', 'https://10.0.0.1:2096/dns-query/token']
    'geosite:cn': ['https://223.5.5.5/dns-query']
    'exact.org,*.wild.org': 'https://doh.example.org/dns-query'
proxies:
  - { name: a, type: anytls, server: 11us.example.com, port: 4430, password: p }
  - { name: b, type: anytls, server: example.com, port: 4430, password: p }
  - { name: c, type: anytls, server: other.net, port: 4430, password: p }
  - { name: d, type: anytls, server: a.wild.org, port: 4430, password: p }
  - { name: e, type: anytls, server: a.b.wild.org, port: 4430, password: p }
  - { name: f, type: anytls, server: exact.org, port: 4430, password: p }
`)
	nodes, err := ParseSubscriptionRaw(raw)
	if err != nil {
		t.Fatalf("ParseSubscriptionRaw() error = %v", err)
	}
	want := map[string][]string{
		"a": {"https://doh.example.net:2096/dns-query/token#skip-cert-verify=true", "https://10.0.0.1:2096/dns-query/token"},
		"b": {"https://doh.example.net:2096/dns-query/token#skip-cert-verify=true", "https://10.0.0.1:2096/dns-query/token"},
		"c": nil,
		"d": {"https://doh.example.org/dns-query"},
		"e": nil,
		"f": {"https://doh.example.org/dns-query"},
	}
	for _, node := range nodes {
		if !reflect.DeepEqual(node.DNSServers, want[node.Name]) {
			t.Fatalf("node %s DNSServers = %v, want %v", node.Name, node.DNSServers, want[node.Name])
		}
	}
}

func TestSingBoxDNSRulesAndDomainResolverApplyDoH(t *testing.T) {
	raw := []byte(`{
  "dns": {
    "servers": [
      {"tag": "alidoh", "type": "https", "server": "223.5.5.5"},
      {"tag": "customdoh", "type": "https", "server": "doh.example.net", "server_port": 2096, "path": "/dns-query/token", "tls": {"enabled": true, "insecure": true}}
    ],
    "rules": [
      {"domain_suffix": ["example.com"], "action": "route", "server": "customdoh"}
    ]
  },
  "outbounds": [
    {"type": "hysteria2", "tag": "hy", "server": "11us.example.com", "server_port": 41000, "password": "p",
     "tls": {"enabled": true, "disable_sni": true, "alpn": ["h3"], "insecure": true}},
    {"type": "anytls", "tag": "resolver", "server": "node.other.net", "server_port": 4430, "password": "p",
     "domain_resolver": {"server": "alidoh"}},
    {"type": "naive", "tag": "plain", "server": "naive.other.net", "server_port": 443, "username": "u", "password": "p"}
  ]
}`)
	nodes, err := ParseSubscriptionRaw(raw)
	if err != nil {
		t.Fatalf("ParseSubscriptionRaw() error = %v", err)
	}
	byName := map[string]Node{}
	for _, node := range nodes {
		byName[node.Name] = node
	}
	if got := byName["hy"].DNSServers; !reflect.DeepEqual(got, []string{"https://doh.example.net:2096/dns-query/token#skip-cert-verify=true"}) {
		t.Fatalf("hy DNSServers = %v", got)
	}
	if !byName["hy"].DisableSNI || !reflect.DeepEqual(byName["hy"].ALPN, []string{"h3"}) {
		t.Fatalf("hy TLS options not parsed: disableSNI=%v alpn=%v", byName["hy"].DisableSNI, byName["hy"].ALPN)
	}
	if got := byName["resolver"].DNSServers; !reflect.DeepEqual(got, []string{"https://223.5.5.5/dns-query"}) {
		t.Fatalf("resolver DNSServers = %v", got)
	}
	if got := byName["plain"].DNSServers; got != nil {
		t.Fatalf("plain DNSServers = %v, want nil", got)
	}
}
