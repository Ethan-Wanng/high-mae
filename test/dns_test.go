package test

import (
	"high-mae/pkg/proxy"
	"testing"
)

func TestDNSRuleMatching(t *testing.T) {
	// Initialize with a known config
	proxy.GlobalDNSConfig = proxy.DNSConfig{
		Servers: []proxy.DNSServer{
			{ID: "google", Name: "Google DNS", Address: "8.8.8.8:53", Type: "udp"},
			{ID: "aliyun", Name: "Aliyun DNS", Address: "223.5.5.5:53", Type: "udp"},
		},
		Rules: []proxy.DNSRule{
			{Type: "domain_suffix", Value: "cn", ServerID: "aliyun"},
			{Type: "domain_keyword", Value: "baidu", ServerID: "aliyun"},
			{Type: "domain", Value: "google.com", ServerID: "google"},
		},
		Default: "google",
	}

	tests := []struct {
		domain   string
		expected string
	}{
		{"www.baidu.com", "aliyun"},
		{"taobao.cn", "aliyun"},
		{"google.com", "google"},
		{"sub.google.com", "google"}, // suffix check for "google" not in rules, but "google.com" is a domain rule. Wait, sub.google.com should NOT match "google.com" domain rule.
		{"twitter.com", "google"},    // default
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := proxy.MatchDNSRule(tt.domain)
			if got != tt.expected {
				t.Errorf("MatchDNSRule(%s) = %s; want %s", tt.domain, got, tt.expected)
			}
		})
	}
}
