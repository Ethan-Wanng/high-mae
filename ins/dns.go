package ins

import (
	"context"
	"encoding/json"
	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/metadata"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

type DNSServer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"` // e.g., 8.8.8.8:53
	Type    string `json:"type"`    // udp (currently only supporting UDP through proxy)
}

type DNSRule struct {
	Type     string `json:"type"`  // domain, domain_suffix, domain_keyword
	Value    string `json:"value"`
	ServerID string `json:"serverId"`
}

type DNSConfig struct {
	Servers []DNSServer `json:"servers"`
	Rules   []DNSRule   `json:"rules"`
	Default string      `json:"default"`
}

var GlobalDNSConfig DNSConfig
const DNSConfigFile = "dns_config.json"

func LoadDNSConfig() {
	data, err := os.ReadFile(DNSConfigFile)
	if err == nil {
		if err := json.Unmarshal(data, &GlobalDNSConfig); err == nil {
			return
		}
	}

	// Default configuration
	GlobalDNSConfig = DNSConfig{
		Servers: []DNSServer{
			{ID: "google", Name: "Google DNS", Address: "8.8.8.8:53", Type: "udp"},
			{ID: "cloudflare", Name: "Cloudflare DNS", Address: "1.1.1.1:53", Type: "udp"},
			{ID: "aliyun", Name: "Aliyun DNS", Address: "223.5.5.5:53", Type: "udp"},
		},
		Rules: []DNSRule{
			{Type: "domain_suffix", Value: "cn", ServerID: "aliyun"},
			{Type: "domain_keyword", Value: "baidu", ServerID: "aliyun"},
			{Type: "domain_keyword", Value: "alicdn", ServerID: "aliyun"},
		},
		Default: "google",
	}
	SaveDNSConfig()
}

func SaveDNSConfig() error {
	data, err := json.MarshalIndent(GlobalDNSConfig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(DNSConfigFile, data, 0644)
}

func getDNSServerByID(id string) *DNSServer {
	for i := range GlobalDNSConfig.Servers {
		if GlobalDNSConfig.Servers[i].ID == id {
			return &GlobalDNSConfig.Servers[i]
		}
	}
	return nil
}

func matchDNSRule(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, rule := range GlobalDNSConfig.Rules {
		value := strings.ToLower(strings.TrimSpace(rule.Value))
		if value == "" {
			continue
		}
		match := false
		switch rule.Type {
		case "domain":
			match = (domain == value)
		case "domain_suffix":
			match = (domain == value || strings.HasSuffix(domain, "."+value))
		case "domain_keyword":
			match = strings.Contains(domain, value)
		}
		if match {
			return rule.ServerID
		}
	}
	return GlobalDNSConfig.Default
}

func StartLocalDNS() {
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 53}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("Failed to start DNS server: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("DNS server listening on %s", addr.String())

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		reqData := make([]byte, n)
		copy(reqData, buf[:n])

		go handleDNSRequest(conn, clientAddr, reqData)
	}
}

func handleDNSRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, reqData []byte) {
	msg := new(dns.Msg)
	if err := msg.Unpack(reqData); err != nil {
		return
	}

	if len(msg.Question) == 0 {
		return
	}

	domain := msg.Question[0].Name
	serverID := matchDNSRule(domain)
	server := getDNSServerByID(serverID)
	if server == nil {
		server = getDNSServerByID(GlobalDNSConfig.Default)
	}
	if server == nil && len(GlobalDNSConfig.Servers) > 0 {
		server = &GlobalDNSConfig.Servers[0]
	}

	if server == nil {
		return
	}

	// For now, we only support UDP-over-TCP/SOCKS through our proxy
	// Most DNS servers work on port 53
	dnsAddr := server.Address
	if !strings.Contains(dnsAddr, ":") {
		dnsAddr += ":53"
	}

	clientMu.RLock()
	client := activeClient
	clientMu.RUnlock()

	if client == nil {
		return
	}

	dest := metadata.ParseSocksaddr(dnsAddr)
	streamRaw, err := client.CreateProxy(context.Background(), dest)
	if err != nil {
		return
	}
	stream := &TrackingConn{streamRaw}
	defer stream.Close()

	length := uint16(len(reqData))
	stream.Write([]byte{byte(length >> 8), byte(length)})
	stream.Write(reqData)

	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, respLenBuf); err != nil {
		return
	}
	respLen := int(respLenBuf[0])<<8 | int(respLenBuf[1])
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(stream, resp); err != nil {
		return
	}

	conn.WriteToUDP(resp, clientAddr)
}
