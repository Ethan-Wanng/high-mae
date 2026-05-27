package proxy

import (
	"wing/pkg/common"
	"wing/pkg/storage"
	"wing/pkg/utils"

	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing/common/metadata"
)

type DNSServer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"` // e.g., 8.8.8.8:53
	Type    string `json:"type"`    // udp (currently only supporting UDP through proxy)
}

type DNSRule struct {
	Type     string `json:"type"` // domain, domain_suffix, domain_keyword
	Value    string `json:"value"`
	ServerID string `json:"serverId"`
}

type DNSConfig struct {
	AutoOverwrite bool        `json:"autoOverwrite"`
	Servers       []DNSServer `json:"servers"`
	Rules         []DNSRule   `json:"rules"`
	Default       string      `json:"default"`
}

type dnsCacheEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
}

var (
	GlobalDNSConfig DNSConfig
	dnsCache        = make(map[string]dnsCacheEntry)
	dnsCacheMu      sync.RWMutex
)

const (
	DNSConfigFile   = "dns_config.json"
	maxDnsCacheSize = 10000 // DNS 缓存最大条目数，防止无限增长
)

func LoadDNSConfig() {
	data, err := storage.ReadOrMigrateFile(DNSConfigFile)
	if err == nil {
		if err := json.Unmarshal(data, &GlobalDNSConfig); err == nil {
			return
		}
	}

	// Default configuration
	GlobalDNSConfig = DNSConfig{
		AutoOverwrite: false,
		Servers: []DNSServer{
			{ID: "google", Name: "Google DNS", Address: "8.8.8.8:53", Type: "udp"},
			{ID: "cloudflare", Name: "Cloudflare DNS", Address: "1.1.1.1:53", Type: "udp"},
			{ID: "opendns", Name: "OpenDNS", Address: "208.67.222.222:53", Type: "udp"},
			{ID: "quad9", Name: "Quad9", Address: "9.9.9.9:53", Type: "udp"},
			{ID: "adguard", Name: "AdGuard DNS", Address: "94.140.14.14:53", Type: "udp"},
			{ID: "aliyun", Name: "Aliyun DNS", Address: "223.5.5.5:53", Type: "udp"},
			{ID: "tencent", Name: "Tencent DNS", Address: "119.29.29.29:53", Type: "udp"},
			{ID: "114", Name: "114 DNS", Address: "114.114.114.114:53", Type: "udp"},
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
	return storage.Write(DNSConfigFile, data)
}

func GetDNSServerByID(id string) *DNSServer {
	for i := range GlobalDNSConfig.Servers {
		if GlobalDNSConfig.Servers[i].ID == id {
			return &GlobalDNSConfig.Servers[i]
		}
	}
	return nil
}

func MatchDNSRule(domain string) string {
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
	if GlobalDNSConfig.AutoOverwrite {
		if common.IsTunModeOn {
			log.Println("TUN 模式已开启，跳过系统 DNS 覆写到 127.0.0.2")
		} else {
			utils.SetSystemDNS(true, "127.0.0.2")
			common.IsSystemDNSHijacked = true
		}
	}

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 53}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("Failed to start DNS server: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("DNS server listening on %s", addr.String())

	// Start cache cleanup goroutine
	utils.SafeGo("dns cache cleanup", func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			now := time.Now()
			dnsCacheMu.Lock()
			for k, entry := range dnsCache {
				if now.After(entry.expiresAt) {
					delete(dnsCache, k)
				}
			}
			dnsCacheMu.Unlock()
		}
	})

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
	atomic.AddInt32(&common.ActiveDNSQueries, 1)
	defer atomic.AddInt32(&common.ActiveDNSQueries, -1)

	msg := new(dns.Msg)
	if err := msg.Unpack(reqData); err != nil {
		return
	}

	if len(msg.Question) == 0 {
		return
	}

	question := msg.Question[0]
	cacheKey := fmt.Sprintf("%s-%d", question.Name, question.Qtype)

	// 1. Check Cache
	dnsCacheMu.RLock()
	entry, found := dnsCache[cacheKey]
	dnsCacheMu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		resp := entry.msg.Copy()
		resp.Id = msg.Id // Match the request ID
		if packed, err := resp.Pack(); err == nil {
			conn.WriteToUDP(packed, clientAddr)
			return
		}
	}

	domain := question.Name
	serverID := MatchDNSRule(domain)
	server := GetDNSServerByID(serverID)
	if server == nil {
		server = GetDNSServerByID(GlobalDNSConfig.Default)
	}
	if server == nil && len(GlobalDNSConfig.Servers) > 0 {
		server = &GlobalDNSConfig.Servers[0]
	}

	if server == nil {
		return
	}

	// For now, we only support UDP-over-TCP/SOCKS through our proxy
	dnsAddr := server.Address
	if !strings.Contains(dnsAddr, ":") {
		dnsAddr += ":53"
	}

	common.ClientMu.RLock()
	client := common.ActiveClient
	common.ClientMu.RUnlock()

	if client == nil {
		return
	}

	dest := metadata.ParseSocksaddr(dnsAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	streamRaw, err := client.CreateProxy(ctx, dest)
	if err != nil {
		return
	}
	// 🚀 DNS 查询不需要 TrackingConn（无 logID），直接使用原始连接
	// 避免每次 DNS Read/Write 都触发无效的锁竞争
	stream := streamRaw
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	defer stream.Close()

	length := uint16(len(reqData))
	stream.Write([]byte{byte(length >> 8), byte(length)})
	stream.Write(reqData)

	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, respLenBuf); err != nil {
		return
	}
	respLen := int(respLenBuf[0])<<8 | int(respLenBuf[1])
	respData := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respData); err != nil {
		return
	}

	// 2. Parse Response and Update Cache
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respData); err == nil && len(respMsg.Answer) > 0 {
		minTTL := uint32(60) // Default 1 minute
		first := true
		for _, ans := range respMsg.Answer {
			if first || ans.Header().Ttl < minTTL {
				minTTL = ans.Header().Ttl
				first = false
			}
		}
		if minTTL > 3600 {
			minTTL = 3600 // Max 1 hour
		}

		dnsCacheMu.Lock()
		// 防止缓存无限增长：超过上限时清空（配合 TTL 淘汰策略即可）
		if len(dnsCache) >= maxDnsCacheSize {
			dnsCache = make(map[string]dnsCacheEntry)
		}
		dnsCache[cacheKey] = dnsCacheEntry{
			msg:       respMsg,
			expiresAt: time.Now().Add(time.Duration(minTTL) * time.Second),
		}
		dnsCacheMu.Unlock()
	}

	conn.WriteToUDP(respData, clientAddr)
}
