package proxy

import (
	"wing/pkg/common"
	"wing/pkg/secure"
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

type ipDomainEntry struct {
	domain    string
	expiresAt time.Time
}

var (
	GlobalDNSConfig DNSConfig
	dnsConfigMu     sync.RWMutex
	dnsCache        = make(map[string]dnsCacheEntry)
	dnsCacheMu      sync.RWMutex
	IPToDomainMap   sync.Map
	ipDomainMapSize atomic.Int64
)

const (
	DNSConfigFile         = "dns_config.json"
	maxDnsCacheSize       = 10000
	dnsCacheTrimTarget    = maxDnsCacheSize * 9 / 10
	maxIPDomainMapSize    = 20000
	ipDomainMapTrimTarget = maxIPDomainMapSize * 9 / 10
	maxDNSTTL             = 3600
)

func dnsEntryExpiry(ttl uint32, now time.Time) time.Time {
	if ttl == 0 {
		ttl = 60
	}
	if ttl > maxDNSTTL {
		ttl = maxDNSTTL
	}
	return now.Add(time.Duration(ttl) * time.Second)
}

func pruneDNSCacheLocked(now time.Time) {
	for k, entry := range dnsCache {
		if now.After(entry.expiresAt) {
			delete(dnsCache, k)
		}
	}
	if len(dnsCache) < maxDnsCacheSize {
		return
	}
	remove := len(dnsCache) - dnsCacheTrimTarget
	for k := range dnsCache {
		delete(dnsCache, k)
		remove--
		if remove <= 0 {
			break
		}
	}
}

func storeIPDomainMapping(ip string, entry ipDomainEntry) {
	if _, loaded := IPToDomainMap.LoadOrStore(ip, entry); loaded {
		IPToDomainMap.Store(ip, entry)
	} else {
		ipDomainMapSize.Add(1)
	}
	if ipDomainMapSize.Load() >= maxIPDomainMapSize {
		pruneIPDomainMap(time.Now())
	}
}

func deleteIPDomainMapping(key any) {
	if _, loaded := IPToDomainMap.LoadAndDelete(key); loaded {
		ipDomainMapSize.Add(-1)
	}
}

func pruneIPDomainMap(now time.Time) {
	IPToDomainMap.Range(func(key, value any) bool {
		entry, ok := value.(ipDomainEntry)
		if !ok || now.After(entry.expiresAt) {
			deleteIPDomainMapping(key)
		}
		return true
	})
	if ipDomainMapSize.Load() < maxIPDomainMapSize {
		return
	}
	remove := ipDomainMapSize.Load() - ipDomainMapTrimTarget
	IPToDomainMap.Range(func(key, _ any) bool {
		deleteIPDomainMapping(key)
		remove--
		return remove > 0
	})
}

func LoadDNSConfig() {
	data, err := secure.SecureReadFile(DNSConfigFile)
	if err == nil {
		var config DNSConfig
		if err := json.Unmarshal(data, &config); err == nil {
			SetDNSConfig(config)
			return
		}
	}

	SetDNSConfig(defaultDNSConfig())
	SaveDNSConfig()
}

func defaultDNSConfig() DNSConfig {
	return DNSConfig{
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
}

func cloneDNSConfig(config DNSConfig) DNSConfig {
	config.Servers = append([]DNSServer(nil), config.Servers...)
	config.Rules = append([]DNSRule(nil), config.Rules...)
	return config
}

func GetDNSConfig() DNSConfig {
	dnsConfigMu.RLock()
	defer dnsConfigMu.RUnlock()
	return cloneDNSConfig(GlobalDNSConfig)
}

func SetDNSConfig(config DNSConfig) {
	dnsConfigMu.Lock()
	defer dnsConfigMu.Unlock()
	GlobalDNSConfig = cloneDNSConfig(config)
}

func SaveDNSConfig() error {
	config := GetDNSConfig()
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return secure.SecureWriteFile(DNSConfigFile, data)
}

func GetDNSServerByID(id string) *DNSServer {
	config := GetDNSConfig()
	return dnsServerByID(config, id)
}

func dnsServerByID(config DNSConfig, id string) *DNSServer {
	for i := range config.Servers {
		if config.Servers[i].ID == id {
			server := config.Servers[i]
			return &server
		}
	}
	return nil
}

func MatchDNSRule(domain string) string {
	return matchDNSRule(GetDNSConfig(), domain)
}

func matchDNSRule(config DNSConfig, domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, rule := range config.Rules {
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
	return config.Default
}

func StartLocalDNS() {
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 53}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("Failed to start DNS server: %v", err)
		return
	}
	defer conn.Close()

	config := GetDNSConfig()
	if config.AutoOverwrite {
		if common.GetTunModeOn() {
			log.Println("TUN 模式已开启，跳过 DNS 自动覆写到 127.0.0.2")
		} else {
			utils.SetSystemDNS(true, "127.0.0.2")
			common.IsSystemDNSHijacked = true
		}
	}

	log.Printf("DNS server listening on %s", addr.String())

	// Start cache cleanup goroutine
	utils.SafeGo("dns cache cleanup", func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			now := time.Now()
			dnsCacheMu.Lock()
			pruneDNSCacheLocked(now)
			dnsCacheMu.Unlock()
			pruneIPDomainMap(now)
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

		utils.SafeGo("dns request", func() {
			handleDNSRequest(conn, clientAddr, reqData)
		})
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
	config := GetDNSConfig()
	serverID := matchDNSRule(config, domain)
	server := dnsServerByID(config, serverID)
	if server == nil {
		server = dnsServerByID(config, config.Default)
	}
	if server == nil && len(config.Servers) > 0 {
		first := config.Servers[0]
		server = &first
	}

	if server == nil {
		return
	}

	// For now, we only support UDP-over-TCP/SOCKS through our proxy
	dnsAddr := server.Address
	if !strings.Contains(dnsAddr, ":") {
		dnsAddr += ":53"
	}

	client := common.GetActiveClient()
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
	if _, err := stream.Write([]byte{byte(length >> 8), byte(length)}); err != nil {
		return
	}
	if _, err := stream.Write(reqData); err != nil {
		return
	}

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
		now := time.Now()
		for _, ans := range respMsg.Answer {
			if first || ans.Header().Ttl < minTTL {
				minTTL = ans.Header().Ttl
				first = false
			}
			if a, ok := ans.(*dns.A); ok {
				storeIPDomainMapping(a.A.String(), ipDomainEntry{domain: domain, expiresAt: dnsEntryExpiry(ans.Header().Ttl, now)})
			} else if aaaa, ok := ans.(*dns.AAAA); ok {
				storeIPDomainMapping(aaaa.AAAA.String(), ipDomainEntry{domain: domain, expiresAt: dnsEntryExpiry(ans.Header().Ttl, now)})
			}
		}

		dnsCacheMu.Lock()
		pruneDNSCacheLocked(now)
		dnsCache[cacheKey] = dnsCacheEntry{
			msg:       respMsg,
			expiresAt: dnsEntryExpiry(minTTL, now),
		}
		dnsCacheMu.Unlock()
	}

	_, _ = conn.WriteToUDP(respData, clientAddr)
}
