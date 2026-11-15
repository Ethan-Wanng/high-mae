package proxy

import (
	"wing/pkg/common"
	"wing/pkg/routing"
	"wing/pkg/secure"
	"wing/pkg/utils"

	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
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
	minDNSCacheTTL        = 60
	minIPDomainMapTTL     = 1800
	maxDNSTTL             = 3600
	directDNSQueryTimeout = 3 * time.Second
	androidLocalDNSPort   = 1053
	desktopLocalDNSPort   = 53
)

func localDNSListenPort() int {
	if runtime.GOOS == "android" {
		// Android applications cannot bind the privileged DNS port. The TUN
		// engine still intercepts client traffic on port 53, then forwards it
		// to this loopback-only, unprivileged listener.
		return androidLocalDNSPort
	}
	return desktopLocalDNSPort
}

func clampedDNSTTL(ttl uint32, minTTL uint32) uint32 {
	if ttl < minTTL {
		ttl = minTTL
	}
	if ttl > maxDNSTTL {
		ttl = maxDNSTTL
	}
	return ttl
}

func dnsEntryExpiry(ttl uint32, now time.Time) time.Time {
	return now.Add(time.Duration(clampedDNSTTL(ttl, minDNSCacheTTL)) * time.Second)
}

func ipDomainEntryExpiry(ttl uint32, now time.Time) time.Time {
	return now.Add(time.Duration(clampedDNSTTL(ttl, minIPDomainMapTTL)) * time.Second)
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
	if serverID, ok := matchExplicitDNSRule(config, domain); ok {
		return serverID
	}
	return config.Default
}

func matchExplicitDNSRule(config DNSConfig, domain string) (string, bool) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
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
			return rule.ServerID, true
		}
	}
	return "", false
}

var domesticDNSIPs = map[string]struct{}{
	"223.5.5.5":       {},
	"223.6.6.6":       {},
	"119.29.29.29":    {},
	"182.254.116.116": {},
	"1.12.12.12":      {},
	"120.53.53.53":    {},
	"114.114.114.114": {},
	"114.114.115.115": {},
	"180.76.76.76":    {},
}

func isDomesticDNSServer(server *DNSServer) bool {
	if server == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(server.ID)) {
	case "aliyun", "tencent", "114":
		return true
	}
	addr := strings.TrimSpace(server.Address)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if _, ok := domesticDNSIPs[host]; ok {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		return true
	}
	return false
}

func pickDomesticDNSServer(config DNSConfig) *DNSServer {
	for _, id := range []string{"aliyun", "tencent", "114"} {
		if server := dnsServerByID(config, id); server != nil {
			return server
		}
	}
	for i := range config.Servers {
		if isDomesticDNSServer(&config.Servers[i]) {
			s := config.Servers[i]
			return &s
		}
	}
	return &DNSServer{ID: "aliyun", Name: "Aliyun DNS", Address: "223.5.5.5:53", Type: "udp"}
}

func selectDNSServer(config DNSConfig, domain string) (*DNSServer, bool) {
	cleanDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	serverID, explicit := matchExplicitDNSRule(config, cleanDomain)
	routeIsDirect := cleanDomain != "" && routing.ShouldDirect(cleanDomain)

	if !explicit && routeIsDirect {
		return pickDomesticDNSServer(config), true
	}

	var server *DNSServer
	if explicit {
		server = dnsServerByID(config, serverID)
	}
	if server == nil {
		server = dnsServerByID(config, config.Default)
	}
	if server == nil && routeIsDirect {
		return pickDomesticDNSServer(config), true
	}
	if server == nil && len(config.Servers) > 0 {
		first := config.Servers[0]
		server = &first
	}
	if server == nil {
		return nil, routeIsDirect
	}

	resolveDirect := isDomesticDNSServer(server) || (routeIsDirect && !explicit)
	return server, resolveDirect
}

func directDoHEndpoints(server *DNSServer) []string {
	if server != nil && (strings.EqualFold(server.ID, "tencent") ||
		strings.HasPrefix(server.Address, "119.29.") ||
		strings.HasPrefix(server.Address, "1.12.")) {
		return []string{
			"https://1.12.12.12/dns-query",
			"https://223.5.5.5/dns-query",
		}
	}
	return []string{
		"https://223.5.5.5/dns-query",
		"https://1.12.12.12/dns-query",
	}
}

func dnsCacheKey(domain string, qtype uint16) string {
	normalized := strings.ToLower(dns.Fqdn(strings.TrimSpace(domain)))
	return fmt.Sprintf("%s-%d", normalized, qtype)
}

func queryRawDoHEndpoint(ctx context.Context, client *http.Client, endpoint string, payload []byte, reqID uint16) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, err
	}
	reply.Id = reqID
	return reply.Pack()
}

func exchangeDNSDoH(ctx context.Context, reqData []byte, endpoints []string) ([]byte, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no DoH endpoints configured")
	}
	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(reqData); err != nil {
		return nil, err
	}
	reqID := reqMsg.Id
	reqMsg.Id = 0
	payload, err := reqMsg.Pack()
	if err != nil {
		return nil, err
	}

	secureClient, _ := nodeDoHClients()
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type dohResult struct {
		data []byte
		err  error
	}
	results := make(chan dohResult, len(endpoints))
	for _, endpoint := range endpoints {
		endpoint := endpoint
		utils.SafeGo("direct doh query", func() {
			data, qErr := queryRawDoHEndpoint(queryCtx, secureClient, endpoint, payload, reqID)
			results <- dohResult{data: data, err: qErr}
		})
	}

	var lastErr error
	for range endpoints {
		select {
		case res := <-results:
			if res.err == nil && len(res.data) > 0 {
				return res.data, nil
			}
			if res.err != nil {
				lastErr = res.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("direct DoH query failed")
}

func exchangeDNSUDP(ctx context.Context, reqData []byte, dnsAddr string) ([]byte, error) {
	if dnsAddr == "" {
		dnsAddr = "223.5.5.5:53"
	} else if !strings.Contains(dnsAddr, ":") {
		dnsAddr += ":53"
	}
	dialer := &net.Dialer{Timeout: directDNSQueryTimeout}
	conn, err := dialer.DialContext(ctx, "udp", dnsAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(directDNSQueryTimeout))
	}
	if _, err := conn.Write(reqData); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func exchangeDNSDirect(ctx context.Context, reqData []byte, server *DNSServer) ([]byte, error) {
	endpoints := directDoHEndpoints(server)
	if common.GetTunModeOn() {
		// sing-box TUN StrictRoute 在 Windows 会拦截物理网卡 53 端口直连，改走物理网卡 DoH (443)
		return exchangeDNSDoH(ctx, reqData, endpoints)
	}
	dnsAddr := "223.5.5.5:53"
	if server != nil && server.Address != "" && isDomesticDNSServer(server) {
		dnsAddr = server.Address
	}
	if respData, err := exchangeDNSUDP(ctx, reqData, dnsAddr); err == nil {
		return respData, nil
	}
	return exchangeDNSDoH(ctx, reqData, endpoints)
}

func queryDNSThroughProxy(ctx context.Context, client common.GenericClient, dnsAddr string, reqData []byte) ([]byte, error) {
	if client == nil {
		return nil, fmt.Errorf("no active proxy client")
	}
	if dnsAddr == "" {
		dnsAddr = "8.8.8.8:53"
	} else if !strings.Contains(dnsAddr, ":") {
		dnsAddr += ":53"
	}
	dest := metadata.ParseSocksaddr(dnsAddr)
	stream, err := client.CreateProxy(ctx, dest)
	if err != nil {
		return nil, err
	}
	// DNS 查询不需要 TrackingConn（无 logID），直接使用原始连接避免锁竞争
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	} else {
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	}
	defer stream.Close()

	length := uint16(len(reqData))
	if _, err := stream.Write([]byte{byte(length >> 8), byte(length)}); err != nil {
		return nil, err
	}
	if _, err := stream.Write(reqData); err != nil {
		return nil, err
	}

	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, respLenBuf); err != nil {
		return nil, err
	}
	respLen := int(respLenBuf[0])<<8 | int(respLenBuf[1])
	respData := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respData); err != nil {
		return nil, err
	}
	return respData, nil
}

func extractSVCBHintIPs(kv dns.SVCBKeyValue) []net.IP {
	switch h := kv.(type) {
	case *dns.SVCBIPv4Hint:
		return h.Hint
	case *dns.SVCBIPv6Hint:
		return h.Hint
	default:
		return nil
	}
}

func storeRecordIPMappings(domain string, rr dns.RR, now time.Time) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return
	}
	expiry := ipDomainEntryExpiry(rr.Header().Ttl, now)
	switch v := rr.(type) {
	case *dns.A:
		storeIPDomainMapping(v.A.String(), ipDomainEntry{domain: domain, expiresAt: expiry})
	case *dns.AAAA:
		storeIPDomainMapping(v.AAAA.String(), ipDomainEntry{domain: domain, expiresAt: expiry})
	case *dns.HTTPS:
		for _, kv := range v.Value {
			for _, ip := range extractSVCBHintIPs(kv) {
				storeIPDomainMapping(ip.String(), ipDomainEntry{domain: domain, expiresAt: expiry})
			}
		}
	case *dns.SVCB:
		for _, kv := range v.Value {
			for _, ip := range extractSVCBHintIPs(kv) {
				storeIPDomainMapping(ip.String(), ipDomainEntry{domain: domain, expiresAt: expiry})
			}
		}
	}
}

func cacheDNSResponse(domain string, cacheKey string, respData []byte) *dns.Msg {
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respData); err != nil {
		return nil
	}
	if respMsg.Rcode != dns.RcodeSuccess || len(respMsg.Answer) == 0 {
		return respMsg
	}

	minTTL := uint32(minDNSCacheTTL)
	first := true
	now := time.Now()
	for _, ans := range respMsg.Answer {
		if first || ans.Header().Ttl < minTTL {
			minTTL = ans.Header().Ttl
			first = false
		}
		storeRecordIPMappings(domain, ans, now)
	}

	dnsCacheMu.Lock()
	pruneDNSCacheLocked(now)
	dnsCache[cacheKey] = dnsCacheEntry{
		msg:       respMsg,
		expiresAt: dnsEntryExpiry(minTTL, now),
	}
	dnsCacheMu.Unlock()
	return respMsg
}

func extractIPsFromDNSMsg(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	var ips []string
	seen := make(map[string]struct{})
	for _, ans := range msg.Answer {
		var ipStr string
		switch rr := ans.(type) {
		case *dns.A:
			ipStr = rr.A.String()
		case *dns.AAAA:
			ipStr = rr.AAAA.String()
		default:
			continue
		}
		if _, ok := seen[ipStr]; ok {
			continue
		}
		seen[ipStr] = struct{}{}
		ips = append(ips, ipStr)
	}
	return ips
}

func resolveDirectHost(ctx context.Context, host string) ([]string, error) {
	cleanHost := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if cleanHost == "" {
		return nil, fmt.Errorf("empty host")
	}

	fqdn := dns.Fqdn(cleanHost)
	now := time.Now()
	var lastErr error

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		cacheKey := dnsCacheKey(fqdn, qtype)
		dnsCacheMu.RLock()
		entry, found := dnsCache[cacheKey]
		dnsCacheMu.RUnlock()
		if found && now.Before(entry.expiresAt) {
			if ips := extractIPsFromDNSMsg(entry.msg); len(ips) > 0 {
				return ips, nil
			}
		}

		reqMsg := new(dns.Msg)
		reqMsg.SetQuestion(fqdn, qtype)
		reqData, err := reqMsg.Pack()
		if err != nil {
			lastErr = err
			continue
		}
		respData, err := exchangeDNSDirect(ctx, reqData, nil)
		if err != nil {
			lastErr = err
			continue
		}
		respMsg := cacheDNSResponse(cleanHost, cacheKey, respData)
		if ips := extractIPsFromDNSMsg(respMsg); len(ips) > 0 {
			return ips, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no direct DNS records for %s", cleanHost)
}

func StartLocalDNS() {
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: localDNSListenPort()}
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
	cacheKey := dnsCacheKey(question.Name, question.Qtype)

	// 1. Check Cache
	dnsCacheMu.RLock()
	entry, found := dnsCache[cacheKey]
	dnsCacheMu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		resp := entry.msg.Copy()
		resp.Id = msg.Id // Match the request ID
		if len(resp.Question) > 0 {
			resp.Question[0].Name = question.Name
		}
		if packed, err := resp.Pack(); err == nil {
			_, _ = conn.WriteToUDP(packed, clientAddr)
			return
		}
	}

	domain := question.Name
	config := GetDNSConfig()
	server, resolveDirect := selectDNSServer(config, domain)
	if server == nil && !resolveDirect {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		respData []byte
		err      error
	)
	client := common.GetActiveClient()
	if resolveDirect || client == nil {
		respData, err = exchangeDNSDirect(ctx, reqData, server)
	} else {
		dnsAddr := server.Address
		respData, err = queryDNSThroughProxy(ctx, client, dnsAddr, reqData)
	}
	if err != nil || len(respData) == 0 {
		return
	}

	// 2. Parse Response and Update Cache
	cacheDNSResponse(domain, cacheKey, respData)

	_, _ = conn.WriteToUDP(respData, clientAddr)
}
