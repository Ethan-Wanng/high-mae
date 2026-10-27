package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"wing/pkg/common"
	"wing/pkg/utils"
	"wing/protocol"

	"github.com/miekg/dns"
)

// 订阅可为节点域名指定专用 DoH（Node.DNSServers）。这些域名在公共 DNS 上可能被解析到
// 占位 IP，导致测速全部超时、连接失败，因此优先使用订阅声明的解析器。

const (
	nodeDoHTimeout  = 4 * time.Second
	nodeDoHMinCache = 60 * time.Second
	nodeDoHMaxCache = 10 * time.Minute
)

type nodeDoHCacheEntry struct {
	ips     []string
	expires time.Time
}

type nodeDoHCall struct {
	done chan struct{}
	ips  []string
}

var (
	nodeDoHMu       sync.Mutex
	nodeDoHCache    = make(map[string]nodeDoHCacheEntry)
	nodeDoHInflight = make(map[string]*nodeDoHCall)

	nodeDoHClientsOnce sync.Once
	nodeDoHSecure      *http.Client
	nodeDoHInsecure    *http.Client
)

// resolveNodeServerWithStrategy 解析节点地址：优先订阅指定的 DoH，其次系统 DNS；
// 域名对应多个地址时选出当前可连通的那个（见 pickReachableNodeIP）。解析失败返回空字符串。
func resolveNodeServerWithStrategy(node protocol.Node, strategy string) string {
	cleanHost := strings.Trim(strings.TrimSpace(node.Server), "[]")
	if cleanHost == "" {
		return ""
	}
	if net.ParseIP(cleanHost) != nil {
		return cleanHost
	}
	var ips []string
	if len(node.DNSServers) > 0 {
		ips = lookupNodeDoH(cleanHost, node.DNSServers, strategy)
	}
	if len(ips) == 0 {
		ips = lookupSystemIPs(cleanHost)
	}
	candidates := candidateResolvedIPs(ips, strategy)
	switch len(candidates) {
	case 0:
		return ""
	case 1:
		return candidates[0]
	}
	return pickReachableNodeIP(node, candidates)
}

func lookupNodeDoH(host string, servers []string, strategy string) []string {
	key := strings.ToLower(host) + "|" + strategy + "|" + strings.Join(servers, ",")

	nodeDoHMu.Lock()
	if entry, ok := nodeDoHCache[key]; ok && time.Now().Before(entry.expires) {
		nodeDoHMu.Unlock()
		return entry.ips
	}
	// 批量测速时同一域名会被多个协议节点同时解析，合并成一次查询。
	if call, ok := nodeDoHInflight[key]; ok {
		nodeDoHMu.Unlock()
		<-call.done
		return call.ips
	}
	call := &nodeDoHCall{done: make(chan struct{})}
	nodeDoHInflight[key] = call
	nodeDoHMu.Unlock()

	ips, ttl := queryNodeDoHServers(host, servers, strategy)

	nodeDoHMu.Lock()
	call.ips = ips
	delete(nodeDoHInflight, key)
	if len(ips) > 0 {
		nodeDoHCache[key] = nodeDoHCacheEntry{ips: ips, expires: time.Now().Add(clampDuration(ttl, nodeDoHMinCache, nodeDoHMaxCache))}
	}
	nodeDoHMu.Unlock()
	close(call.done)
	return ips
}

func queryNodeDoHServers(host string, servers []string, strategy string) ([]string, time.Duration) {
	qtypes := []uint16{dns.TypeA}
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(strategy), "-", "_")) {
	case "ipv6_only":
		qtypes = []uint16{dns.TypeAAAA}
	case "ipv4_only":
	default:
		qtypes = append(qtypes, dns.TypeAAAA)
	}

	type result struct {
		ips []string
		ttl time.Duration
	}
	ctx, cancel := context.WithTimeout(context.Background(), nodeDoHTimeout)
	defer cancel()

	// 并发请求所有声明的 DoH，取第一个有结果的服务器，避免单个入口被墙时拖慢测速。
	results := make(chan result, len(servers))
	for _, server := range servers {
		server := server
		go func() {
			var ips []string
			var ttl time.Duration
			for _, qtype := range qtypes {
				answers, answerTTL, err := queryNodeDoH(ctx, server, host, qtype)
				if err != nil {
					continue
				}
				ips = append(ips, answers...)
				if ttl == 0 || (answerTTL > 0 && answerTTL < ttl) {
					ttl = answerTTL
				}
			}
			results <- result{ips: ips, ttl: ttl}
		}()
	}
	for range servers {
		select {
		case r := <-results:
			if len(r.ips) > 0 {
				return r.ips, r.ttl
			}
		case <-ctx.Done():
			return nil, 0
		}
	}
	return nil, 0
}

func queryNodeDoH(ctx context.Context, server string, host string, qtype uint16) ([]string, time.Duration, error) {
	endpoint, insecure, err := parseNodeDoHServer(server)
	if err != nil {
		return nil, 0, err
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.Id = 0 // RFC 8484 建议 DoH 使用 0 以便缓存
	packed, err := msg.Pack()
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(packed))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	secureClient, insecureClient := nodeDoHClients()
	client := secureClient
	if insecure {
		client = insecureClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("DoH status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, 0, err
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, 0, err
	}
	if reply.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("DoH rcode %s", dns.RcodeToString[reply.Rcode])
	}

	var ips []string
	var ttl time.Duration
	for _, answer := range reply.Answer {
		var ip net.IP
		switch rr := answer.(type) {
		case *dns.A:
			ip = rr.A
		case *dns.AAAA:
			ip = rr.AAAA
		default:
			continue
		}
		ips = append(ips, ip.String())
		answerTTL := time.Duration(answer.Header().Ttl) * time.Second
		if ttl == 0 || answerTTL < ttl {
			ttl = answerTTL
		}
	}
	return ips, ttl, nil
}

func parseNodeDoHServer(server string) (string, bool, error) {
	parsed, err := url.Parse(strings.TrimSpace(server))
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return "", false, fmt.Errorf("unsupported DoH server")
	}
	insecure := false
	if params, err := url.ParseQuery(parsed.Fragment); err == nil {
		insecure = strings.EqualFold(params.Get("skip-cert-verify"), "true")
	}
	parsed.Fragment = ""
	return parsed.String(), insecure, nil
}

func nodeDoHClients() (*http.Client, *http.Client) {
	nodeDoHClientsOnce.Do(func() {
		nodeDoHSecure = newNodeDoHClient(false)
		nodeDoHInsecure = newNodeDoHClient(true)
	})
	return nodeDoHSecure, nodeDoHInsecure
}

func newNodeDoHClient(insecure bool) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// TUN 开启时绑定真实网卡地址，避免节点解析请求绕回隧道自身。
			dialer := &net.Dialer{Timeout: nodeDoHTimeout}
			if common.GetTunModeOn() {
				realIP := common.RealLocalIPBeforeTun
				if realIP == "" {
					realIP = utils.GetRealLocalIP()
				}
				if realIP != "" && realIP != common.TunIP {
					dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(realIP)}
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
		ForceAttemptHTTP2:   true, // 部分 DoH 入口只接受 HTTP/2，HTTP/1.1 会返回 505
		TLSHandshakeTimeout: nodeDoHTimeout,
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: nodeDoHTimeout}
}

func clampDuration(value, min, max time.Duration) time.Duration {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
