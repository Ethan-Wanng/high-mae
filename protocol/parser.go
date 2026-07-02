package protocol

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"wing/pkg/secure"

	"gopkg.in/yaml.v3"
)

type WSOpts struct {
	Path    string            `yaml:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

type RealityOpts struct {
	PublicKey string `yaml:"public-key,omitempty"`
	ShortID   string `yaml:"short-id,omitempty"`
}

type Node struct {
	Type                string            `yaml:"type"`
	Name                string            `yaml:"name"`
	Server              string            `yaml:"server"`
	Port                int               `yaml:"port"`
	PortRange           string            `yaml:"port-range,omitempty"`
	Ports               string            `yaml:"ports,omitempty"`
	MPort               string            `yaml:"mport,omitempty"`
	UUID                string            `yaml:"uuid"`
	Username            string            `yaml:"username,omitempty"`
	Password            string            `yaml:"password"`
	HashedPassword      string            `yaml:"hashed-password,omitempty"`
	Method              string            `yaml:"method,omitempty"`
	SNI                 string            `yaml:"sni,omitempty"`
	ALPN                []string          `yaml:"alpn"`
	SkipCertVerify      bool              `yaml:"skip-cert-verify,omitempty"`
	Insecure            bool              `yaml:"insecure,omitempty"`       // Clash 常用
	AllowInsecure       bool              `yaml:"allow-insecure,omitempty"` // Clash 常用
	DisableSNI          bool              `yaml:"disable-sni,omitempty"`
	ReduceRTT           bool              `yaml:"reduce-rtt,omitempty"`
	CongestionControl   string            `yaml:"congestion-control,omitempty"`
	UDPRelayMode        string            `yaml:"udp-relay-mode,omitempty"`
	ClientFingerprint   string            `yaml:"client-fingerprint,omitempty"`
	UDP                 bool              `yaml:"udp,omitempty"`
	TFO                 bool              `yaml:"tfo,omitempty"`
	TLS                 bool              `yaml:"tls,omitempty"` // 统一使用 TLS 字段
	Tls                 bool              `yaml:"-"`             // 兼容旧版，解析时忽略
	AlterId             int               `yaml:"alterId,omitempty"`
	Cipher              string            `yaml:"cipher,omitempty"`
	Network             string            `yaml:"network,omitempty"`
	Host                string            `yaml:"host,omitempty"`
	WSPath              string            `yaml:"ws-path,omitempty"`
	WSHeaders           map[string]string `yaml:"ws-headers,omitempty"`
	WSOpts              WSOpts            `yaml:"ws-opts,omitempty"`
	Flow                string            `yaml:"flow,omitempty"`
	ServerName          string            `yaml:"servername,omitempty"` // VLESS 专用 SNI 别名
	RealityOpts         *RealityOpts      `yaml:"reality-opts,omitempty"`
	GrpcOpts            map[string]string `yaml:"grpc-opts,omitempty"`
	Transport           string            `yaml:"transport,omitempty"`
	Mtu                 int               `yaml:"mtu,omitempty"`
	Multiplexing        string            `yaml:"multiplexing,omitempty"`
	HandshakeMode       string            `yaml:"handshake-mode,omitempty"`
	TrafficPattern      string            `yaml:"traffic-pattern,omitempty"`
	DomainStrategy      string            `yaml:"domain-strategy,omitempty"`
	QUIC                bool              `yaml:"quic,omitempty"`
	QUICCongestion      string            `yaml:"quic-congestion-control,omitempty"`
	InsecureConcurrency int               `yaml:"insecure-concurrency,omitempty"`
	ExtraHeaders        map[string]string `yaml:"extra-headers,omitempty"`
	Group               string            `yaml:"group,omitempty"`
	Obfs                string            `yaml:"obfs,omitempty"`
	ObfsPassword        string            `yaml:"obfs-password,omitempty"`
	SourceFile          string            `yaml:"source-file,omitempty"`
	SourceKey           string            `yaml:"source-key,omitempty"`
	SourceName          string            `yaml:"source-name,omitempty"`
}

const (
	maxSubscriptionInputBytes    = 8 << 20
	maxSubscriptionResponseBytes = 8 << 20
	maxSubscriptionDecodedBytes  = 8 << 20
	maxSubscriptionGzipBytes     = 16 << 20
	maxSubscriptionEncodedChars  = 12 << 20
)

func PreprocessYAML(data string) string {
	// 预处理：万一有连续的 }{ 之间没有分隔符，强行插入 --- 分隔符
	s := strings.ReplaceAll(data, "}\n{", "}\n---\n{")
	s = strings.ReplaceAll(s, "}{", "}\n---\n{")
	return s
}

func ParseNodes(path string) ([]Node, error) {
	data, err := secure.SecureReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseNodesData(data)
}

func ParseNodesData(data []byte) ([]Node, error) {
	content := PreprocessYAML(string(data))
	var nodes []Node

	chunks := strings.Split(content, "\n---")
	for _, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		var node Node
		err := yaml.Unmarshal([]byte(chunk), &node)
		if err != nil {
			fmt.Printf("⚠️ 提示: 解析节点失败, 忽略该节点: %v\n", err)
			continue
		}

		// 🚀 核心修改：使用 switch 白名单支持多协议扩展
		switch node.Type {
		case "anytls", "trojan", "tuic", "vmess", "ss", "hysteria2", "hy2", "http", "https", "vless", "socks5", "ssocks", "mieru", "naive":
			// 如果未来增加了新协议，直接在这个 case 里加名字即可
			nodes = append(nodes, node)
		default:
			// 如果遇到未知协议或者空类型，静默跳过
			if node.Type != "" {
				fmt.Printf("⚠️ 提示: 跳过不支持的协议节点 [%s] %s\n", node.Type, node.Name)
			}
		}
	}
	return nodes, nil
}

func tryGzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxSubscriptionGzipBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxSubscriptionGzipBytes {
		return nil, fmt.Errorf("gzip decoded subscription exceeds %d bytes", maxSubscriptionGzipBytes)
	}
	return out, nil
}

func tryBase64Variants(s string) ([]byte, bool) {
	clean := strings.TrimSpace(s)
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.ReplaceAll(clean, "\n", "")
	if len(clean) > maxSubscriptionEncodedChars {
		return nil, false
	}
	var decoders = []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString, base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString, base64.RawURLEncoding.DecodeString,
	}
	for _, dec := range decoders {
		if out, err := dec(clean); err == nil && len(out) > 0 && len(out) <= maxSubscriptionDecodedBytes {
			return out, true
		}
	}
	return nil, false
}

func LoadInput(input string) ([]byte, error) {
	return LoadInputWithUserAgent(input, "wing/1.0")
}

func LoadInputWithUserAgent(input string, userAgent string) ([]byte, error) {
	result, err := LoadInputWithUserAgentInfoContext(context.Background(), input, userAgent)
	if err != nil {
		return nil, err
	}
	return result.Body, nil
}

type LoadInputResult struct {
	Body    []byte
	Headers http.Header
}

func LoadInputWithUserAgentInfo(input string, userAgent string) (LoadInputResult, error) {
	return LoadInputWithUserAgentInfoContext(context.Background(), input, userAgent)
}

func LoadInputWithUserAgentInfoContext(ctx context.Context, input string, userAgent string) (LoadInputResult, error) {
	s := strings.TrimSpace(input)
	s = strings.Trim(s, "“”\"'")
	if len(s) > maxSubscriptionInputBytes {
		return LoadInputResult{}, fmt.Errorf("subscription input exceeds %d bytes", maxSubscriptionInputBytes)
	}

	isSingleLine := !strings.Contains(s, "\n")
	if isPlainHTTPRemoteInput(s, isSingleLine) && !allowInsecureSubscriptionInput() {
		return LoadInputResult{}, fmt.Errorf("出于安全原因，默认拒绝明文 HTTP 订阅；请改用 HTTPS")
	}
	if (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")) && isSingleLine && !strings.Contains(s, "@") {
		if err := validateRemoteSubscriptionURL(ctx, s); err != nil {
			return LoadInputResult{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s, nil)
		if err != nil {
			return LoadInputResult{}, err
		}

		// 这里保留正常请求头，不做“伪装绕过”
		if userAgent == "" {
			userAgent = "wing/1.0"
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

		return doSubscriptionRequest(req)
	}

	return LoadInputResult{Body: []byte(s), Headers: http.Header{}}, nil
}

func isPlainHTTPRemoteInput(input string, isSingleLine bool) bool {
	return isSingleLine && !strings.Contains(input, "@") && strings.HasPrefix(input, "http://")
}

func allowInsecureSubscriptionInput() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("WING_ALLOW_INSECURE_SUBSCRIPTIONS")))
	return value == "1" || value == "true" || value == "yes"
}

func validateRemoteSubscriptionURL(ctx context.Context, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && allowInsecureSubscriptionInput()) {
		return fmt.Errorf("unsupported subscription URL scheme: %s", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("subscription URL missing host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedSubscriptionIP(ip) {
			return fmt.Errorf("subscription URL targets a local or private address")
		}
		return nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return fmt.Errorf("subscription host resolved no addresses")
	}
	for _, addr := range addrs {
		if isBlockedSubscriptionIP(addr.IP) {
			return fmt.Errorf("subscription URL resolves to a local or private address")
		}
	}
	return nil
}

func isBlockedSubscriptionIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}

func readLimitedSubscriptionBody(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("subscription response exceeds %d bytes", limit)
	}
	return body, nil
}

func doSubscriptionRequest(req *http.Request) (LoadInputResult, error) {
	var lastErr error
	attempts := []struct {
		name  string
		proxy func(*http.Request) (*url.URL, error)
		http2 bool
	}{
		{name: "env_proxy", proxy: http.ProxyFromEnvironment, http2: true},
		{name: "direct", http2: true},
		{name: "direct_http1", http2: false},
	}

	for _, attempt := range attempts {
		clone := req.Clone(req.Context())
		transport := subscriptionTransport(attempt.proxy, attempt.http2)
		client := &http.Client{
			Timeout:   20 * time.Second,
			Transport: transport,
			CheckRedirect: func(redirectReq *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return validateRemoteSubscriptionURL(redirectReq.Context(), redirectReq.URL.String())
			},
		}
		resp, err := client.Do(clone)
		if err != nil {
			transport.CloseIdleConnections()
			lastErr = fmt.Errorf("%s: %w", attempt.name, err)
			continue
		}

		body, readErr := readLimitedSubscriptionBody(resp.Body, maxSubscriptionResponseBytes)
		resp.Body.Close()
		transport.CloseIdleConnections()
		if readErr != nil {
			lastErr = fmt.Errorf("%s: %w", attempt.name, readErr)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("订阅下载失败，HTTP 状态码: %d, 响应: %s", resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 1024)])))
			continue
		}
		return LoadInputResult{Body: body, Headers: resp.Header.Clone()}, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("unknown subscription request error")
	}
	return LoadInputResult{}, fmt.Errorf("HTTP 请求失败: %w", lastErr)
}

func subscriptionTransport(proxy func(*http.Request) (*url.URL, error), http2 bool) *http.Transport {
	return &http.Transport{
		Proxy: proxy,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     http2,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	}
}

func NormalizeSubscription(raw []byte) (string, error) {
	if len(raw) > maxSubscriptionResponseBytes {
		return "", fmt.Errorf("subscription input exceeds %d bytes", maxSubscriptionResponseBytes)
	}
	b := bytes.TrimSpace(raw)
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	s := string(b)
	if strings.Contains(s, "://") {
		return s, nil
	}
	if dec, err := tryGzip(b); err == nil && len(dec) > 0 {
		s = string(bytes.TrimSpace(dec))
		if strings.Contains(s, "://") {
			return s, nil
		}
		b = dec
	}
	tryList := [][]byte{b}
	decodedOnce := false
	for round := 0; round < 2; round++ {
		var next []byte
		for _, candidate := range tryList {
			if dec, ok := tryBase64Variants(string(candidate)); ok {
				next = dec
				decodedOnce = true
				break
			}
		}
		if len(next) == 0 {
			break
		}
		text := strings.TrimSpace(string(next))
		if strings.Contains(text, "://") {
			return text, nil
		}
		tryList = [][]byte{next}
	}
	if decodedOnce {
		return strings.TrimSpace(string(tryList[0])), nil
	}
	return strings.TrimSpace(string(b)), nil
}

func getString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int(t)) {
			return strconv.Itoa(int(t))
		}
		return fmt.Sprintf("%v", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}
func getPort(v any) (int, error) {
	switch t := v.(type) {
	case string:
		return strconv.Atoi(t)
	case float64:
		return int(t), nil
	case int:
		return t, nil
	default:
		return 0, fmt.Errorf("unsupported port type")
	}
}
