package ins

import (
	"context"
	"fmt"
	sing_anytls "github.com/anytls/sing-anytls"
	anytls_util "github.com/anytls/sing-anytls/util"
	utls "github.com/refraction-networking/utls"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing/common/metadata"
	"high-mae/protocol"
	"net"
	"net/http"
	"net/url"
	"time"
)

// resolveDirect 智能解析服务器地址为真实 IP
// 1. 如果已经是 IP，直接返回
// 2. 如果是域名，进行本地 DNS 解析并优先返回 IPv4 地址
// 3. 解析失败返回空字符串，交由上层降级使用原域名
func resolveDirect(host string) string {
	// 如果为空，直接跳过
	if host == "" {
		return ""
	}

	// 1. 判断是否已经是合法的 IP 地址 (IPv4 / IPv6)
	if ip := net.ParseIP(host); ip != nil {
		return host
	}

	// 2. 发起系统 DNS 解析
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		// 解析失败（可能是没网，或者域名写错了），返回空字符串
		return ""
	}

	// 3. 遍历解析结果，优先提取 IPv4 地址
	// (因为部分网络环境或代理协议对纯 IPv6 的握手兼容性较差)
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		// ip.To4() 不为 nil 说明这是一个 IPv4 地址
		if ip != nil && ip.To4() != nil {
			return ipStr
		}
	}

	// 4. 如果没有找到 IPv4 地址，只能退而求其次返回第一个 IPv6 地址
	return ips[0]
}

// CreateTempHTTPClient 直接返回一个装载了特定节点的原生 http.Client，专供并发测速
func CreateTempHTTPClient(node protocol.Node) (*http.Client, func(), error) {
	newIP := resolveDirect(node.Server)
	var dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
	var cleanup func()

	// A. AnyTLS 节点
	if node.Type == "anytls" {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		dialOut := func(ctx context.Context) (net.Conn, error) {
			dialHost := node.Server
			if newIP != "" {
				dialHost = newIP
			}
			nodeAddr := net.JoinHostPort(dialHost, fmt.Sprint(node.Port))
			conn, err := dialer.DialContext(ctx, "tcp", nodeAddr)
			if err != nil {
				return nil, err
			}
			sni := node.SNI
			if sni == "" {
				sni = node.Server
			}
			tlsConfig := &utls.Config{ServerName: sni, InsecureSkipVerify: node.SkipCertVerify}
			tlsConn := utls.UClient(conn, tlsConfig, utls.HelloFirefox_Auto)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		}

		client, err := sing_anytls.NewClient(context.Background(), sing_anytls.ClientConfig{
			Password:       node.Password,
			MinIdleSession: 1,
			DialOut:        anytls_util.DialOutFunc(dialOut),
		})
		if err != nil {
			return nil, nil, err
		}

		dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return client.CreateProxy(ctx, metadata.ParseSocksaddr(addr))
		}
		cleanup = func() {} // AnyTLS 由 Go GC 自动回收

	} else {
		// B. Sing-box 其他多协议节点
		opts, err := buildSingBoxOptions(node, newIP)
		if err != nil {
			return nil, nil, err
		}

		b, err := box.New(box.Options{Options: opts, Context: include.Context(context.Background())})
		if err != nil {
			return nil, nil, err
		}
		if err := b.Start(); err != nil {
			b.Close()
			return nil, nil, err
		}

		adapter := &SingBoxAdapter{Instance: b}
		dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return adapter.CreateProxy(ctx, metadata.ParseSocksaddr(addr))
		}
		cleanup = func() { b.Close() } // 测完手动关闭释放内存
	}

	// 直接组装成原生 HTTP Client 返回
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext:       dialCtx,
			ForceAttemptHTTP2: true,
		},
		Timeout: 5 * time.Second,
	}

	return httpClient, cleanup, nil
}

func TestProxyLatency() {
	proxyUrl, _ := url.Parse("http://127.0.0.1:" + LocalHttpPort)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)},
		Timeout:   5 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get("https://www.google.com/generate_204")
	if err != nil {
		ShowWindowsMsgBox("测速失败", "当前节点超时或网络异常！\n可尝试在上方菜单切换其他节点。\n\n详情: "+err.Error())
		return
	}
	defer resp.Body.Close()

	latency := time.Since(start).Milliseconds()
	rating := "🟡 较慢"
	if latency < 200 {
		rating = "🚀 极佳"
	} else if latency < 500 {
		rating = "🟢 良好"
	}

	ShowWindowsMsgBox("测速结果", fmt.Sprintf("🎯 当前节点畅通！\n\n⏱ 延迟：%d ms\n📊 状态：%s", latency, rating))
}
