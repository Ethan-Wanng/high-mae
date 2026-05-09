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
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
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

	var localAddr *net.TCPAddr
	if IsTunModeOn {
		realIP := GetRealLocalIP()
		if realIP != "" && realIP != "10.0.0.1" && realIP != "10.0.0.2" {
			localAddr = &net.TCPAddr{IP: net.ParseIP(realIP), Port: 0}
		}
	}
	if node.Type == "anytls" {
		// 1. 创建带生命周期控制的 Context
		clientCtx, cancelClient := context.WithCancel(context.Background())

		dialer := &net.Dialer{Timeout: 10 * time.Second, LocalAddr: localAddr}
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

		// 2. 初始化引擎，🚀 强行塞入 dummyLogger，彻底堵死空指针崩溃漏洞！
		client, err := sing_anytls.NewClient(clientCtx, sing_anytls.ClientConfig{
			Password:       node.Password,
			MinIdleSession: 1,
			DialOut:        anytls_util.DialOutFunc(dialOut),
			Logger:         dummyLogger{}, // <--- 救命的黑魔法在这里
		})
		if err != nil {
			cancelClient()
			return nil, nil, err
		}

		dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := client.CreateProxy(ctx, metadata.ParseSocksaddr(addr))
			if err == nil {
				conn = &TrackingConn{conn}
			}
			return conn, err
		}

		// 3. 测速完成后的安全清理逻辑
		cleanup = func() {
			cancelClient() // 发送取消信号，优雅终止底层死循环
			// 主动关闭连接池
			if closer, ok := any(client).(io.Closer); ok {
				closer.Close()
			}
		}

	} else if node.Type == "mieru" {
		adapter, err := newMieruClientAdapter(node)
		if err != nil {
			return nil, nil, err
		}

		dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := adapter.CreateProxy(ctx, metadata.ParseSocksaddr(addr))
			if err == nil {
				conn = &TrackingConn{conn}
			}
			return conn, err
		}
		cleanup = func() {
			adapter.Close()
		}

	} else {
		// B. Sing-box 其他多协议节点
		opts, err := buildSingBoxOptions(node, newIP)
		if err != nil {
			return nil, nil, err
		}

		boxCtx, cancelBox := context.WithCancel(context.Background())
		b, err := box.New(box.Options{Options: opts, Context: include.Context(boxCtx)})
		if err != nil {
			cancelBox()
			return nil, nil, err
		}
		if err := b.Start(); err != nil {
			b.Close()
			cancelBox()
			return nil, nil, err
		}

		adapter := &SingBoxAdapter{Instance: b}
		dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := adapter.CreateProxy(ctx, metadata.ParseSocksaddr(addr))
			if err == nil {
				conn = &TrackingConn{conn}
			}
			return conn, err
		}
		cleanup = func() { 
			b.Close()
			cancelBox() 
		}
	}

	tr := &http.Transport{
		DialContext:       dialCtx,
		ForceAttemptHTTP2: false,
		MaxIdleConns:      1,
		IdleConnTimeout:   1 * time.Second,
	}

	// 直接组装成原生 HTTP Client 返回
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	finalCleanup := func() {
		tr.CloseIdleConnections()
		if cleanup != nil {
			cleanup()
		}
	}

	return httpClient, finalCleanup, nil
}

// =======================================================
// 1. 核心测速组件 (纯逻辑，无 UI 耦合，方便复用)
// =======================================================
func CheckProxyLatency(proxyURL string, targetURL string, timeout time.Duration) (int64, error) {
	pUrl, err := url.Parse(proxyURL)
	if err != nil {
		return 0, fmt.Errorf("代理地址解析失败: %v", err)
	}

	tr := &http.Transport{
		Proxy:             http.ProxyURL(pUrl),
		ForceAttemptHTTP2: false,
		MaxIdleConns:      1,
		IdleConnTimeout:   1 * time.Second,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	start := time.Now()
	resp, err := client.Get(targetURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// 🚀 核心优化：将 Body 的数据读入黑洞丢弃。
	// 这是 Go 标准库的潜规则：只有读完 Body，底层的 TCP/TLS 连接才能被放入连接池复用！
	io.Copy(io.Discard, resp.Body)

	// 只要不是 204 或者 200，说明节点遇到了验证码/拦截网页
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("节点可能被拦截，异常状态码: %d", resp.StatusCode)
	}
	return time.Since(start).Milliseconds(), nil
}

func TestNodeLatency(node protocol.Node) (int64, error) {
	client, cleanup, err := CreateTempHTTPClient(node)
	if err != nil {
		return 0, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	targetURL := "https://cp.cloudflare.com/generate_204"
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

// FastTCPPing 提供极低内存、极快速度的 TCP 握手测速，专门用于"一键测速全部节点"
// 它不会启动任何代理内核，因此内存消耗几乎为 0，并且可以轻松绕过 TUN 网卡防止死循环
func FastTCPPing(node protocol.Node) (int64, error) {
	newIP := resolveDirect(node.Server)
	dialHost := node.Server
	if newIP != "" {
		dialHost = newIP
	}

	port := node.Port
	if port <= 0 {
		if node.PortRange != "" || node.Ports != "" || node.MPort != "" {
			return 0, fmt.Errorf("不支持端口段测速")
		}
		port = 443 // 默认回退
	}
	addr := net.JoinHostPort(dialHost, fmt.Sprint(port))

	// 获取真实的本地 IP，绕过 TUN
	var localAddr net.Addr

	isUDP := node.Type == "hysteria2" || node.Type == "hy2" || node.Type == "wireguard"
	network := "tcp"
	if isUDP {
		network = "udp"
	}

	if IsTunModeOn {
		realIP := GetRealLocalIP()
		if realIP != "" && realIP != "10.0.0.1" && realIP != "10.0.0.2" {
			if isUDP {
				localAddr = &net.UDPAddr{IP: net.ParseIP(realIP), Port: 0}
			} else {
				localAddr = &net.TCPAddr{IP: net.ParseIP(realIP), Port: 0}
			}
		}
	}

	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		LocalAddr: localAddr,
	}

	// 🚀 核心修复：UDP 的 Dial 是无连接的，永远"成功"且延迟为 0，根本测不出连通性！
	// 对于 Hysteria2 等基于 QUIC 的 UDP 协议，必须发一个真实的 QUIC Initial 包，
	// 等服务器回一个 Version Negotiation / Retry / Handshake 包，才能证明对端存活。
	if isUDP {
		return fastQUICPing(dialer, network, addr)
	}

	start := time.Now()
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start).Milliseconds(), nil
}

// fastQUICPing 发送一个故意使用无效版本号的 QUIC Long Header 包，验证 UDP 服务器是否存活。
// 根据 RFC 9000 §6.1，QUIC 服务器收到不支持的版本时 **必须** 回复 Version Negotiation 包，
// 所以只要能收到任何回包，就证明服务器可达且端口开放。
//
// 💡 为什么不用合法的 QUIC v1 版本？
// 因为 v1 Initial 包的 payload 必须包含有效的 CRYPTO frame (TLS ClientHello)，
// 否则服务器会静默丢弃 → 永远 timeout。用无效版本号能 100% 触发 Version Negotiation 回包。
func fastQUICPing(dialer *net.Dialer, network, addr string) (int64, error) {
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// 构造一个最简 QUIC Long Header 包，故意用无效版本号触发 Version Negotiation:
	// RFC 9000 §17.2 Long Header 格式:
	//   [Header Form (1) | Fixed Bit (1) | Type (2) | Reserved (4)] = 1 byte
	//   [Version (4 bytes)]
	//   [DCID Len (1)] [DCID (N)] [SCID Len (1)] [SCID (M)]
	//   [Payload ...]
	// 整个包必须 >= 1200 字节 (RFC 9000 §14.1) 才会被服务器当作合法的初始包处理
	packet := make([]byte, 1200)
	packet[0] = 0xC0 // Long Header Form bit set, Fixed bit set
	// 🚀 关键：使用一个绝对不存在的 QUIC 版本号，强制触发 Version Negotiation
	packet[1] = 0xBA
	packet[2] = 0xBA
	packet[3] = 0xBA
	packet[4] = 0xBA
	// DCID Length = 8
	packet[5] = 0x08
	// DCID (bytes 6-13): 固定探测值
	packet[6] = 0xDE
	packet[7] = 0xAD
	packet[8] = 0xBE
	packet[9] = 0xEF
	packet[10] = 0xCA
	packet[11] = 0xFE
	packet[12] = 0xBA
	packet[13] = 0xBE
	// SCID Length = 0
	packet[14] = 0x00
	// 剩余部分全是 0 (填充)

	start := time.Now()

	// 写出探测包
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(packet); err != nil {
		return 0, fmt.Errorf("UDP 发送失败: %w", err)
	}

	// 等待服务器回复 Version Negotiation 包
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	_, err = conn.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("UDP 服务器无响应 (超时或不可达): %w", err)
	}

	return time.Since(start).Milliseconds(), nil
}


// =======================================================
// 2. GUI 菜单绑定的触发函数 (处理弹窗交互)
// =======================================================
func TestProxyLatency() {
	proxyStr := "http://127.0.0.1:" + LocalHttpPort

	// 使用 Cloudflare 的 204 接口，全球 CDN 加速，比 Google 更稳定且不会弹人机验证
	targetURL := "https://cp.cloudflare.com/generate_204"

	// 放宽到 8 秒，包容复杂协议的冷启动
	latency, err := CheckProxyLatency(proxyStr, targetURL, 8*time.Second)

	if err != nil {
		// 优化错误提示，去掉冗长且难看的 Go 语言原生错误堆栈
		errMsg := err.Error()
		if strings.Contains(errMsg, "Client.Timeout") || strings.Contains(errMsg, "timeout") {
			errMsg = "节点连接超时 (Timeout)"
		} else if strings.Contains(errMsg, "connection refused") {
			errMsg = "本地代理服务未启动或被拒绝"
		}

		ShowWindowsMsgBox("测速失败", fmt.Sprintf("当前节点连通性异常！\n可尝试在上方菜单切换其他节点。\n\n详情: %s", errMsg))
		return
	}

	// 评级表情
	rating := "🟡 较慢"
	if latency < 200 {
		rating = "🚀 极佳"
	} else if latency < 500 {
		rating = "🟢 良好"
	} else if latency >= 1000 {
		rating = "🔴 极差"
	}

	ShowWindowsMsgBox("测速结果", fmt.Sprintf("🎯 当前节点畅通！\n\n⏱ 延迟：%d ms\n📊 状态：%s", latency, rating))
}

// 🚀 专治 AnyTLS 空指针的哑巴日志器
type dummyLogger struct{}

func (l dummyLogger) TraceContext(ctx context.Context, args ...any) {}

func (l dummyLogger) DebugContext(ctx context.Context, args ...any) {}

func (l dummyLogger) InfoContext(ctx context.Context, args ...any) {}

func (l dummyLogger) WarnContext(ctx context.Context, args ...any) {}

func (l dummyLogger) ErrorContext(ctx context.Context, args ...any) {}

func (l dummyLogger) FatalContext(ctx context.Context, args ...any) {}

func (l dummyLogger) PanicContext(ctx context.Context, args ...any) {}

func (l dummyLogger) Trace(args ...any)                 {}
func (l dummyLogger) Tracef(format string, args ...any) {}
func (l dummyLogger) Debug(args ...any)                 {}
func (l dummyLogger) Debugf(format string, args ...any) {}
func (l dummyLogger) Info(args ...any)                  {}
func (l dummyLogger) Infof(format string, args ...any)  {}
func (l dummyLogger) Warn(args ...any)                  {}
func (l dummyLogger) Warnf(format string, args ...any)  {}
func (l dummyLogger) Error(args ...any)                 {}
func (l dummyLogger) Errorf(format string, args ...any) {}
func (l dummyLogger) Fatal(args ...any)                 {}
func (l dummyLogger) Fatalf(format string, args ...any) {}
func (l dummyLogger) Panic(args ...any)                 {}
func (l dummyLogger) Panicf(format string, args ...any) {}
