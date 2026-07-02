package proxy

import (
	"wing/pkg/common"
	"wing/pkg/utils"

	"context"
	"fmt"
	sing_anytls "github.com/anytls/sing-anytls"
	anytls_util "github.com/anytls/sing-anytls/util"
	utls "github.com/refraction-networking/utls"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"wing/protocol"
)

// resolveDirect 智能解析服务器地址为真实 IP
// 1. 如果已经是 IP，直接返回
// 2. 如果是域名，进行本地 DNS 解析并按全局 IPv6 开关选择地址
// 3. 解析失败返回空字符串，交由上层降级使用原域名
func ResolveDirect(host string) string {
	return ResolveDirectWithStrategy(host, defaultDomainStrategy())
}

func ResolveNodeServer(node protocol.Node) string {
	return ResolveDirectWithStrategy(node.Server, defaultDomainStrategy())
}

func defaultDomainStrategy() string {
	if GlobalSystemConfig.PreferIPv6 {
		return "prefer_ipv6"
	}
	return "ipv4_only"
}

func ResolveDirectWithStrategy(host string, strategy string) string {
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
	isFakeIP := false
	if len(ips) > 0 {
		if ipObj := net.ParseIP(ips[0]); ipObj != nil {
			if ip4 := ipObj.To4(); ip4 != nil && ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
				isFakeIP = true
			}
		}
	}
	if err != nil || len(ips) == 0 || isFakeIP {
		// 隐私优先：不要在系统 DNS 失败时主动向固定公共 DNS 兜底查询节点域名。
		// 返回空字符串后，上层会按原域名继续处理，避免额外 DNS 泄露面。
		return ""
	}

	return selectResolvedIP(ips, strategy)
}

func selectResolvedIP(ips []string, strategy string) string {
	preferIPv6 := false
	ipv4Only := false
	ipv6Only := false
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(strategy), "-", "_")) {
	case "prefer_ipv6":
		preferIPv6 = true
	case "ipv4_only":
		ipv4Only = true
	case "ipv6_only":
		ipv6Only = true
	}

	var first4 string
	var first6 string
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			if first4 == "" {
				first4 = ipStr
			}
			continue
		}
		if first6 == "" {
			first6 = ipStr
		}
	}

	if ipv4Only {
		return first4
	}
	if ipv6Only {
		return first6
	}
	if preferIPv6 && first6 != "" {
		return first6
	}
	if first4 != "" {
		return first4
	}
	return first6
}

// CreateTempHTTPClient 直接返回一个装载了特定节点的原生 http.Client，专供并发测速
func CreateTempHTTPClient(node protocol.Node) (*http.Client, func(), error) {
	newIP := ResolveNodeServer(node)
	var dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
	var cleanup func()

	var routeAdded bool
	state := common.SnapshotRuntimeState()
	if state.TunModeOn && newIP != "" && newIP != state.GlobalNodeIP {
		realGateway := utils.GetDefaultGateway()
		if realGateway != "" {
			// 先尝试删除可能残留的旧路由，避免冲突
			utils.RunHiddenCommand("route", "delete", newIP, "mask", "255.255.255.255")
			utils.RunHiddenCommand("route", "add", newIP, "mask", "255.255.255.255", realGateway, "metric", "1")
			routeAdded = true
		}
	}

	var realIP string
	var localAddr *net.TCPAddr
	if state.TunModeOn {
		realIP = common.RealLocalIPBeforeTun
		if realIP == "" {
			realIP = utils.GetRealLocalIP()
		}
		if realIP != "" && realIP != common.TunIP {
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
				conn = &TrackingConn{Conn: conn}
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
				conn = &TrackingConn{Conn: conn}
			}
			return conn, err
		}
		cleanup = func() {
			adapter.Close()
		}

	} else if (node.Type == "socks5" || node.Type == "socks") && (node.TLS || node.Tls) {
		// C. SOCKS5-over-TLS (sing-box 的 SOCKS outbound 不支持 TLS，手动处理)
		adapter := &Socks5TLSAdapter{
			Server:         node.Server,
			ResolvedIP:     newIP,
			Port:           node.Port,
			Username:       node.Username,
			Password:       node.Password,
			SNI:            node.SNI,
			SkipCertVerify: node.SkipCertVerify,
			LocalIP:        realIP,
		}
		dialCtx = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := adapter.CreateProxy(ctx, metadata.ParseSocksaddr(addr))
			if err == nil {
				conn = &TrackingConn{Conn: conn}
			}
			return conn, err
		}
		cleanup = nil // Socks5TLSAdapter 无状态，无需清理

	} else {
		// D. Sing-box 其他多协议节点
		// 通用 sing-box 临时 client 暂不支持按本地 IP 绑定；AnyTLS/SOCKS5-TLS/FastTCPPing 使用 net.Dialer.LocalAddr。
		opts, err := buildSingBoxOptions(node, newIP)
		if err != nil {
			return nil, nil, err
		}

		boxCtx, cancelBox := context.WithCancel(getRegistryContext())
		b, err := box.New(box.Options{Options: opts, Context: boxCtx})
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
				conn = &TrackingConn{Conn: conn}
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
		Timeout:   30 * time.Second,
	}

	finalCleanup := func() {
		tr.CloseIdleConnections()
		if routeAdded {
			utils.RunHiddenCommand("route", "delete", newIP, "mask", "255.255.255.255")
		}
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
	var proxyFunc func(*http.Request) (*url.URL, error)
	if strings.TrimSpace(proxyURL) != "" {
		pUrl, err := url.Parse(proxyURL)
		if err != nil {
			return 0, fmt.Errorf("代理地址解析失败: %v", err)
		}
		proxyFunc = http.ProxyURL(pUrl)
	}

	tr := &http.Transport{
		Proxy:             proxyFunc,
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
	newIP := ResolveNodeServer(node)
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

	isUDP := node.Type == "hysteria2" || node.Type == "hy2" || node.Type == "wireguard" || (node.Type == "naive" && node.QUIC)
	network := "tcp"
	if isUDP {
		network = "udp"
	}

	if common.GetTunModeOn() {
		realIP := common.RealLocalIPBeforeTun
		if realIP == "" {
			realIP = utils.GetRealLocalIP()
		}
		if realIP != "" && realIP != common.TunIP {
			if isUDP {
				localAddr = &net.UDPAddr{IP: net.ParseIP(realIP), Port: 0}
			} else {
				localAddr = &net.TCPAddr{IP: net.ParseIP(realIP), Port: 0}
			}
		}
	}

	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
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
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(packet); err != nil {
		return 0, fmt.Errorf("UDP 发送失败: %w", err)
	}

	// 等待服务器回复 Version Negotiation 包
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
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
	proxyStr := "http://127.0.0.1:" + common.LocalHttpPort

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

		utils.ShowWindowsMsgBox("测速失败", fmt.Sprintf("当前节点连通性异常！\n可尝试在上方菜单切换其他节点。\n\n详情: %s", errMsg))
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

	utils.ShowWindowsMsgBox("测速结果", fmt.Sprintf("🎯 当前节点畅通！\n\n⏱ 延迟：%d ms\n📊 状态：%s", latency, rating))
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
