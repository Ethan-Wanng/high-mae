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
	"strconv"
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
	return resolveNodeServerWithStrategy(node, defaultDomainStrategy())
}

func defaultDomainStrategy() string {
	if GlobalSystemConfig.PreferIPv6 {
		return "prefer_ipv6"
	}
	return "ipv4_only"
}

func ResolveDirectWithStrategy(host string, strategy string) string {
	cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
	if cleanHost == "" {
		return ""
	}

	// 1. 判断是否已经是合法的 IP 地址 (IPv4 / IPv6)
	if ip := net.ParseIP(cleanHost); ip != nil {
		return cleanHost
	}

	return selectResolvedIP(lookupSystemIPs(cleanHost), strategy)
}

// lookupSystemIPs 用系统 DNS 解析域名；失败或命中 Fake-IP 时返回 nil。
func lookupSystemIPs(cleanHost string) []string {
	lookupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(lookupCtx, cleanHost)
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
		// 返回空后，上层会按原域名继续处理，避免额外 DNS 泄露面。
		return nil
	}
	return ips
}

func selectResolvedIP(ips []string, strategy string) string {
	if candidates := candidateResolvedIPs(ips, strategy); len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// candidateResolvedIPs 返回按解析策略应使用的那一族地址（保持原顺序）。
func candidateResolvedIPs(ips []string, strategy string) []string {
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

	var v4, v6 []string
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ipStr)
			continue
		}
		v6 = append(v6, ipStr)
	}

	if ipv4Only {
		return v4
	}
	if ipv6Only {
		return v6
	}
	if preferIPv6 && len(v6) > 0 {
		return v6
	}
	if len(v4) > 0 {
		return v4
	}
	return v6
}

// DialContextFunc 通过某个节点建立到目标地址的代理连接。
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// CreateTempHTTPClient 直接返回一个装载了特定节点的原生 http.Client，专供并发测速
func CreateTempHTTPClient(node protocol.Node) (*http.Client, func(), error) {
	dialCtx, cleanup, err := newTempNodeDialer(node)
	if err != nil {
		return nil, nil, err
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
		Timeout:   10 * time.Second,
	}

	finalCleanup := func() {
		tr.CloseIdleConnections()
		cleanup()
	}

	return httpClient, finalCleanup, nil
}

// newTempNodeDialer 为节点创建一个临时代理拨号器，用完必须调用返回的 cleanup。
func newTempNodeDialer(node protocol.Node) (DialContextFunc, func(), error) {
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

	finalCleanup := func() {
		if routeAdded {
			utils.RunHiddenCommand("route", "delete", newIP, "mask", "255.255.255.255")
		}
		if cleanup != nil {
			cleanup()
		}
	}

	return dialCtx, finalCleanup, nil
}

func parseFirstPort(portStr string) int {
	portStr = strings.Trim(strings.TrimSpace(portStr), "[]\"' ")
	for _, sep := range []string{"-", ":", "/", ","} {
		if idx := strings.Index(portStr, sep); idx != -1 {
			portStr = portStr[:idx]
			break
		}
	}
	p, _ := strconv.Atoi(strings.TrimSpace(portStr))
	return p
}

// Subscription formats may encode hopping ports as a list or a range.
// sing-box expects individual ranges with a colon separator, without brackets.
func normalizeHysteriaPorts(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '[' || r == ']' || r == ',' || r == ' ' || r == '"' || r == '\''
	})
	for i := range parts {
		parts[i] = strings.ReplaceAll(parts[i], "-", ":")
	}
	return parts
}

// =======================================================
// 2. GUI 菜单绑定的触发函数 (处理弹窗交互)
// =======================================================
func TestProxyLatency() {
	latency, err := MeasureActiveLatency(DefaultLatencyTestTimeout)

	if err != nil {
		// 优化错误提示，去掉冗长且难看的 Go 语言原生错误堆栈
		errMsg := err.Error()
		if strings.Contains(errMsg, "deadline exceeded") || strings.Contains(errMsg, "timeout") {
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
