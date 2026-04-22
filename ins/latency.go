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

	// A. AnyTLS 节点
	if node.Type == "anytls" {
		// 1. 创建带生命周期控制的 Context
		clientCtx, cancelClient := context.WithCancel(context.Background())

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
			return client.CreateProxy(ctx, metadata.ParseSocksaddr(addr))
		}

		// 3. 测速完成后的安全清理逻辑
		cleanup = func() {
			cancelClient() // 发送取消信号，优雅终止底层死循环
			// 主动关闭连接池
			if closer, ok := any(client).(io.Closer); ok {
				closer.Close()
			}
		}

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

// =======================================================
// 1. 核心测速组件 (纯逻辑，无 UI 耦合，方便复用)
// =======================================================
func CheckProxyLatency(proxyURL string, targetURL string, timeout time.Duration) (int64, error) {
	pUrl, err := url.Parse(proxyURL)
	if err != nil {
		return 0, fmt.Errorf("代理地址解析失败: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(pUrl),
			ForceAttemptHTTP2: true, // 强制尝试 HTTP/2 以提速
		},
		Timeout: timeout,
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
