package ins

import (
	"context"
	"fmt"
	"github.com/sagernet/sing/common/json/badoption"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"high-mae/protocol"

	sing_anytls "github.com/anytls/sing-anytls"
	utls "github.com/refraction-networking/utls"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/metadata"
)

func ShouldDirect(hostPort string) bool {
	if ProxyMode == "Global" {
		return false
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	host = strings.ToLower(host)
	for _, d := range exactDomains {
		if host == d {
			return true
		}
	}
	for _, d := range suffixDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	for _, k := range keywordDomains {
		if strings.Contains(host, k) {
			return true
		}
	}
	return false
}

// 供 GenericClient 使用的 Sing-Box 适配器
type SingBoxAdapter struct {
	Instance *box.Box
}

func (s *SingBoxAdapter) CreateProxy(ctx context.Context, dest metadata.Socksaddr) (net.Conn, error) {
	if s.Instance == nil {
		return nil, fmt.Errorf("sing-box instance is nil")
	}
	ob := s.Instance.Outbound()
	if ob == nil {
		return nil, fmt.Errorf("sing-box outbound missing")
	}
	def := ob.Default()
	if def == nil {
		return nil, fmt.Errorf("no default outbound")
	}
	return def.DialContext(ctx, "tcp", dest)
}

// 全局单例的 Box，用于在切换节点时平滑重启/关闭
var currentBox *box.Box

func SwitchNode(node protocol.Node) {
	clientMu.Lock()
	defer clientMu.Unlock()

	ips, err := net.LookupHost(node.Server)
	newIP := ""
	if err == nil && len(ips) > 0 {
		newIP = ips[0]
	}

	if IsTunModeOn {
		realGateway := GetDefaultGateway()
		if GlobalNodeIP != "" && GlobalNodeIP != newIP {
			exec.Command("route", "delete", GlobalNodeIP, "mask", "255.255.255.255").Run()
		}
		if newIP != "" && realGateway != "" && GlobalNodeIP != newIP {
			exec.Command("route", "add", newIP, "mask", "255.255.255.255", realGateway, "metric", "1").Run()
		}
	}

	globalNodeServer = node.Server
	GlobalNodeIP = newIP

	// 专门处理 AnyTLS 节点 (保持原有高效客户端逻辑)
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
			// 确保 node.SkipCertVerify 被正确传递
			tlsConfig := &utls.Config{ServerName: sni, InsecureSkipVerify: node.SkipCertVerify}
			tlsConn := utls.UClient(conn, tlsConfig, utls.HelloFirefox_Auto)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		}

		newClient, err := sing_anytls.NewClient(context.Background(), sing_anytls.ClientConfig{
			Password:       node.Password,
			MinIdleSession: 1,
			DialOut:        dialOut,
		})
		if err != nil {
			log.Printf("AnyTLS Client 创建失败: %v", err)
			return
		}

		if currentBox != nil {
			currentBox.Close()
			currentBox = nil
		}
		activeClient = newClient
		return
	}

	// === 多协议支持：利用 sing-box 构建通用客户端 ===
	log.Printf("初始化通用代理引擎 [%s] 节点: %s", node.Type, node.Name)
	opts, err := buildSingBoxOptions(node, newIP)
	if err != nil {
		log.Printf("构建 Sing-Box 配置失败: %v", err)
		return
	}

	if currentBox != nil {
		currentBox.Close()
	}

	b, err := box.New(box.Options{
		Options: opts,
		Context: include.Context(context.Background()),
	})
	if err != nil {
		log.Printf("启动 Sing-Box 引擎失败: %v", err)
		return
	}

	if err := b.Start(); err != nil {
		log.Printf("开启 Sing-Box 失败: %v", err)
		b.Close()
		return
	}

	currentBox = b
	activeClient = &SingBoxAdapter{Instance: b}
}

func buildSingBoxOptions(node protocol.Node, resolvedIP string) (option.Options, error) {
	// 智能选取 SNI
	sni := node.SNI
	if sni == "" {
		sni = node.ServerName // VLESS 常用
	}
	if sni == "" {
		sni = node.Server
	}

	makeTLS := func() *option.OutboundTLSOptions {
		tls := &option.OutboundTLSOptions{
			Enabled:  true,
			Insecure: node.SkipCertVerify,
		}
		if !node.DisableSNI {
			tls.ServerName = sni
		}
		if len(node.ALPN) > 0 {
			tls.ALPN = node.ALPN
		}

		// 🌟 支持浏览器指纹伪装 (uTLS)
		if node.ClientFingerprint != "" {
			tls.UTLS = &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: node.ClientFingerprint,
			}
		}

		// 🌟 支持 REALITY 伪装
		if node.RealityOpts != nil && node.RealityOpts.PublicKey != "" {
			tls.Reality = &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: node.RealityOpts.PublicKey,
				ShortID:   node.RealityOpts.ShortID,
			}
			// Sing-box 要求开启 REALITY 必须配置 uTLS 指纹
			if tls.UTLS == nil {
				tls.UTLS = &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: "chrome",
				}
			}
		}
		return tls
	}

	serverAddr := node.Server
	if resolvedIP != "" {
		serverAddr = resolvedIP
	}
	serverOpts := option.ServerOptions{
		Server:     serverAddr,
		ServerPort: uint16(node.Port),
	}

	var outbound option.Outbound
	outbound.Tag = "proxy"

	switch node.Type {
	case "tuic":
		outbound.Type = "tuic"
		cc := node.CongestionControl
		if cc == "" {
			cc = "cubic"
		}
		opts := option.TUICOutboundOptions{
			ServerOptions:     serverOpts,
			UUID:              node.UUID,
			Password:          node.Password,
			CongestionControl: cc,
		}
		opts.TLS = makeTLS()
		outbound.Options = &opts

	// === 🚀 新增：VLESS 协议 (含 Reality / Vision / WebSocket) ===
	case "vless":
		outbound.Type = "vless"
		opts := option.VLESSOutboundOptions{
			ServerOptions: serverOpts,
			UUID:          node.UUID,
			Flow:          node.Flow,
		}

		if node.TLS || node.Tls || node.RealityOpts != nil {
			opts.TLS = makeTLS()
		}

		if node.Network == "ws" || node.Network == "websocket" {
			headers := make(map[string]badoption.Listable[string])
			for k, v := range node.WSOpts.Headers {
				headers[k] = badoption.Listable[string]{v}
			}
			opts.Transport = &option.V2RayTransportOptions{
				Type: "ws",
				WebsocketOptions: option.V2RayWebsocketOptions{
					Path:    node.WSOpts.Path,
					Headers: headers,
				},
			}
		}
		outbound.Options = &opts

	// === 🚀 新增：Hysteria2 协议 ===
	case "hysteria2", "hy2":
		outbound.Type = "hysteria2"
		opts := option.Hysteria2OutboundOptions{
			ServerOptions: serverOpts,
			Password:      node.Password,
		}
		opts.TLS = makeTLS()
		outbound.Options = &opts

	case "vmess":
		outbound.Type = "vmess"
		cipher := node.Cipher
		if cipher == "" {
			cipher = "auto"
		}

		opts := option.VMessOutboundOptions{
			ServerOptions: serverOpts,
			UUID:          node.UUID,
			AlterId:       node.AlterId,
			Security:      cipher,
		}

		if node.Tls || node.TLS || node.SNI != "" {
			opts.TLS = makeTLS()
		}

		if node.Network == "ws" || node.Network == "websocket" {
			path := node.WSOpts.Path
			if path == "" {
				path = node.WSPath
			}
			if path == "" {
				path = "/"
			}

			host := ""
			if node.WSOpts.Headers != nil && node.WSOpts.Headers["Host"] != "" {
				host = node.WSOpts.Headers["Host"]
			} else if node.WSHeaders != nil && node.WSHeaders["Host"] != "" {
				host = node.WSHeaders["Host"]
			} else if node.Host != "" {
				host = node.Host
			}

			wsOpts := option.V2RayWebsocketOptions{Path: path}
			if host != "" {
				wsOpts.Headers = map[string]badoption.Listable[string]{"Host": {host}}
			}
			opts.Transport = &option.V2RayTransportOptions{Type: "ws", WebsocketOptions: wsOpts}
		} else if node.Network == "grpc" {
			opts.Transport = &option.V2RayTransportOptions{
				Type:        "grpc",
				GRPCOptions: option.V2RayGRPCOptions{ServiceName: node.WSOpts.Path},
			}
		}
		outbound.Options = &opts

	case "trojan":
		outbound.Type = "trojan"
		opts := option.TrojanOutboundOptions{
			ServerOptions: serverOpts,
			Password:      node.Password,
		}
		opts.TLS = makeTLS()
		outbound.Options = &opts

	case "ss", "shadowsocks":
		outbound.Type = "shadowsocks"
		opts := option.ShadowsocksOutboundOptions{
			ServerOptions: serverOpts,
			Method:        node.Method,
			Password:      node.Password,
		}
		outbound.Options = &opts

	case "http", "https":
		outbound.Type = "http"
		opts := option.HTTPOutboundOptions{ServerOptions: serverOpts}
		if node.Username != "" || node.Password != "" {
			opts.Username = node.Username
			opts.Password = node.Password
		}
		if node.Type == "https" || node.Tls || node.TLS || node.SNI != "" || node.Port == 443 {
			tlsOpt := makeTLS()
			if len(tlsOpt.ALPN) == 0 {
				tlsOpt.ALPN = []string{"h2", "http/1.1"}
			}
			opts.TLS = tlsOpt
		}
		outbound.Options = &opts

	default:
		return option.Options{}, fmt.Errorf("不支持的 sing-box 节点类型: %s", node.Type)
	}

	return option.Options{
		Log: &option.LogOptions{
			Disabled: true,    // 彻底禁用底层内核的常规运行日志
			Level:    "error", // 即使没被禁用，也只允许打印最高级别的崩溃报错
		},
		Outbounds: []option.Outbound{outbound},
	}, nil
}

func StartAnyTLSHttpServer() {
	server := &http.Server{Addr: "127.0.0.1:" + LocalHttpPort, Handler: &HTTPProxyHandler{}}
	server.ListenAndServe()
}
