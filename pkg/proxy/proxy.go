package proxy

import (
	"high-mae/pkg/common"

	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"high-mae/protocol"

	sing_anytls "github.com/anytls/sing-anytls"
	anytls_util "github.com/anytls/sing-anytls/util"
	utls "github.com/refraction-networking/utls"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/metadata"
)

// 全局单例的 Box，用于在切换节点时平滑重启/关闭
var currentBox *box.Box
var cancelAnyTLS context.CancelFunc

func SwitchNode(node protocol.Node) {
	if common.MCurrentNode != nil {
		common.MCurrentNode.SetTitle(fmt.Sprintf("📍 当前节点: [%s] %s", strings.ToUpper(node.Type), node.Name))
	}

	common.ClientMu.Lock()
	defer common.ClientMu.Unlock()

	// 🚀 修复 1：使用智能解析函数，防止给原本就是 IP 的地址做二次 DNS 污染解析
	newIP := resolveDirect(node.Server)

	common.GlobalNodeServer = node.Server
	common.GlobalNodeIP = newIP
	common.ActiveNodeName = node.Name

	// 🚀 修复 2：彻底清理上一个节点的残留资源（无论是 Sing-box 还是 AnyTLS）
	if currentBox != nil {
		currentBox.Close()
		currentBox = nil
	}
	if cancelAnyTLS != nil {
		cancelAnyTLS()
		cancelAnyTLS = nil
	}
	if currentMieru != nil {
		currentMieru.Close()
		currentMieru = nil
	}
	if closer, ok := common.ActiveClient.(io.Closer); ok {
		closer.Close()
	}
	common.ActiveClient = nil

	// ==========================================
	// 专门处理 AnyTLS 节点
	// ==========================================
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

		ctx, cancel := context.WithCancel(context.Background())
		cancelAnyTLS = cancel

		newClient, err := sing_anytls.NewClient(ctx, sing_anytls.ClientConfig{
			Password:       node.Password,
			MinIdleSession: 1,
			DialOut:        anytls_util.DialOutFunc(dialOut),
			Logger:         dummyLogger{},
		})
		if err != nil {
			log.Printf("AnyTLS Client 创建失败: %v", err)
			cancel()
			return
		}
		common.ActiveClient = newClient
		restartTunAfterNodeSwitch()
		return
	}

	if node.Type == "mieru" {
		newClient, err := newMieruClientAdapter(node)
		if err != nil {
			log.Printf("Mieru Client 创建失败: %v", err)
			return
		}
		currentMieru = newClient
		common.ActiveClient = newClient
		restartTunAfterNodeSwitch()
		return
	}

	if (node.Type == "socks5" || node.Type == "socks") && (node.TLS || node.Tls) {
		adapter := &Socks5TLSAdapter{
			Server:         node.Server,
			ResolvedIP:     newIP,
			Port:           node.Port,
			Username:       node.Username,
			Password:       node.Password,
			SNI:            node.SNI,
			SkipCertVerify: node.SkipCertVerify,
		}
		common.ActiveClient = adapter
		restartTunAfterNodeSwitch()
		return
	}

	log.Printf("初始化通用代理引擎 [%s] 节点: %s", node.Type, node.Name)
	opts, err := buildSingBoxOptions(node, newIP)
	if err != nil {
		log.Printf("构建 Sing-Box 配置失败: %v", err)
		return
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
	common.ActiveClient = &SingBoxAdapter{Instance: b}
	restartTunAfterNodeSwitch()
}

func restartTunAfterNodeSwitch() {
	if !common.IsTunModeOn {
		return
	}
	if err := RestartSingBoxTun(); err != nil {
		log.Printf("重启 sing-box TUN 失败: %v", err)
	}
}

func buildSingBoxOptions(node protocol.Node, resolvedIP string) (option.Options, error) {
	sni := node.SNI
	if sni == "" {
		sni = node.ServerName
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
		fingerprint := node.ClientFingerprint
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		tls.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fingerprint,
		}
		if node.RealityOpts != nil && node.RealityOpts.PublicKey != "" {
			tls.Reality = &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: node.RealityOpts.PublicKey,
				ShortID:   node.RealityOpts.ShortID,
			}
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
			cc = "bbr"
		}
		udpMode := node.UDPRelayMode
		if udpMode == "" {
			udpMode = "native"
		}
		opts := option.TUICOutboundOptions{
			ServerOptions:     serverOpts,
			UUID:              node.UUID,
			Password:          node.Password,
			CongestionControl: cc,
			UDPRelayMode:      udpMode,
			ZeroRTTHandshake:  node.ReduceRTT,
		}
		opts.TLS = makeTLS()
		if len(opts.TLS.ALPN) == 0 {
			opts.TLS.ALPN = []string{"h3"}
		}
		outbound.Options = &opts
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
		} else if node.Network == "grpc" {
			serviceName := node.GrpcOpts["grpc-service-name"]
			if serviceName == "" && node.WSOpts.Path != "" {
				serviceName = node.WSOpts.Path
			}
			opts.Transport = &option.V2RayTransportOptions{
				Type: "grpc",
				GRPCOptions: option.V2RayGRPCOptions{
					ServiceName: serviceName,
				},
			}
		}
		outbound.Options = &opts
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
		if node.TLS || node.Tls {
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
			extractHost := func(m map[string]string) string {
				for k, v := range m {
					if strings.ToLower(k) == "host" {
						return v
					}
				}
				return ""
			}
			if h := extractHost(node.WSOpts.Headers); h != "" {
				host = h
			} else if h := extractHost(node.WSHeaders); h != "" {
				host = h
			} else if node.Host != "" {
				host = node.Host
			}
			wsOpts := option.V2RayWebsocketOptions{
				Path: path,
			}
			if host != "" {
				wsOpts.Headers = map[string]badoption.Listable[string]{
					"Host": {host},
				}
			}
			opts.Transport = &option.V2RayTransportOptions{
				Type:             "ws",
				WebsocketOptions: wsOpts,
			}
		} else if node.Network == "grpc" {
			serviceName := node.GrpcOpts["grpc-service-name"]
			if serviceName == "" && node.WSOpts.Path != "" {
				serviceName = node.WSOpts.Path
			}
			opts.Transport = &option.V2RayTransportOptions{
				Type: "grpc",
				GRPCOptions: option.V2RayGRPCOptions{
					ServiceName: serviceName,
				},
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
		method := node.Method
		if method == "" {
			method = node.Cipher
		}
		opts := option.ShadowsocksOutboundOptions{
			ServerOptions: serverOpts,
			Method:        method,
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
	case "socks", "socks5":
		outbound.Type = "socks"
		opts := option.SOCKSOutboundOptions{
			ServerOptions: serverOpts,
		}
		if node.Username != "" || node.Password != "" {
			opts.Username = node.Username
			opts.Password = node.Password
		}
		outbound.Options = &opts
	default:
		return option.Options{}, fmt.Errorf("不支持的 sing-box 节点类型: %s", node.Type)
	}
	return option.Options{
		Log: &option.LogOptions{
			Disabled: true,
			Level:    "error",
		},
		Outbounds: []option.Outbound{outbound},
	}, nil
}

func StartAnyTLSHttpServer() {
	server := &http.Server{Addr: "127.0.0.1:" + common.LocalHttpPort, Handler: &HTTPProxyHandler{}}
	server.ListenAndServe()
}

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

// Helpers are provided by other files in the proxy package (e.g. latency.go)
