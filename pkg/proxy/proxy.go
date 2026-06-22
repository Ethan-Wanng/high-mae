package proxy

import (
	"wing/pkg/common"
	"wing/pkg/storage"
	"wing/pkg/utils"

	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"wing/protocol"

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

var (
	globalRegistryContext context.Context
	globalRegistryOnce    sync.Once
	networkTransitionMu   sync.Mutex
	localHTTPServerMu     sync.Mutex
	localHTTPServer       *http.Server
)

func getRegistryContext() context.Context {
	globalRegistryOnce.Do(func() {
		globalRegistryContext = include.Context(context.Background())
	})
	return globalRegistryContext
}

func RunNetworkTransition(fn func()) {
	networkTransitionMu.Lock()
	defer networkTransitionMu.Unlock()
	fn()
}

func SwitchNode(node protocol.Node) {
	networkTransitionMu.Lock()
	defer networkTransitionMu.Unlock()

	newIP := ResolveNodeServer(node)
	cleanupBypass := prepareNodeBypassRouteForSwitch(newIP)
	newClient, err := CreateNodeClientWithResolvedIP(node, newIP)
	if err != nil {
		cleanupBypass()
		log.Printf("节点 %s 初始化失败，保留当前可用节点: %v", node.Name, err)
		return
	}

	common.ClientMu.Lock()
	oldClient := common.ActiveClient
	common.GlobalNodeServer = node.Server
	common.GlobalNodeIP = newIP
	common.ActiveNode = node
	common.ActiveNodeName = node.Name
	common.ActiveClient = newClient
	common.ClientMu.Unlock()

	if node.Name != "" {
		_ = storage.Write("last_active_node_name", []byte(node.Name))
	}
	if common.MCurrentNode != nil {
		common.MCurrentNode.SetTitle(fmt.Sprintf("📍 当前节点: [%s] %s", strings.ToUpper(node.Type), node.Name))
	}

	ClearNodeClientsCache()
	if currentBox != nil {
		if err := closeSingBoxInstance("active proxy box", currentBox); err != nil {
			log.Printf("关闭当前代理引擎失败: %v", err)
		}
		currentBox = nil
	}
	if cancelAnyTLS != nil {
		cancelAnyTLS()
		cancelAnyTLS = nil
	}
	if currentMieru != nil {
		if err := closeMieruRuntime("current mieru client", currentMieru); err != nil {
			log.Printf("关闭 Mieru 客户端失败: %v", err)
		}
		currentMieru = nil
	}
	_ = closeGenericClient("old active client", oldClient)
	restartTunAfterNodeSwitch()
}

func restartTunAfterNodeSwitch() {
	if !common.IsTunModeOn {
		return
	}
	nodeServer := common.GlobalNodeServer
	nodeIP := common.GlobalNodeIP
	if err := RestartTun(nodeServer, nodeIP); err != nil {
		log.Printf("重启 TUN 失败: %v", err)
		common.IsTunModeOn = false
		if common.MToggleTun != nil {
			common.MToggleTun.SetTitle("🔌 隧道连接: [已关闭]")
		}
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
		if node.Type != "tuic" && node.Type != "hysteria2" && node.Type != "hy2" && node.Type != "naive" {
			tls.UTLS = &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: fingerprint,
			}
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

	dialerOpts := option.DialerOptions{}

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
			DialerOptions:     dialerOpts,
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
			DialerOptions: dialerOpts,
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
			DialerOptions: dialerOpts,
		}
		if node.Obfs != "" {
			opts.Obfs = &option.Hysteria2Obfs{
				Type:     node.Obfs,
				Password: node.ObfsPassword,
			}
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
			DialerOptions: dialerOpts,
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
			DialerOptions: dialerOpts,
		}
		opts.TLS = makeTLS()
		outbound.Options = &opts
	case "naive":
		outbound.Type = "naive"
		opts := option.NaiveOutboundOptions{
			ServerOptions:         serverOpts,
			DialerOptions:         dialerOpts,
			Username:              node.Username,
			Password:              node.Password,
			InsecureConcurrency:   node.InsecureConcurrency,
			QUIC:                  node.QUIC,
			QUICCongestionControl: normalizeNaiveQUICCongestion(node.QUICCongestion),
		}
		if len(node.ExtraHeaders) > 0 {
			headers := make(badoption.HTTPHeader)
			for k, v := range node.ExtraHeaders {
				headers[k] = badoption.Listable[string]{v}
			}
			opts.ExtraHeaders = headers
		}
		opts.TLS = &option.OutboundTLSOptions{
			Enabled: true,
		}
		if !node.DisableSNI {
			opts.TLS.ServerName = sni
		}
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
			DialerOptions: dialerOpts,
		}
		outbound.Options = &opts
	case "http", "https":
		outbound.Type = "http"
		opts := option.HTTPOutboundOptions{
			ServerOptions: serverOpts,
			DialerOptions: dialerOpts,
		}
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
			DialerOptions: dialerOpts,
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

func normalizeNaiveQUICCongestion(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "default":
		return ""
	case "bbr", "tbbr":
		return "bbr"
	case "bbrv2", "bbr2", "b2on":
		return "bbr2"
	case "cubic", "qbic":
		return "cubic"
	case "reno":
		return "reno"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func StartAnyTLSHttpServer() {
	if err := launchLocalHTTPProxyServer(); err != nil {
		log.Printf("本地 HTTP 代理启动失败: %v", err)
	}
	if err := launchLocalSOCKSProxyServer(); err != nil {
		log.Printf("本地 SOCKS5 代理启动失败: %v", err)
	}
}

func localHTTPProxyListenAddr() string {
	return "127.0.0.1:" + common.LocalHttpPort
}

func RestartLocalHTTPProxyServer() error {
	shutdownLocalHTTPProxyServer()
	shutdownLocalSOCKSProxyServer()
	if err := launchLocalHTTPProxyServer(); err != nil {
		return err
	}
	return launchLocalSOCKSProxyServer()
}

func launchLocalHTTPProxyServer() error {
	addr := localHTTPProxyListenAddr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler:           &HTTPProxyHandler{},
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	localHTTPServerMu.Lock()
	localHTTPServer = server
	localHTTPServerMu.Unlock()

	log.Printf("HTTP 代理监听: %s", addr)
	utils.SafeGo("local http proxy listener", func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP 代理监听异常: %v", err)
		}
		localHTTPServerMu.Lock()
		if localHTTPServer == server {
			localHTTPServer = nil
		}
		localHTTPServerMu.Unlock()
	})
	return nil
}

func shutdownLocalHTTPProxyServer() {
	localHTTPServerMu.Lock()
	server := localHTTPServer
	localHTTPServer = nil
	localHTTPServerMu.Unlock()
	if server == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		server.Close()
	}
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

func (s *SingBoxAdapter) Close() error {
	if s != nil && s.Instance != nil {
		return closeSingBoxInstance("sing-box adapter", s.Instance)
	}
	return nil
}

// Helpers are provided by other files in the proxy package (e.g. latency.go)

var (
	nodeClientsMu sync.Mutex
	nodeClients   = make(map[string]common.GenericClient)
)

type anytlsCloserAdapter struct {
	common.GenericClient
	cancel context.CancelFunc
}

func (a *anytlsCloserAdapter) Close() error {
	a.cancel()
	return closeGenericClient("anytls adapter", a.GenericClient)
}

func closeSingBoxInstance(name string, b *box.Box) (err error) {
	if b == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			utils.WriteCrashLog(name, r)
			err = fmt.Errorf("%s close panic: %v", name, r)
		}
	}()
	return b.Close()
}

func startSingBoxInstance(name string, b *box.Box) (err error) {
	if b == nil {
		return fmt.Errorf("%s is nil", name)
	}
	defer func() {
		if r := recover(); r != nil {
			utils.WriteCrashLog(name, r)
			err = fmt.Errorf("%s start panic: %v", name, r)
		}
	}()
	return b.Start()
}

func closeGenericClient(name string, client common.GenericClient) (err error) {
	closer, ok := client.(io.Closer)
	if !ok || closer == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			utils.WriteCrashLog(name, r)
			err = fmt.Errorf("%s close panic: %v", name, r)
		}
	}()
	return closer.Close()
}

func closeMieruRuntime(name string, client mieruRuntime) (err error) {
	if client == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			utils.WriteCrashLog(name, r)
			err = fmt.Errorf("%s close panic: %v", name, r)
		}
	}()
	return client.Close()
}

func ClearNodeClientsCache() {
	nodeClientsMu.Lock()
	defer nodeClientsMu.Unlock()
	for name, client := range nodeClients {
		if err := closeGenericClient("cached route client "+name, client); err != nil {
			log.Printf("关闭规则缓存节点 %s 失败: %v", name, err)
		}
		delete(nodeClients, name)
	}
}

func CreateNodeClient(node protocol.Node) (common.GenericClient, error) {
	newIP := ResolveNodeServer(node)
	return CreateNodeClientWithResolvedIP(node, newIP)
}

func CreateNodeClientWithResolvedIP(node protocol.Node, newIP string) (common.GenericClient, error) {
	var realIP string
	if common.IsTunModeOn {
		realIP = common.RealLocalIPBeforeTun
		if realIP == "" {
			realIP = utils.GetRealLocalIP()
		}
	}

	if node.Type == "anytls" {
		var localAddr *net.TCPAddr
		if realIP != "" && realIP != common.TunIP {
			localAddr = &net.TCPAddr{IP: net.ParseIP(realIP), Port: 0}
		}
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

		ctx, cancel := context.WithCancel(context.Background())
		newClient, err := sing_anytls.NewClient(ctx, sing_anytls.ClientConfig{
			Password:       node.Password,
			MinIdleSession: 1,
			DialOut:        anytls_util.DialOutFunc(dialOut),
			Logger:         dummyLogger{},
		})
		if err != nil {
			cancel()
			return nil, err
		}
		return &anytlsCloserAdapter{GenericClient: newClient, cancel: cancel}, nil
	}

	if node.Type == "mieru" {
		newClient, err := newMieruSocks5Adapter(node, false)
		if err != nil {
			return nil, err
		}
		return newClient, nil
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
			LocalIP:        realIP,
		}
		return adapter, nil
	}

	opts, err := buildSingBoxOptions(node, newIP)
	if err != nil {
		return nil, err
	}

	b, err := box.New(box.Options{
		Options: opts,
		Context: getRegistryContext(),
	})
	if err != nil {
		return nil, err
	}
	if err := startSingBoxInstance("node client", b); err != nil {
		if closeErr := closeSingBoxInstance("failed node client", b); closeErr != nil {
			log.Printf("启动失败后关闭节点代理引擎失败: %v", closeErr)
		}
		return nil, err
	}
	return &SingBoxAdapter{Instance: b}, nil
}

func GetNodeClient(node protocol.Node) (common.GenericClient, error) {
	nodeClientsMu.Lock()
	defer nodeClientsMu.Unlock()

	if client, exists := nodeClients[node.Name]; exists {
		return client, nil
	}

	client, err := CreateNodeClient(node)
	if err != nil {
		return nil, err
	}
	nodeClients[node.Name] = client
	return client, nil
}

func GetNodeForRoute(action string) (protocol.Node, bool) {
	action = strings.TrimSpace(action)
	if action == "" {
		return protocol.Node{}, false
	}
	for _, n := range common.AllNodes {
		if strings.EqualFold(n.Name, action) {
			return n, true
		}
	}
	for _, n := range common.AllNodes {
		if strings.EqualFold(n.Group, action) {
			return n, true
		}
	}
	return protocol.Node{}, false
}
