//go:build android

package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"wing/pkg/common"
	"wing/pkg/stats"
	"wing/pkg/utils"
)

const (
	tunInboundTag               = "wing-tun"
	tunLocalSocksTag            = "wing-local-socks"
	tunLocalDNSTag              = "wing-local-dns"
	tunMTU                      = 1400
	tunStack                    = "gvisor"
	tunUDPTimeout               = 30 * time.Second
	androidVpnCmdStop           = 0
	androidVpnCmdStart          = 1
	androidVpnCmdNetworkChanged = 2
)

var (
	androidTunMu        sync.Mutex
	androidTunBox       *box.Box
	androidTunFd        int = -1
	androidNetResetting atomic.Bool
)

func StartAndroidTunListener() {
	utils.SafeGo("android tun unix listener", func() {
		l, err := net.Listen("unix", "@wing_vpn_fd")
		if err != nil {
			log.Printf("[Android TUN] Failed to listen on @wing_vpn_fd: %v", err)
			return
		}
		defer l.Close()
		log.Println("[Android TUN] Listening on abstract socket @wing_vpn_fd for Android VpnService...")

		for {
			conn, err := l.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				log.Printf("[Android TUN] Accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			utils.SafeGo("android vpn socket", func() {
				unixConn, ok := conn.(*net.UnixConn)
				if !ok {
					_ = conn.Close()
					return
				}
				handleVpnSocket(unixConn)
			})
		}
	})
}

func handleVpnSocket(conn *net.UnixConn) {
	defer conn.Close()
	acknowledge := func(ok bool, message string) {
		value := byte(0)
		if ok {
			value = 1
		}
		payload := append([]byte{value}, []byte(message)...)
		if _, err := conn.Write(payload); err != nil {
			log.Printf("[Android TUN] Failed to acknowledge VPN service: %v", err)
		}
	}

	buf := make([]byte, 32)
	oob := make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil || n == 0 {
		log.Printf("[Android TUN] ReadMsgUnix error: %v", err)
		return
	}
	command := buf[0]
	switch command {
	case androidVpnCmdStop:
		StopTun()
		acknowledge(true, "")
		log.Println("[Android TUN] Received stop command from Android VpnService")
		return
	case androidVpnCmdNetworkChanged:
		handleAndroidNetworkChanged()
		acknowledge(true, "")
		return
	case androidVpnCmdStart:
	default:
		acknowledge(false, fmt.Sprintf("未知 VPN 控制指令: %d", command))
		return
	}

	receivedFd := -1
	if oobn > 0 {
		cmsgs, parseErr := syscall.ParseSocketControlMessage(oob[:oobn])
		if parseErr != nil {
			log.Printf("[Android TUN] ParseSocketControlMessage error: %v", parseErr)
			acknowledge(false, "解析 VPN 文件描述符失败")
			return
		}
		for _, cmsg := range cmsgs {
			if cmsg.Header.Level == syscall.SOL_SOCKET && cmsg.Header.Type == syscall.SCM_RIGHTS {
				fds, fdsErr := syscall.ParseUnixRights(&cmsg)
				if fdsErr == nil && len(fds) > 0 {
					receivedFd = fds[0]
				}
			}
		}
	}
	if receivedFd < 0 {
		log.Printf("[Android TUN] Failed to receive valid FD from VpnService")
		acknowledge(false, "未收到 Android VPN 文件描述符")
		return
	}

	log.Printf("[Android TUN] Received VPN FileDescriptor: %d. Starting TUN engine...", receivedFd)

	androidTunMu.Lock()
	defer androidTunMu.Unlock()

	if androidTunBox != nil {
		_ = closeSingBoxInstance("android tun box", androidTunBox)
		androidTunBox = nil
		androidTunFd = -1
	} else if androidTunFd >= 0 && androidTunFd != receivedFd {
		_ = syscall.Close(androidTunFd)
	}
	androidTunFd = receivedFd

	if err := startAndroidTunEngineLocked(receivedFd); err != nil {
		log.Printf("[Android TUN] Start TUN engine error: %v", err)
		androidTunFd = -1
		acknowledge(false, err.Error())
		return
	}

	common.SetTunModeOn(true)
	proxyOn, tunOn, _ := common.GetNetworkState()
	_ = SaveLastNetworkMode(proxyOn, tunOn)
	stats.SyncTrafficSession(proxyOn, tunOn)
	acknowledge(true, "")
	log.Println("[Android TUN] Android Native VPN TUN is now active and routing traffic!")
}

func handleAndroidNetworkChanged() {
	if !androidNetResetting.CompareAndSwap(false, true) {
		return
	}
	utils.SafeGo("android network change reset", func() {
		defer androidNetResetting.Store(false)
		ResetDNSState()
		ResetNodeDoHState()
		ResetNodeIPChoices()

		activeNode, activeName, _ := common.GetActiveNodeSnapshot()
		if activeName == "" && activeNode.Server == "" {
			return
		}
		if err := SwitchNode(activeNode); err != nil {
			log.Printf("[Android TUN] 网络切换重建节点客户端失败: %v", err)
		} else {
			log.Println("[Android TUN] 网络切换完成，已重置连接池并重建当前节点客户端")
		}
	})
}

type androidPlatformInterface struct {
	fd       int
	onOpened func()
}

// androidDefaultInterfaceMonitor deliberately keeps no system routes. The
// Android VpnService owns route selection and excludes this application from
// its VPN, while sing-box only needs a non-nil monitor for its lifecycle and
// TUN adapter wiring.
type androidDefaultInterfaceMonitor struct {
	mu          sync.RWMutex
	myInterface string
}

func (m *androidDefaultInterfaceMonitor) Start() error { return nil }

func (m *androidDefaultInterfaceMonitor) Close() error { return nil }

func (m *androidDefaultInterfaceMonitor) DefaultInterface() *control.Interface { return nil }

func (m *androidDefaultInterfaceMonitor) OverrideAndroidVPN() bool { return false }

func (m *androidDefaultInterfaceMonitor) AndroidVPNEnabled() bool { return true }

func (m *androidDefaultInterfaceMonitor) RegisterCallback(callback singtun.DefaultInterfaceUpdateCallback) *list.Element[singtun.DefaultInterfaceUpdateCallback] {
	return nil
}

func (m *androidDefaultInterfaceMonitor) UnregisterCallback(element *list.Element[singtun.DefaultInterfaceUpdateCallback]) {
}

func (m *androidDefaultInterfaceMonitor) RegisterMyInterface(interfaceName string) {
	m.mu.Lock()
	m.myInterface = interfaceName
	m.mu.Unlock()
}

func (m *androidDefaultInterfaceMonitor) MyInterface() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.myInterface
}

func (p *androidPlatformInterface) Initialize(networkManager adapter.NetworkManager) error {
	return nil
}

func (p *androidPlatformInterface) UsePlatformAutoDetectInterfaceControl() bool {
	return false
}

func (p *androidPlatformInterface) AutoDetectInterfaceControl(fd int) error {
	return nil
}

func (p *androidPlatformInterface) UsePlatformInterface() bool {
	return true
}

func (p *androidPlatformInterface) OpenInterface(options *singtun.Options, platformOptions option.TunPlatformOptions) (singtun.Tun, error) {
	options.FileDescriptor = p.fd
	options.Name = "wing-tun"
	options.AutoRoute = false
	options.StrictRoute = false
	tunDev, err := singtun.New(*options)
	if err == nil && p.onOpened != nil {
		p.onOpened()
	}
	return tunDev, err
}

func (p *androidPlatformInterface) UsePlatformDefaultInterfaceMonitor() bool {
	return false
}

func (p *androidPlatformInterface) CreateDefaultInterfaceMonitor(logger logger.Logger) singtun.DefaultInterfaceMonitor {
	return &androidDefaultInterfaceMonitor{}
}

func (p *androidPlatformInterface) UsePlatformNetworkInterfaces() bool {
	return false
}

func (p *androidPlatformInterface) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return nil, nil
}

func (p *androidPlatformInterface) UnderNetworkExtension() bool {
	return false
}

func (p *androidPlatformInterface) NetworkExtensionIncludeAllNetworks() bool {
	return false
}

func (p *androidPlatformInterface) ClearDNSCache() {}

func (p *androidPlatformInterface) RequestPermissionForWIFIState() error {
	return nil
}

func (p *androidPlatformInterface) ReadWIFIState() adapter.WIFIState {
	return adapter.WIFIState{}
}

func (p *androidPlatformInterface) SystemCertificates() []string {
	return nil
}

func (p *androidPlatformInterface) UsePlatformConnectionOwnerFinder() bool {
	// A non-nil Android platform interface makes sing-box require a platform
	// process finder. Falling back to its built-in Android finder is unsafe
	// here because that finder dereferences a PackageManager which is only
	// created when no platform interface is present.
	return true
}

func (p *androidPlatformInterface) FindConnectionOwner(request *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	// The standalone VPN route does not use per-application rules. Return a
	// valid unknown owner so sing-box can continue matching network rules
	// without performing an unsupported package lookup.
	return &adapter.ConnectionOwner{UserId: -1}, nil
}

func (p *androidPlatformInterface) UsePlatformWIFIMonitor() bool {
	return false
}

func (p *androidPlatformInterface) UsePlatformNotification() bool {
	return false
}

func (p *androidPlatformInterface) SendNotification(notification *adapter.Notification) error {
	return nil
}

func startAndroidTunEngineLocked(fd int) (err error) {
	var fdOwnedByTun atomic.Bool
	closeUnusedFd := func() {
		if !fdOwnedByTun.Load() && fd >= 0 {
			_ = syscall.Close(fd)
		}
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			closeUnusedFd()
			utils.WriteCrashLog("android tun start", recovered)
			log.Printf("[Android TUN] Recovered core panic: %v\n%s", recovered, debug.Stack())
			err = fmt.Errorf("Android VPN 核心初始化异常: %v", recovered)
		}
	}()

	opts, err := buildAndroidTunBoxOptions()
	if err != nil {
		closeUnusedFd()
		return err
	}

	ctx := include.Context(context.Background())
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &androidPlatformInterface{
		fd: fd,
		onOpened: func() {
			fdOwnedByTun.Store(true)
		},
	})

	b, err := box.New(box.Options{
		Options: opts,
		Context: ctx,
	})
	if err != nil {
		closeUnusedFd()
		return fmt.Errorf("创建 sing-box TUN 实例失败: %w", err)
	}

	if err := startSingBoxInstance("android tun box", b); err != nil {
		closeUnusedFd()
		_ = closeSingBoxInstance("failed android tun box", b)
		return fmt.Errorf("启动 sing-box TUN 实例失败: %w", err)
	}

	androidTunBox = b
	return nil
}

func androidTunDNSStrategy() option.DomainStrategy {
	if GlobalSystemConfig.PreferIPv6 {
		return option.DomainStrategy(C.DomainStrategyPreferIPv6)
	}
	return option.DomainStrategy(C.DomainStrategyIPv4Only)
}

func buildAndroidTunBoxOptions() (option.Options, error) {
	tunAddress, err := netip.ParsePrefix("172.19.0.1/30")
	if err != nil {
		return option.Options{}, err
	}
	tunAddress6, err := netip.ParsePrefix("fdfe:dcba:9876::1/126")
	if err != nil {
		return option.Options{}, err
	}

	return option.Options{
		Log: &option.LogOptions{
			Disabled: true,
			Level:    "error",
		},
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{
						Type: C.DNSTypeUDP,
						Tag:  tunLocalDNSTag,
						Options: &option.RemoteDNSServerOptions{
							DNSServerAddressOptions: option.DNSServerAddressOptions{
								Server:     "127.0.0.2",
								ServerPort: uint16(localDNSListenPort()),
							},
						},
					},
				},
				Final: tunLocalDNSTag,
				DNSClientOptions: option.DNSClientOptions{
					Strategy: androidTunDNSStrategy(),
				},
			},
		},
		Inbounds: []option.Inbound{
			{
				Type: C.TypeTun,
				Tag:  tunInboundTag,
				Options: &option.TunInboundOptions{
					InterfaceName: "wing-tun",
					MTU:           tunMTU,
					Address:       []netip.Prefix{tunAddress, tunAddress6},
					AutoRoute:     false,
					StrictRoute:   false,
					UDPTimeout:    option.UDPTimeoutCompat(tunUDPTimeout),
					Stack:         tunStack,
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeSOCKS,
				Tag:  tunLocalSocksTag,
				Options: &option.SOCKSOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: 10810,
					},
					Version: "5",
				},
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Inbound: []string{tunInboundTag},
							Port:    []uint16{53},
						},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeHijackDNS,
						},
					},
				},
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Inbound: []string{tunInboundTag},
							Network: []string{N.NetworkICMP, N.NetworkUDP},
						},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeReject,
							RejectOptions: option.RejectActionOptions{
								Method: C.RuleActionRejectMethodDefault,
							},
						},
					},
				},
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Inbound: []string{tunInboundTag},
							Network: []string{N.NetworkTCP},
						},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeRoute,
							RouteOptions: option.RouteActionOptions{
								Outbound: tunLocalSocksTag,
							},
						},
					},
				},
			},
			Final: tunLocalSocksTag,
		},
	}, nil
}

func ToggleTunMode() string {
	return SetTunMode(!common.GetTunModeOn())
}

func SetTunMode(enabled bool) string {
	if !enabled {
		StopTun()
	}
	// Starting the Android TUN requires VpnService user consent. The Flutter
	// bridge starts the service, which passes its TUN FD to this process.
	return ""
}

func RestartTun(nodeServer, nodeIP string) error {
	return nil
}

func StopTun() {
	androidTunMu.Lock()
	defer androidTunMu.Unlock()

	hadBox := androidTunBox != nil
	if hadBox {
		_ = closeSingBoxInstance("android tun box", androidTunBox)
		androidTunBox = nil
	}
	if androidTunFd >= 0 && !hadBox {
		_ = syscall.Close(androidTunFd)
	}
	androidTunFd = -1
	common.SetTunModeOn(false)
	proxyOn, tunOn, _ := common.GetNetworkState()
	_ = SaveLastNetworkMode(proxyOn, tunOn)
	stats.SyncTrafficSession(proxyOn, tunOn)
	debug.FreeOSMemory()
}

func prepareNodeBypassRouteForSwitch(nodeIP string) func() {
	return func() {}
}
