//go:build android

package proxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"wing/pkg/common"
	"wing/pkg/utils"
)

const (
	tunInboundTag    = "wing-tun"
	tunLocalSocksTag = "wing-local-socks"
	tunLocalDNSTag   = "wing-local-dns"
	tunMTU           = 1500
	tunStack         = "system"
	tunUDPTimeout    = 30 * time.Second
)

var (
	androidTunMu  sync.Mutex
	androidTunBox *box.Box
	androidTunFd  int = -1
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
				log.Printf("[Android TUN] Accept error: %v", err)
				return
			}
			go handleVpnSocket(conn.(*net.UnixConn))
		}
	})
}

func handleVpnSocket(conn *net.UnixConn) {
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		log.Printf("[Android TUN] SyscallConn error: %v", err)
		return
	}

	var receivedFd int = -1
	err = rawConn.Control(func(fd uintptr) {
		buf := make([]byte, 32)
		oob := make([]byte, syscall.CmsgSpace(4))
		n, oobn, _, _, recvErr := syscall.Recvmsg(int(fd), buf, oob, 0)
		if recvErr != nil {
			log.Printf("[Android TUN] Recvmsg error: %v", recvErr)
			return
		}
		if n > 0 && oobn > 0 {
			cmsgs, parseErr := syscall.ParseSocketControlMessage(oob[:oobn])
			if parseErr != nil {
				log.Printf("[Android TUN] ParseSocketControlMessage error: %v", parseErr)
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
	})

	if err != nil || receivedFd < 0 {
		log.Printf("[Android TUN] Failed to receive valid FD from VpnService")
		return
	}

	log.Printf("[Android TUN] Received VPN FileDescriptor: %d. Starting TUN engine...", receivedFd)

	androidTunMu.Lock()
	defer androidTunMu.Unlock()

	if androidTunBox != nil {
		_ = androidTunBox.Close()
		androidTunBox = nil
	}
	if androidTunFd >= 0 && androidTunFd != receivedFd {
		_ = syscall.Close(androidTunFd)
	}
	androidTunFd = receivedFd

	if err := startAndroidTunEngineLocked(receivedFd); err != nil {
		log.Printf("[Android TUN] Start TUN engine error: %v", err)
		_ = syscall.Close(receivedFd)
		androidTunFd = -1
		return
	}

	common.SetTunModeOn(true)
	log.Println("[Android TUN] Android Native VPN TUN is now active and routing traffic!")
}

type androidPlatformInterface struct {
	fd int
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
	return singtun.New(*options)
}

func (p *androidPlatformInterface) UsePlatformDefaultInterfaceMonitor() bool {
	return false
}

func (p *androidPlatformInterface) CreateDefaultInterfaceMonitor(logger logger.Logger) singtun.DefaultInterfaceMonitor {
	return nil
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
	return false
}

func (p *androidPlatformInterface) FindConnectionOwner(request *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, nil
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

func startAndroidTunEngineLocked(fd int) error {
	opts, err := buildAndroidTunBoxOptions()
	if err != nil {
		return err
	}

	ctx := include.Context(context.Background())
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, &androidPlatformInterface{fd: fd})

	b, err := box.New(box.Options{
		Options: opts,
		Context: ctx,
	})
	if err != nil {
		return fmt.Errorf("创建 sing-box TUN 实例失败: %w", err)
	}

	if err := b.Start(); err != nil {
		_ = b.Close()
		return fmt.Errorf("启动 sing-box TUN 实例失败: %w", err)
	}

	androidTunBox = b
	return nil
}

func buildAndroidTunBoxOptions() (option.Options, error) {
	tunAddress, err := netip.ParsePrefix("172.19.0.1/30")
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
								ServerPort: 53,
							},
						},
					},
				},
				Final: tunLocalDNSTag,
			},
		},
		Inbounds: []option.Inbound{
			{
				Type: C.TypeTun,
				Tag:  tunInboundTag,
				Options: &option.TunInboundOptions{
					InterfaceName: "wing-tun",
					MTU:           tunMTU,
					Address:       []netip.Prefix{tunAddress},
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
							Network: []string{N.NetworkICMP},
						},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeReject,
						},
					},
				},
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Inbound: []string{tunInboundTag},
							Network: []string{N.NetworkTCP, N.NetworkUDP},
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
	return ""
}

func SetTunMode(enabled bool) string {
	if !enabled {
		StopTun()
	}
	return ""
}

func RestartTun(nodeServer, nodeIP string) error {
	return nil
}

func StopTun() {
	androidTunMu.Lock()
	defer androidTunMu.Unlock()

	if androidTunBox != nil {
		_ = androidTunBox.Close()
		androidTunBox = nil
	}
	if androidTunFd >= 0 {
		_ = syscall.Close(androidTunFd)
		androidTunFd = -1
	}
	common.SetTunModeOn(false)
}

func prepareNodeBypassRouteForSwitch(nodeIP string) func() {
	return func() {}
}
