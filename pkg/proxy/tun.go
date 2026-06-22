package proxy

import (
	"fmt"
	"log"
	"net/netip"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"wing/pkg/common"
	"wing/pkg/utils"
)

const (
	TunIP               = common.TunIP
	tunInterfaceName    = "AnyTLS-TUN"
	tunInboundTag       = "wing-tun"
	tunLocalSocksTag    = "wing-local-socks"
	tunLocalDNSTag      = "wing-local-dns"
	tunMTU              = 1400
	tunStack            = "system"
	tunUDPTimeout       = 30 * time.Second
	legacyTunGateway    = "10.0.0.1"
	internalTunGateway  = "10.0.0.3"
	tunInterfaceAddress = TunIP + "/24"
)

var (
	tunMu           sync.Mutex
	tunBox          *box.Box
	tunWatchStop    chan struct{}
	tunWatchDone    chan struct{}
	tunGateway      string
	tunRealLocalIP  string
	tunRoutedNodeIP string
)

// ToggleTunMode 切换 TUN 模式的开/关状态，返回需要展示给用户的消息（空串表示成功）
func ToggleTunMode() string {
	networkTransitionMu.Lock()
	defer networkTransitionMu.Unlock()

	tunMu.Lock()
	defer tunMu.Unlock()

	if common.IsTunModeOn {
		stopTunWatchdogLocked()
		stopTunLocked()
		common.IsTunModeOn = false
		common.RealLocalIPBeforeTun = "" // 清除缓存，下次开启时重新获取
		if common.MToggleTun != nil {
			common.MToggleTun.SetTitle("🔌 隧道连接: [已关闭]")
		}
		if common.RefreshTrayIcon != nil {
			common.RefreshTrayIcon()
		}
		log.Println("TUN 模式已关闭（销毁虚拟网卡，删除路由）")
		return ""
	}

	if !utils.IsAdmin() {
		return "使用虚拟网卡(TUN)需要管理员权限！请以管理员身份运行。"
	}

	nodeIP := common.GlobalNodeIP
	if err := startTunLocked(nodeIP); err != nil {
		return fmt.Sprintf("启动 TUN 失败: %v", err)
	}

	common.IsTunModeOn = true
	startTunWatchdogLocked()
	if common.MToggleTun != nil {
		common.MToggleTun.SetTitle("🟢 隧道连接: [已开启]")
	}
	if common.RefreshTrayIcon != nil {
		common.RefreshTrayIcon()
	}
	log.Println("TUN 模式已开启（内置 sing-box TUN，自动路由）")
	return ""
}

// RestartTun 重启 TUN（在切换节点后由 proxy.go 调用）
func RestartTun(nodeServer, nodeIP string) error {
	tunMu.Lock()
	defer tunMu.Unlock()

	if !common.IsTunModeOn {
		return nil
	}

	stopTunWatchdogLocked()
	stopTunLocked()
	if err := startTunLocked(nodeIP); err != nil {
		common.IsTunModeOn = false
		if common.MToggleTun != nil {
			common.MToggleTun.SetTitle("🔌 隧道连接: [已关闭]")
		}
		if common.RefreshTrayIcon != nil {
			common.RefreshTrayIcon()
		}
		return err
	}
	startTunWatchdogLocked()
	return nil
}

// StopTun 停止 TUN（程序退出时由 main.go 调用）
func StopTun() {
	tunMu.Lock()
	defer tunMu.Unlock()

	if common.IsTunModeOn {
		stopTunWatchdogLocked()
		stopTunLocked()
	}
}

// =====================================================
// 内部实现
// =====================================================

// stopTunLocked 关闭正在运行的内置 TUN 实例（调用者必须持有 tunMu）
func stopTunLocked() {
	if tunBox != nil {
		if err := closeTunBox(tunBox); err != nil {
			log.Printf("关闭 TUN 实例失败: %v", err)
		}
		tunBox = nil
	}

	cleanupLegacyTunRoutesLocked()
	routedNodeIP := tunRoutedNodeIP
	if routedNodeIP != "" {
		utils.RunHiddenCommand("route", "delete", routedNodeIP, "mask", "255.255.255.255")
	}
	tunGateway = ""
	tunRealLocalIP = ""
	tunRoutedNodeIP = ""
	releaseRuntimeMemory()
	log.Println("旧 TUN 实例已关闭")
}

func prepareNodeBypassRouteForSwitch(nodeIP string) func() {
	nodeIP = strings.TrimSpace(nodeIP)
	if _, ok := tunNodeRoutePrefix(nodeIP); !ok {
		return func() {}
	}

	tunMu.Lock()
	defer tunMu.Unlock()
	if !common.IsTunModeOn || tunGateway == "" || nodeIP == tunRoutedNodeIP {
		return func() {}
	}

	utils.RunHiddenCommand("route", "delete", nodeIP, "mask", "255.255.255.255")
	utils.RunHiddenCommand("route", "add", nodeIP, "mask", "255.255.255.255", tunGateway, "metric", "1")
	return func() {
		tunMu.Lock()
		defer tunMu.Unlock()
		if tunRoutedNodeIP != nodeIP {
			utils.RunHiddenCommand("route", "delete", nodeIP, "mask", "255.255.255.255")
		}
	}
}

// startTunLocked 启动一个全新的内置 TUN 实例（调用者必须持有 tunMu）
func startTunLocked(nodeIP string) error {
	realGateway := utils.GetDefaultGateway()
	if realGateway == "" {
		return fmt.Errorf("无法识别系统的默认网关")
	}

	common.RealLocalIPBeforeTun = utils.GetRealLocalIP()
	tunGateway = realGateway
	tunRealLocalIP = common.RealLocalIPBeforeTun

	cleanupLegacyTunRoutesLocked()
	if tunRoutedNodeIP != "" {
		utils.RunHiddenCommand("route", "delete", tunRoutedNodeIP, "mask", "255.255.255.255")
		tunRoutedNodeIP = ""
	}

	nodeIP = strings.TrimSpace(nodeIP)
	if _, ok := tunNodeRoutePrefix(nodeIP); ok {
		utils.RunHiddenCommand("route", "delete", nodeIP, "mask", "255.255.255.255")
		utils.RunHiddenCommand("route", "add", nodeIP, "mask", "255.255.255.255", realGateway, "metric", "1")
		tunRoutedNodeIP = nodeIP
	}

	opts, err := buildTunBoxOptions(nodeIP)
	if err != nil {
		cleanupStartedTunNodeRouteLocked()
		return err
	}
	b, err := box.New(box.Options{
		Options: opts,
		Context: getRegistryContext(),
	})
	if err != nil {
		cleanupStartedTunNodeRouteLocked()
		return fmt.Errorf("创建内置 TUN 引擎失败: %w", err)
	}
	if err := startTunBox(b); err != nil {
		if closeErr := closeTunBox(b); closeErr != nil {
			log.Printf("启动失败后关闭 TUN 实例失败: %v", closeErr)
		}
		cleanupStartedTunNodeRouteLocked()
		return fmt.Errorf("启动内置 TUN 引擎失败: %w", err)
	}

	tunBox = b
	releaseRuntimeMemory()
	return nil
}

func startTunBox(b *box.Box) (err error) {
	defer func() {
		if r := recover(); r != nil {
			utils.WriteCrashLog("tun start", r)
			err = fmt.Errorf("TUN 引擎启动时发生内部异常: %v", r)
		}
	}()
	return b.Start()
}

func closeTunBox(b *box.Box) (err error) {
	if b == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			utils.WriteCrashLog("tun close", r)
			err = fmt.Errorf("TUN 引擎关闭时发生内部异常: %v", r)
		}
	}()
	return b.Close()
}

func buildTunBoxOptions(nodeIP string) (option.Options, error) {
	localSocksPort, err := parseTunLocalSocksPort(common.LocalSocksPort)
	if err != nil {
		return option.Options{}, err
	}
	tunAddress, err := netip.ParsePrefix(tunInterfaceAddress)
	if err != nil {
		return option.Options{}, fmt.Errorf("解析 TUN 地址失败: %w", err)
	}

	routeExcludeAddress := make([]netip.Prefix, 0, 1)
	if prefix, ok := tunNodeRoutePrefix(nodeIP); ok {
		routeExcludeAddress = append(routeExcludeAddress, prefix)
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
				DNSClientOptions: option.DNSClientOptions{
					Strategy: tunDNSStrategy(),
				},
			},
		},
		Inbounds: []option.Inbound{
			{
				Type: C.TypeTun,
				Tag:  tunInboundTag,
				Options: &option.TunInboundOptions{
					InterfaceName:       tunInterfaceName,
					MTU:                 tunMTU,
					Address:             []netip.Prefix{tunAddress},
					AutoRoute:           true,
					StrictRoute:         true,
					RouteExcludeAddress: routeExcludeAddress,
					UDPTimeout:          option.UDPTimeoutCompat(tunUDPTimeout),
					Stack:               tunStack,
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
						ServerPort: localSocksPort,
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
			Final:               tunLocalSocksTag,
			AutoDetectInterface: true,
		},
	}, nil
}

func parseTunLocalSocksPort(value string) (uint16, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("本地 SOCKS 端口无效: %q", value)
	}
	return uint16(port), nil
}

func tunNodeRoutePrefix(nodeIP string) (netip.Prefix, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(nodeIP))
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func cleanupStartedTunNodeRouteLocked() {
	if tunRoutedNodeIP == "" {
		return
	}
	utils.RunHiddenCommand("route", "delete", tunRoutedNodeIP, "mask", "255.255.255.255")
	tunRoutedNodeIP = ""
}

func cleanupLegacyTunRoutesLocked() {
	utils.RunHiddenCommand("route", "delete", "0.0.0.0", "mask", "0.0.0.0", TunIP)
	utils.RunHiddenCommand("route", "delete", "0.0.0.0", "mask", "0.0.0.0", legacyTunGateway)
	utils.RunHiddenCommand("route", "delete", "0.0.0.0", "mask", "0.0.0.0", internalTunGateway)
}

func startTunWatchdogLocked() {
	if tunWatchStop != nil {
		return
	}
	tunWatchStop = make(chan struct{})
	tunWatchDone = make(chan struct{})
	stopCh := tunWatchStop
	doneCh := tunWatchDone
	utils.SafeGo("tun watchdog", func() {
		defer close(doneCh)
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				reconcileTunRoute()
			case <-stopCh:
				return
			}
		}
	})
}

func stopTunWatchdogLocked() {
	if tunWatchStop == nil {
		return
	}
	stopCh := tunWatchStop
	doneCh := tunWatchDone
	tunWatchStop = nil
	tunWatchDone = nil
	close(stopCh)
	tunMu.Unlock()
	<-doneCh
	tunMu.Lock()
}

func reconcileTunRoute() {
	common.ClientMu.RLock()
	tunOn := common.IsTunModeOn
	activeNode := common.ActiveNode
	currentNodeIP := common.GlobalNodeIP
	common.ClientMu.RUnlock()
	if !tunOn || activeNode.Server == "" {
		return
	}

	resolvedIP := ResolveNodeServer(activeNode)
	if resolvedIP != "" && resolvedIP != currentNodeIP {
		log.Printf("TUN 自愈：节点 %s 解析 IP 从 %s 变为 %s，重建代理客户端和路由", activeNode.Name, currentNodeIP, resolvedIP)
		SwitchNode(activeNode)
		return
	}

	gateway := utils.GetDefaultGateway()
	realLocalIP := utils.GetRealLocalIP()

	tunMu.Lock()
	defer tunMu.Unlock()
	if !common.IsTunModeOn {
		return
	}
	if gateway == "" {
		return
	}
	if gateway != tunGateway || (realLocalIP != "" && realLocalIP != tunRealLocalIP) {
		log.Printf("TUN 自愈：网络环境变化，重建路由。gateway %s -> %s, localIP %s -> %s", tunGateway, gateway, tunRealLocalIP, realLocalIP)
		stopTunLocked()
		if err := startTunLocked(currentNodeIP); err != nil {
			log.Printf("TUN 自愈重启失败: %v", err)
		}
	}
}

func tunDNSStrategy() option.DomainStrategy {
	if GlobalSystemConfig.PreferIPv6 {
		return option.DomainStrategy(C.DomainStrategyPreferIPv6)
	}
	return option.DomainStrategy(C.DomainStrategyIPv4Only)
}

func releaseRuntimeMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}
