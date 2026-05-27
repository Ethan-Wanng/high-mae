package proxy

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"wing/pkg/common"
	"wing/pkg/utils"
)

//go:embed tun2socks.exe
var tun2socksBytes []byte

//go:embed wintun.dll
var wintunBytes []byte

var (
	tunMu           sync.Mutex
	tunCmd          *exec.Cmd
	tunWatchStop    chan struct{}
	tunWatchDone    chan struct{}
	tunGateway      string
	tunRealLocalIP  string
	tunRoutedNodeIP string
)

const TunIP = "10.0.0.2"

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
			common.MToggleTun.SetTitle("🔌 虚拟网卡 (TUN): [已关闭]")
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
		common.MToggleTun.SetTitle("🟢 虚拟网卡 (TUN): [已开启]")
	}
	log.Println("TUN 模式已开启（创建虚拟网卡，添加路由）")
	return ""
}

// RestartTun 重启 TUN（在切换节点后由 proxy.go 调用）
func RestartTun(nodeServer, nodeIP string) error {
	tunMu.Lock()
	defer tunMu.Unlock()

	if !common.IsTunModeOn {
		return nil
	}

	stopTunLocked()
	return startTunLocked(nodeIP)
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

// stopTunLocked 关闭正在运行的 tun2socks 实例（调用者必须持有 tunMu）
func stopTunLocked() {
	if tunCmd != nil && tunCmd.Process != nil {
		_ = tunCmd.Process.Kill()
		_ = tunCmd.Wait()
		tunCmd = nil
	}
	utils.RunHiddenCommand("taskkill", "/F", "/IM", "tun2socks.exe")
	utils.RunHiddenCommand("route", "delete", "0.0.0.0", "mask", "0.0.0.0", TunIP)

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
	if nodeIP == "" {
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

// startTunLocked 启动一个全新的 tun2socks 实例（调用者必须持有 tunMu）
func startTunLocked(nodeIP string) error {
	realGateway := utils.GetDefaultGateway()
	if realGateway == "" {
		return fmt.Errorf("无法识别系统的默认网关")
	}

	// 记录原始网卡IP
	common.RealLocalIPBeforeTun = utils.GetRealLocalIP()
	tunGateway = realGateway
	tunRealLocalIP = common.RealLocalIPBeforeTun

	// 增强健壮性：启动前确保没有僵尸进程和残留路由
	utils.RunHiddenCommand("taskkill", "/F", "/IM", "tun2socks.exe")
	utils.RunHiddenCommand("route", "delete", "0.0.0.0", "mask", "0.0.0.0", TunIP)
	if tunRoutedNodeIP != "" {
		utils.RunHiddenCommand("route", "delete", tunRoutedNodeIP, "mask", "255.255.255.255")
		tunRoutedNodeIP = ""
	}
	if nodeIP != "" {
		utils.RunHiddenCommand("route", "delete", nodeIP, "mask", "255.255.255.255")
	}

	if err := ensureTunAssetsLocked(); err != nil {
		return err
	}

	tunCmd = exec.Command(
		"./tun2socks.exe",
		"-device", "tun://AnyTLS-TUN",
		"-proxy", "http://127.0.0.1:"+common.LocalHttpPort,
		"-loglevel", "silent",
		"-mtu", "1400",
		"-tcp-rcvbuf", "256k",
		"-tcp-sndbuf", "256k",
		"-udp-timeout", "30s",
	)
	tunCmd.Env = append(os.Environ(), "GOGC=20", "GOMEMLIMIT=96MiB")
	tunCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := tunCmd.Start(); err != nil {
		return fmt.Errorf("无法启动底层引擎: %v", err)
	}
	releaseRuntimeMemory()
	time.Sleep(3 * time.Second) // 增加到 3 秒，防止 wintun 还没初始化完毕导致 netsh 失败

	utils.RunHiddenCommand("netsh", "interface", "ip", "set", "address", "AnyTLS-TUN", "static", TunIP, "255.255.255.0", "10.0.0.1")

	if nodeIP != "" {
		utils.RunHiddenCommand("route", "add", nodeIP, "mask", "255.255.255.255", realGateway, "metric", "1")
		tunRoutedNodeIP = nodeIP
	}

	utils.RunHiddenCommand("route", "add", "0.0.0.0", "mask", "0.0.0.0", TunIP, "metric", "1")
	utils.RunHiddenCommand("netsh", "interface", "ip", "set", "dns", "AnyTLS-TUN", "static", "127.0.0.2")

	return nil
}

func ensureTunAssetsLocked() error {
	if _, err := os.Stat("tun2socks.exe"); os.IsNotExist(err) {
		if len(tun2socksBytes) == 0 {
			return fmt.Errorf("tun2socks.exe 不存在，且内置资源已释放")
		}
		if err := os.WriteFile("tun2socks.exe", tun2socksBytes, 0755); err != nil {
			return fmt.Errorf("写入 tun2socks.exe 失败: %w", err)
		}
	}
	if _, err := os.Stat("wintun.dll"); os.IsNotExist(err) {
		if len(wintunBytes) == 0 {
			return fmt.Errorf("wintun.dll 不存在，且内置资源已释放")
		}
		if err := os.WriteFile("wintun.dll", wintunBytes, 0644); err != nil {
			return fmt.Errorf("写入 wintun.dll 失败: %w", err)
		}
	}

	tun2socksBytes = nil
	wintunBytes = nil
	releaseRuntimeMemory()
	return nil
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

func releaseRuntimeMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}
