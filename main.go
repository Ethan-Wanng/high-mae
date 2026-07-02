package main

import (
	"wing/pkg/common"
	"wing/pkg/proxy"
	"wing/pkg/routing"
	"wing/pkg/stats"
	"wing/pkg/storage"
	"wing/pkg/sub"
	"wing/pkg/utils"
	"wing/pkg/webui"

	_ "embed"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/getlantern/systray"
)

func init() {
	os.Setenv("GOMEMLIMIT", "150MiB")
	debug.SetGCPercent(20)
}

//go:embed assets/icon.ico
var iconBytes []byte

//go:embed assets/icon-direct-dark.ico
var iconDirectDarkBytes []byte

//go:embed assets/icon-direct-light.ico
var iconDirectLightBytes []byte

//go:embed assets/icon-proxy.ico
var iconProxyBytes []byte

//go:embed assets/icon-tun.ico
var iconTunBytes []byte

//go:embed assets/icon-proxy-tun.ico
var iconProxyTunBytes []byte

func onReady() {
	defer utils.RecoverPanic("systray ready")

	proxy.LoadSystemConfig()
	common.RefreshTrayIcon = refreshTrayIcon
	refreshTrayIcon()
	systray.SetTitle("wing")
	systray.SetTooltip("wing")
	systray.SetOnClick(ShowFlutterWindow)

	utils.SafeGo("net speed monitor", func() { stats.StartNetSpeedMonitor(nil) })

	common.MCurrentNode = systray.AddMenuItem("📍 当前节点: [未选择]", "")
	common.MCurrentNode.Disable()
	systray.AddSeparator()

	webui.EnsureStartupState()

	if len(common.GetAllNodes()) == 0 {
		fmt.Println("⚠️ 启动时未找到有效的配置文件，节点列表将为空。请通过面板导入节点或订阅。")
	}

	routing.LoadUserRules()
	proxy.LoadDNSConfig()

	mRestart := systray.AddMenuItem("🔁 重启 wing", "重启 wing 后端与桌面控制面板")
	mAbout := systray.AddMenuItem("ℹ️ 关于", "查看项目信息与技术栈")
	common.MQuit = systray.AddMenuItem("❌ 安全退出", "退出程序")

	utils.SafeGo("local dns server", proxy.StartLocalDNS)
	utils.SafeGo("web ui server", webui.StartWebUI)
	utils.SafeGo("local http proxy", proxy.StartAnyTLSHttpServer)
	utils.SafeGo("flutter ui show", ShowFlutterWindowWhenWebUIReady)
	sub.StartAutoUpdateSubscriptions()
	restoreResult, err := proxy.RestoreLastNetworkMode()
	if err != nil {
		fmt.Printf("⚠️ 恢复上次代理模式失败: %v\n", err)
	} else if restoreResult.HadStored && restoreResult.TunDisabledForPrivilege {
		fmt.Println("⚠️ 上次代理模式包含 TUN，但当前不是管理员，已自动关闭 TUN。")
	}

	utils.SafeGo("tray menu loop", func() {
		for {
			select {
			case <-mRestart.ClickedCh:
				restartFromTray(mRestart)
			case <-mAbout.ClickedCh:
				aboutMsg := "wing v" + common.AppVersion + " - 桌面代理客户端\n\n" +
					"wing 是基于 Flutter + Go 的代理客户端，集成 sing-box、Mieru Client 与本地 Web 控制面板，支持节点订阅、测速、规则分流、自动选点、隧道连接、DNS 分流与 WebRTC 防泄漏。\n\n" +
					"协议支持：Hysteria2、TUIC、VLESS、VMess、Trojan、Shadowsocks、AnyTLS、Naive、Mieru、HTTP/SOCKS 等。\n\n" +
					"桌面交互：启动后会自动显示 Flutter 控制面板，左键点击托盘可再次唤起，右键点击托盘可打开菜单并安全退出。\n\n" +
					"安全与隐私：控制面板默认只监听 127.0.0.1:10809；Web UI API 会校验本地可信 Origin 与请求头；订阅、DNS、路由、自动选择和聚合组等本地配置通过安全存储层读写。移动端 WebView 仅允许访问本机、模拟器和私有局域网控制面板地址。\n\n" +
					"命令行进程规则可按完整命令或命令前缀选择直连/代理，默认预设 go test 直连。该规则作用于进入本地 HTTP 代理的 TCP 请求；ping 等 ICMP 流量需使用 TUN 模式接管。\n\n" +
					"核心技术栈：\n" +
					"• 框架：Flutter Desktop/Mobile + Go 后端\n" +
					"• 引擎：sing-box (及定制版 mbox) & Mieru Client\n" +
					"• 托盘：getlantern/systray\n" +
					"• 控制面板：Go 标准库 (net/http)\n" +
					"• 发布：Windows / macOS / Linux / Android / iOS\n" +
					"• 网络接管：内置 sing-box TUN + Wintun\n\n" +
					flutterUIStatus() + "\n\n" +
					"Created with ❤️ by Ethan-Wanng"
				utils.ShowWindowsMsgBox("关于 wing", aboutMsg)
			case <-common.MQuit.ClickedCh:
				quitFromTray()
			}
		}
	})
}

func restartFromTray(menuItem *systray.MenuItem) {
	if !isQuitting.CompareAndSwap(false, true) {
		return
	}
	menuItem.SetTitle("⏳ 正在重启 wing...")
	menuItem.Disable()
	if common.MQuit != nil {
		common.MQuit.Disable()
	}

	utils.SafeGo("tray restart", func() {
		if err := utils.RestartApp(); err != nil {
			isQuitting.Store(false)
			menuItem.SetTitle("🔁 重启 wing")
			menuItem.Enable()
			if common.MQuit != nil {
				common.MQuit.Enable()
			}
			utils.ShowWindowsMsgBox("重启 wing", "重启失败: "+err.Error())
			return
		}
		time.Sleep(300 * time.Millisecond)
		systray.Quit()
	})
}

func quitFromTray() {
	if !isQuitting.CompareAndSwap(false, true) {
		return
	}
	if common.MQuit != nil {
		common.MQuit.SetTitle("⏳ 正在退出 wing...")
		common.MQuit.Disable()
	}

	utils.SafeGo("tray quit", func() {
		time.Sleep(100 * time.Millisecond)
		systray.Quit()
	})
}

func onExit() {
	defer utils.RecoverPanic("shutdown cleanup")

	if err := proxy.SaveShutdownNetworkMode(); err != nil {
		fmt.Printf("⚠️ 保存上次代理模式失败: %v\n", err)
	}
	_ = utils.SetSystemProxy(false)
	if common.IsSystemDNSHijacked {
		utils.SetSystemDNS(false, "")
		common.IsSystemDNSHijacked = false
	}
	if common.GetTunModeOn() {
		proxy.StopTun()
		common.SetTunModeOn(false)
	}
	common.SetSystemProxyOn(false)
	stats.SyncTrafficSession(false, false)
	_ = storage.Close()
	QuitFlutterApp()
	utils.ReleaseSingleInstanceLock()
}

func main() {
	defer utils.RecoverPanic("main")

	var (
		locked bool
		err    error
	)
	if utils.HasRestartHandoffArg() {
		locked, err = utils.AcquireSingleInstanceLockWithRetry(8 * time.Second)
	} else {
		locked, err = utils.AcquireSingleInstanceLock()
	}
	if err != nil {
		utils.ShowWindowsMsgBox("wing", "无法创建单实例锁: "+err.Error())
		return
	}
	if !locked {
		utils.ShowWindowsMsgBox("wing", "wing 已经在运行，请从系统托盘打开控制面板。")
		return
	}
	defer utils.ReleaseSingleInstanceLock()

	utils.EnsureCronetDll()

	if err := storage.Init(); err != nil {
		utils.ShowWindowsMsgBox("wing", "数据库初始化失败: "+err.Error())
		return
	}

	systray.Run(onReady, onExit)
}

func refreshTrayIcon() {
	systray.SetIcon(currentTrayIconBytes())
}

func currentTrayIconBytes() []byte {
	proxyOn, tunOn, _ := common.GetNetworkState()
	switch {
	case proxyOn && tunOn:
		return iconProxyTunBytes
	case proxyOn:
		return iconProxyBytes
	case tunOn:
		return iconTunBytes
	case isEffectiveLightTheme():
		return iconDirectLightBytes
	default:
		return iconDirectDarkBytes
	}
}

func isEffectiveLightTheme() bool {
	switch proxy.GlobalSystemConfig.ThemeMode {
	case "light":
		return true
	case "dark":
		return false
	default:
		return utils.IsSystemLightTheme()
	}
}
