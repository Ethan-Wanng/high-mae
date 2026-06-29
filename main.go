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

	mImportLink := systray.AddMenuItem("📋 导入节点/订阅", "从剪贴板自动解析并添加节点")
	systray.AddSeparator()

	webui.EnsureStartupState()

	if len(common.AllNodes) == 0 {
		fmt.Println("⚠️ 启动时未找到有效的配置文件，节点列表将为空。请通过面板导入节点或订阅。")
	}

	routing.LoadUserRules()
	proxy.LoadDNSConfig()

	common.MToggleProxy = systray.AddMenuItem("⚪ 系统代理: [已关闭]", "点击切换系统浏览器代理")
	common.MToggleMode = systray.AddMenuItem("🔄 路由模式: [规则分流]", "点击切换全局/分流")
	systray.AddSeparator()
	common.MToggleTun = systray.AddMenuItem("🔌 隧道连接: [已关闭]", "通过 TUN 隧道接管所有流量")
	systray.AddSeparator()
	mRestart := systray.AddMenuItem("🔁 重启 wing", "重启 wing 后端与桌面控制面板")
	mAbout := systray.AddMenuItem("ℹ️ 关于", "查看项目信息与技术栈")
	common.MQuit = systray.AddMenuItem("❌ 安全退出", "退出程序")

	utils.SafeGo("local dns server", proxy.StartLocalDNS)
	utils.SafeGo("web ui server", webui.StartWebUI)
	utils.SafeGo("local http proxy", proxy.StartAnyTLSHttpServer)
	utils.SafeGo("flutter ui show", ShowFlutterWindowWhenWebUIReady)
	sub.StartAutoUpdateSubscriptions()
	if err := utils.SetSystemProxy(common.IsSystemProxyOn); err != nil {
		fmt.Printf("⚠️ 同步系统代理状态失败: %v\n", err)
	}

	utils.SafeGo("tray menu loop", func() {
		for {
			select {
			case <-mImportLink.ClickedCh:
				sub.ImportNodeFromClipboard()
			case <-common.MToggleProxy.ClickedCh:
				if err := proxy.ToggleSystemProxy(); err != nil {
					utils.ShowWindowsMsgBox("系统代理", "切换系统代理失败: "+err.Error())
				}
			case <-common.MToggleMode.ClickedCh:
				proxy.ToggleProxyMode()
			case <-common.MToggleTun.ClickedCh:
				if msg := proxy.ToggleTunMode(); msg != "" {
					utils.ShowWindowsMsgBox("隧道连接", msg)
				}
				stats.SyncTrafficSession(common.IsSystemProxyOn, common.IsTunModeOn)
				refreshTrayIcon()
			case <-mRestart.ClickedCh:
				if err := utils.RestartApp(); err != nil {
					utils.ShowWindowsMsgBox("重启 wing", "重启失败: "+err.Error())
					continue
				}
				isQuitting.Store(true)
				utils.SafeGo("tray restart exit", func() {
					time.Sleep(500 * time.Millisecond)
					systray.Quit()
				})
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
				isQuitting.Store(true)
				systray.Quit()
			}
		}
	})
}

func onExit() {
	defer utils.RecoverPanic("shutdown cleanup")

	_ = utils.SetSystemProxy(false)
	if common.IsSystemDNSHijacked {
		utils.SetSystemDNS(false, "")
		common.IsSystemDNSHijacked = false
	}
	if common.IsTunModeOn {
		proxy.StopTun()
		common.IsTunModeOn = false
	}
	common.IsSystemProxyOn = false
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
	switch {
	case common.IsSystemProxyOn && common.IsTunModeOn:
		return iconProxyTunBytes
	case common.IsSystemProxyOn:
		return iconProxyBytes
	case common.IsTunModeOn:
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
