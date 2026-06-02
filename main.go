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

	"github.com/getlantern/systray"
)

func init() {
	os.Setenv("GOMEMLIMIT", "150MiB")
	debug.SetGCPercent(20)
}

//go:embed assets/icon.ico
var iconBytes []byte

func onReady() {
	defer utils.RecoverPanic("systray ready")

	systray.SetIcon(iconBytes)
	systray.SetTitle("wing")
	systray.SetTooltip("wing")

	utils.SafeGo("net speed monitor", func() { stats.StartNetSpeedMonitor(nil) })

	common.MCurrentNode = systray.AddMenuItem("📍 当前节点: [未选择]", "")
	common.MCurrentNode.Disable()
	systray.AddSeparator()

	mShowUI := systray.AddMenuItem("🎛️ 显示控制面板", "显示 Flutter 桌面控制面板窗口")
	mBrowserUI := systray.AddMenuItem("🌐 浏览器打开控制面板", "在浏览器中管理节点并测速")
	mImportLink := systray.AddMenuItem("📋 导入节点/订阅", "从剪贴板自动解析并添加节点")
	systray.AddSeparator()

	webui.EnsureStartupState()

	if len(common.AllNodes) == 0 {
		fmt.Println("⚠️ 启动时未找到有效的配置文件，节点列表将为空。请通过面板导入节点或订阅。")
	}

	routing.LoadUserRules()
	proxy.LoadDNSConfig()
	proxy.LoadSystemConfig()

	common.MToggleProxy = systray.AddMenuItem("⚪ 系统代理: [已关闭]", "点击切换系统浏览器代理")
	common.MToggleMode = systray.AddMenuItem("🔄 路由模式: [规则分流]", "点击切换全局/分流")
	systray.AddSeparator()
	common.MToggleTun = systray.AddMenuItem("🔌 隧道连接: [已关闭]", "通过 TUN 隧道接管所有流量")
	systray.AddSeparator()
	mAbout := systray.AddMenuItem("ℹ️ 关于", "查看项目信息与技术栈")
	common.MQuit = systray.AddMenuItem("❌ 安全退出", "退出程序")

	utils.SafeGo("local dns server", proxy.StartLocalDNS)
	utils.SafeGo("web ui server", webui.StartWebUI)
	utils.SafeGo("local http proxy", proxy.StartAnyTLSHttpServer)
	sub.StartAutoUpdateSubscriptions()
	utils.SetSystemProxy(common.IsSystemProxyOn)
	utils.SafeGo("flutter desktop ui", ShowFlutterWindow)

	utils.SafeGo("tray menu loop", func() {
		for {
			select {
			case <-mShowUI.ClickedCh:
				ShowFlutterWindow()
			case <-mBrowserUI.ClickedCh:
				openExternalURL(webUIURL)
			case <-mImportLink.ClickedCh:
				sub.ImportNodeFromClipboard()
			case <-common.MToggleProxy.ClickedCh:
				proxy.RunNetworkTransition(func() {
					common.IsSystemProxyOn = !common.IsSystemProxyOn
					utils.SetSystemProxy(common.IsSystemProxyOn)
					stats.SyncTrafficSession(common.IsSystemProxyOn, common.IsTunModeOn)
					if common.IsSystemProxyOn {
						common.MToggleProxy.SetTitle("🟢 系统代理: [已开启]")
					} else {
						common.MToggleProxy.SetTitle("⚪ 系统代理: [已关闭]")
					}
				})
			case <-common.MToggleMode.ClickedCh:
				proxy.RunNetworkTransition(func() {
					if common.ProxyMode == "Rule" {
						common.ProxyMode = "Global"
						common.MToggleMode.SetTitle("🌐 路由模式: [全局代理]")
					} else {
						common.ProxyMode = "Rule"
						common.MToggleMode.SetTitle("🔄 路由模式: [规则分流]")
					}
				})
			case <-common.MToggleTun.ClickedCh:
				if msg := proxy.ToggleTunMode(); msg != "" {
					utils.ShowWindowsMsgBox("隧道连接", msg)
				}
				stats.SyncTrafficSession(common.IsSystemProxyOn, common.IsTunModeOn)
			case <-mAbout.ClickedCh:
				aboutMsg := "wing v1.0.0 - 桌面代理客户端\n\n" +
					"wing 集成 sing-box、Mieru Client 与本地 Web 控制面板，支持节点订阅、测速、规则分流、隧道连接、DNS 分流与 WebRTC 防泄漏。\n\n" +
					"协议支持：Hysteria2、TUIC、VLESS、VMess、Trojan、Shadowsocks、AnyTLS、Naive、Mieru、HTTP/SOCKS 等。\n\n" +
					"命令行进程规则可按完整命令或命令前缀选择直连/代理，默认预设 go test 直连。该规则作用于进入本地 HTTP 代理的 TCP 请求；ping 等 ICMP 流量需使用 TUN 模式接管。\n\n" +
					"核心技术栈：\n" +
					"• 框架：Flutter Desktop + Go 后端\n" +
					"• 引擎：sing-box (及定制版 mbox) & Mieru Client\n" +
					"• 托盘：getlantern/systray\n" +
					"• 控制面板：Go 标准库 (net/http)\n" +
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

	utils.SetSystemProxy(false)
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

	locked, err := utils.AcquireSingleInstanceLock()
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
