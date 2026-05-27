package main

import (
	"high-mae/pkg/common"
	"high-mae/pkg/proxy"
	"high-mae/pkg/routing"
	"high-mae/pkg/stats"
	"high-mae/pkg/storage"
	"high-mae/pkg/sub"
	"high-mae/pkg/utils"
	"high-mae/pkg/webui"
	"high-mae/protocol"

	_ "embed"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/getlantern/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
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
	systray.SetTitle("High Mae")
	systray.SetTooltip("High Mae")

	utils.SafeGo("net speed monitor", func() { stats.StartNetSpeedMonitor(nil) })

	common.MCurrentNode = systray.AddMenuItem("📍 当前节点: [未选择]", "")
	common.MCurrentNode.Disable()
	systray.AddSeparator()

	mShowUI := systray.AddMenuItem("🎛️ 显示控制面板", "显示桌面控制面板窗口")
	mBrowserUI := systray.AddMenuItem("🌐 浏览器打开控制面板", "在浏览器中管理节点并测速")
	mImportLink := systray.AddMenuItem("📋 导入节点/订阅", "从剪贴板自动解析并添加节点")
	systray.AddSeparator()

	// 1. 读取上次选择的配置文件和节点
	var lastConfigFile string
	var lastNodeName string

	if data, err := storage.Read("last_active_config_file"); err == nil {
		lastConfigFile = string(data)
	}
	if data, err := storage.Read("last_active_node_name"); err == nil {
		lastNodeName = string(data)
	}

	// 2. 如果上次没有保存过的配置文件，则回退到默认的第一个
	if lastConfigFile == "" {
		links, err := sub.ReadSubscriptions()
		if err == nil && len(links) > 0 {
			lastConfigFile = links[0].FileName
		}
	}

	// 3. 设置当前使用的配置文件并解析节点
	if lastConfigFile != "" {
		sub.CurrentConfigFile = lastConfigFile
		localNodes, err := protocol.ParseNodes(sub.CurrentConfigFile)
		if err == nil && len(localNodes) > 0 {
			common.AllNodes = localNodes
		}
	}

	if len(common.AllNodes) == 0 {
		fmt.Println("⚠️ 启动时未找到有效的配置文件，节点列表将为空。请通过面板导入节点或订阅。")
	}

	routing.LoadUserRules()
	proxy.LoadDNSConfig()

	// 4. 激活上次选择的节点，如果不存在或第一次，则默认激活第一个节点
	if len(common.AllNodes) > 0 {
		targetNode := common.AllNodes[0] // 默认第一个
		if lastNodeName != "" {
			for _, n := range common.AllNodes {
				if n.Name == lastNodeName {
					targetNode = n
					break
				}
			}
		}
		proxy.SwitchNode(targetNode)
	}

	common.MToggleProxy = systray.AddMenuItem("⚪ 系统代理: [已关闭]", "点击切换系统浏览器代理")
	common.MToggleMode = systray.AddMenuItem("🔄 路由模式: [规则分流]", "点击切换全局/分流")
	systray.AddSeparator()
	common.MToggleTun = systray.AddMenuItem("🔌 虚拟网卡 (TUN): [已关闭]", "接管所有流量")
	systray.AddSeparator()
	mAbout := systray.AddMenuItem("ℹ️ 关于", "查看项目信息与技术栈")
	common.MQuit = systray.AddMenuItem("❌ 安全退出", "退出程序")

	utils.SafeGo("local dns server", proxy.StartLocalDNS)
	utils.SafeGo("web ui server", webui.StartWebUI)
	utils.SafeGo("local http proxy", proxy.StartAnyTLSHttpServer)
	sub.StartAutoUpdateSubscriptions()
	utils.SetSystemProxy(common.IsSystemProxyOn)

	utils.SafeGo("tray menu loop", func() {
		for {
			select {
			case <-mShowUI.ClickedCh:
				ShowWailsWindow()
			case <-mBrowserUI.ClickedCh:
				utils.RunHiddenCommand("cmd", "/c", "start", "http://127.0.0.1:10809/")
			case <-mImportLink.ClickedCh:
				sub.ImportNodeFromClipboard()
			case <-common.MToggleProxy.ClickedCh:
				common.IsSystemProxyOn = !common.IsSystemProxyOn
				utils.SetSystemProxy(common.IsSystemProxyOn)
				stats.SyncTrafficSession(common.IsSystemProxyOn, common.IsTunModeOn)
				if common.IsSystemProxyOn {
					common.MToggleProxy.SetTitle("🟢 系统代理: [已开启]")
				} else {
					common.MToggleProxy.SetTitle("⚪ 系统代理: [已关闭]")
				}
			case <-common.MToggleMode.ClickedCh:
				if common.ProxyMode == "Rule" {
					common.ProxyMode = "Global"
					common.MToggleMode.SetTitle("🌐 路由模式: [全局代理]")
				} else {
					common.ProxyMode = "Rule"
					common.MToggleMode.SetTitle("🔄 路由模式: [规则分流]")
				}
			case <-common.MToggleTun.ClickedCh:
				if msg := proxy.ToggleTunMode(); msg != "" {
					utils.ShowWindowsMsgBox("TUN 模式", msg)
				}
				stats.SyncTrafficSession(common.IsSystemProxyOn, common.IsTunModeOn)
			case <-mAbout.ClickedCh:
				aboutMsg := "High-Mae v1.2.0 - Windows 桌面代理客户端\n\n" +
					"High-Mae 集成 sing-box、Mieru Client 与本地 Web 控制面板，支持节点订阅、测速、规则分流、TUN 接管、DNS 分流与 WebRTC 防泄漏。\n\n" +
					"协议支持：Hysteria2、TUIC、VLESS、VMess、Trojan、Shadowsocks、AnyTLS、Naive、Mieru、HTTP/SOCKS 等。\n\n" +
					"命令行进程规则可按完整命令或命令前缀选择直连/代理，默认预设 go test 直连。该规则作用于进入本地 HTTP 代理的 TCP 请求；ping 等 ICMP 流量需使用 TUN 模式接管。\n\n" +
					"核心技术栈：\n" +
					"• 框架：Wails v2 Desktop\n" +
					"• 引擎：sing-box (及定制版 mbox) & Mieru Client\n" +
					"• 托盘：getlantern/systray\n" +
					"• 控制面板：Go 标准库 (net/http)\n" +
					"• 网络驱动：sing-box TUN\n\n" +
					"Created with ❤️ by Ethan-Wanng"
				utils.ShowWindowsMsgBox("关于 High-Mae", aboutMsg)
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
		proxy.StopSingBoxTun()
		common.IsTunModeOn = false
	}
	common.IsSystemProxyOn = false
	stats.SyncTrafficSession(false, false)
	_ = storage.Close()
	QuitWailsApp()
	utils.ReleaseSingleInstanceLock()
}

func main() {
	defer utils.RecoverPanic("main")

	locked, err := utils.AcquireSingleInstanceLock()
	if err != nil {
		utils.ShowWindowsMsgBox("High-Mae", "无法创建单实例锁: "+err.Error())
		return
	}
	if !locked {
		utils.ShowWindowsMsgBox("High-Mae", "High-Mae 已经在运行，请从系统托盘打开控制面板。")
		return
	}
	defer utils.ReleaseSingleInstanceLock()

	utils.EnsureCronetDll()

	// 1. Run the system tray in a background thread
	utils.SafeGo("systray", func() { systray.Run(onReady, onExit) })

	// 2. Initialize and run the Wails Desktop window on the main thread
	app := NewApp()

	err = wails.Run(&options.App{
		Title:             "海魅 High-Mae",
		Width:             1280,
		Height:            800,
		DisableResize:     false,
		Fullscreen:        false,
		Frameless:         false,
		StartHidden:       false,
		HideWindowOnClose: true,
		AssetServer: &assetserver.Options{
			Assets:  webui.GetEmbeddedAssets(),
			Handler: webui.GetWebUIMux(),
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.startup,
		OnBeforeClose:    app.beforeClose,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
