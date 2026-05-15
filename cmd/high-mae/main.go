package main

import (
	"high-mae/pkg/common"
	"high-mae/pkg/proxy"
	"high-mae/pkg/routing"
	"high-mae/pkg/stats"
	"high-mae/pkg/sub"
	"high-mae/pkg/utils"
	"high-mae/pkg/webui"

	_ "embed"
	"fmt"
	"high-mae/protocol"
	"time"

	"runtime/debug"

	"github.com/getlantern/systray"
	"os"
)

func init() {
	os.Setenv("GOMEMLIMIT", "150MiB")
	debug.SetGCPercent(20)
}

//go:embed assets/icon.ico
var iconBytes []byte

func onReady() {
	systray.SetIcon(iconBytes)
	systray.SetTitle("High Mae")
	systray.SetTooltip("High Mae")

	go stats.StartNetSpeedMonitor(nil)

	common.MCurrentNode = systray.AddMenuItem("📍 当前节点: [未选择]", "")
	common.MCurrentNode.Disable()
	systray.AddSeparator()

	mWebUI := systray.AddMenuItem("🎛️ 打开 Web 控制面板", "在浏览器中管理节点并测速")
	mImportLink := systray.AddMenuItem("📋 导入节点/订阅", "从剪贴板自动解析并添加节点")
	systray.AddSeparator()

	links, err := sub.ReadSubscriptions()
	if err == nil && len(links) > 0 {
		sub.CurrentConfigFile = links[0].FileName
	}

	localNodes, err := protocol.ParseNodes(sub.CurrentConfigFile)
	if err == nil && len(localNodes) > 0 {
		common.AllNodes = localNodes
	} else {
		fmt.Println("⚠️ 启动时未找到有效的配置文件，节点列表将为空。请通过 Web 面板导入节点或订阅。")
	}

	routing.LoadUserRules()
	proxy.LoadDNSConfig() // Note: DNS config was in proxy after reorganization if I put it there

	if len(common.AllNodes) > 0 {
		proxy.SwitchNode(common.AllNodes[0])
	}

	common.MToggleProxy = systray.AddMenuItem("🟢 系统代理: [已开启]", "点击切换系统浏览器代理")
	common.MToggleMode = systray.AddMenuItem("🔄 路由模式: [规则分流]", "点击切换全局/分流")
	systray.AddSeparator()
	common.MToggleTun = systray.AddMenuItem("🔌 虚拟网卡 (TUN): [已关闭]", "接管所有流量")
	systray.AddSeparator()
	mAbout := systray.AddMenuItem("ℹ️ 关于海魅", "查看项目信息与技术栈")
	common.MQuit = systray.AddMenuItem("❌ 安全退出", "退出程序")

	go proxy.StartLocalDNS()
	go webui.StartWebUI()
	go proxy.StartAnyTLSHttpServer()
	sub.StartAutoUpdateSubscriptions()
	utils.SetSystemProxy(true)

	go func() {
		time.Sleep(500 * time.Millisecond)
		utils.RunHiddenCommand("cmd", "/c", "start", "http://127.0.0.1:10809/")
	}()

	go func() {
		for {
			select {
			case <-mWebUI.ClickedCh:
				utils.RunHiddenCommand("cmd", "/c", "start", "http://127.0.0.1:10809/")
			case <-mImportLink.ClickedCh:
				sub.ImportNodeFromClipboard()
			case <-common.MToggleProxy.ClickedCh:
				common.IsSystemProxyOn = !common.IsSystemProxyOn
				utils.SetSystemProxy(common.IsSystemProxyOn)
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
			case <-mAbout.ClickedCh:
				aboutMsg := "海魅 (High-Mae) - 现代化 Windows 代理客户端\n\n" +
					"本项目已在 GitHub 遵循 MIT 协议开源。\n\n" +
					"核心技术栈：\n" +
					"• 引擎：sing-box (及定制版 mbox)\n" +
					"• 托盘：getlantern/systray\n" +
					"• 控制面板：Go 标准库 (net/http)\n" +
					"• 网络驱动：sing-box TUN\n\n" +
					"Created with ❤️ by Ethan-Wanng"
				utils.ShowWindowsMsgBox("关于海魅", aboutMsg)
			case <-common.MQuit.ClickedCh:
				systray.Quit()
			}
		}
	}()
}

func onExit() {
	utils.SetSystemProxy(false)
	if proxy.GlobalDNSConfig.AutoOverwrite {
		utils.SetSystemDNS(false, "")
	}
	if common.IsTunModeOn {
		proxy.StopSingBoxTun()
		common.IsTunModeOn = false
	}
}

func main() {
	systray.Run(onReady, onExit)
}
