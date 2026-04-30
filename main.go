package main

import (
	_ "embed"
	"fmt"
	"high-mae/ins"
	"high-mae/protocol"
	"os"
	"time"

	"runtime/debug"

	"github.com/getlantern/systray"
)

func init() {
	// Set Go Memory Limit to ~150MB to force aggressive GC
	// This helps keeping the memory reported in Task Manager low.
	os.Setenv("GOMEMLIMIT", "150MiB")
	// Reduce GC threshold to make it collect garbage more frequently
	debug.SetGCPercent(20)
}

////go:embed .yml
//var embeddedConfig []byte

//go:embed icon.ico
var iconBytes []byte

//go:embed tun2socks.exe
var tun2socksBytes []byte

//go:embed wintun.dll
var wintunBytes []byte

//var importTempFile = "config.yml"

func onReady() {
	systray.SetIcon(iconBytes)
	systray.SetTitle("High Mae")
	systray.SetTooltip("High Mae")

	// 后台启动网速监控（供 Web 面板使用，不在托盘显示）
	go ins.StartNetSpeedMonitor(nil)

	// 顶部显示当前节点
	ins.MCurrentNode = systray.AddMenuItem("📍 当前节点: [未选择]", "")
	ins.MCurrentNode.Disable()
	systray.AddSeparator()

	// Web 控制面板入口
	mWebUI := systray.AddMenuItem("🎛️ 打开 Web 控制面板", "在浏览器中管理节点并测速")
	mImportLink := systray.AddMenuItem("📋 导入节点/订阅", "从剪贴板自动解析并添加节点")
	systray.AddSeparator()

	// 🚀 核心修改：程序启动时，直接从本地硬盘尝试读取持久化的配置文件
	links, err := ins.ReadSubscriptions()
	if err == nil && len(links) > 0 {
		ins.CurrentConfigFile = links[0].FileName
	}

	localNodes, err := protocol.ParseNodes(ins.CurrentConfigFile)
	if err == nil && len(localNodes) > 0 {
		ins.AllNodes = localNodes
	} else {
		fmt.Println("⚠️ 启动时未找到有效的配置文件，节点列表将为空。请通过 Web 面板导入节点或订阅。")
	}

	if len(ins.AllNodes) > 0 {
		ins.SwitchNode(ins.AllNodes[0])
	}

	// 其他基础菜单
	ins.MToggleProxy = systray.AddMenuItem("🟢 系统代理: [已开启]", "点击切换系统浏览器代理")
	ins.MToggleMode = systray.AddMenuItem("🔄 路由模式: [规则分流]", "点击切换全局/分流")
	systray.AddSeparator()
	ins.MToggleTun = systray.AddMenuItem("🔌 虚拟网卡 (TUN): [已关闭]", "接管所有流量")
	systray.AddSeparator()
	ins.MQuit = systray.AddMenuItem("❌ 安全退出", "退出程序")

	ins.Tun2socksBytes = tun2socksBytes
	ins.WintunBytes = wintunBytes

	go ins.StartLocalDNS()
	go ins.StartWebUI()

	// 🚀 在这里调用！启动本地 10808 端口的 HTTP 代理服务
	// 必须加 go 关键字让它在后台跑，千万不能漏掉 go！
	go ins.StartAnyTLSHttpServer()

	// 开启系统全局代理
	ins.SetSystemProxy(true)

	// if len(ins.AllNodes) > 0 {
	// 	go ins.ShowWindowsMsgBox("启动成功", "智能代理已成功运行！控制面板已在浏览器中打开。")
	// } else {
	// 	go ins.ShowWindowsMsgBox("代理已启动", "目前暂无节点可用，请在浏览器控制面板中点击「导入订阅」！")
	// }

	// 自动打开 Web 面板
	go func() {
		time.Sleep(500 * time.Millisecond)
		ins.RunHiddenCommand("cmd", "/c", "start", "http://127.0.0.1:10809/")
	}()

	go func() {
		for {
			select {
			case <-mWebUI.ClickedCh:
				ins.RunHiddenCommand("cmd", "/c", "start", "http://127.0.0.1:10809/")
			case <-mImportLink.ClickedCh:
				ins.ImportNodeFromClipboard()
			case <-ins.MToggleProxy.ClickedCh:
				ins.IsSystemProxyOn = !ins.IsSystemProxyOn
				ins.SetSystemProxy(ins.IsSystemProxyOn)
				if ins.IsSystemProxyOn {
					ins.MToggleProxy.SetTitle("🟢 系统代理: [已开启]")
				} else {
					ins.MToggleProxy.SetTitle("⚪ 系统代理: [已关闭]")
				}
			case <-ins.MToggleMode.ClickedCh:
				if ins.ProxyMode == "Rule" {
					ins.ProxyMode = "Global"
					ins.MToggleMode.SetTitle("🌐 路由模式: [全局代理]")
				} else {
					ins.ProxyMode = "Rule"
					ins.MToggleMode.SetTitle("🔄 路由模式: [规则分流]")
				}
			case <-ins.MToggleTun.ClickedCh:
				ins.ToggleTunMode(ins.MToggleTun, tun2socksBytes, wintunBytes)
			case <-ins.MQuit.ClickedCh:
				systray.Quit()
			}
		}
	}()
}

func onExit() {
	ins.SetSystemProxy(false)
	if ins.IsTunModeOn {
		ins.RunHiddenCommand("route", "delete", "0.0.0.0", "mask", "0.0.0.0", ins.TunIP)
		if ins.GlobalNodeIP != "" {
			ins.RunHiddenCommand("route", "delete", ins.GlobalNodeIP, "mask", "255.255.255.255")
		}
		if ins.TunCmd != nil && ins.TunCmd.Process != nil {
			ins.TunCmd.Process.Kill()
		}
	}
	os.Remove("tun2socks.exe")
	os.Remove("wintun.dll")
	//os.Remove(importTempFile)

}

func main() {
	systray.Run(onReady, onExit)
}
