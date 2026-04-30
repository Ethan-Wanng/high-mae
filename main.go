package main

import (
	_ "embed"
	"fmt"
	"high-mae/ins"
	"high-mae/protocol"
	"os"
	"os/exec"

	"github.com/getlantern/systray"
	"runtime/debug"
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

	// 顶部显示当前节点
	ins.MCurrentNode = systray.AddMenuItem("📍 当前节点: [未选择]", "")
	ins.MCurrentNode.Disable()
	systray.AddSeparator()

	// 动态加载节点功能区
	ins.MNodeMenu = systray.AddMenuItem("🌐 选择节点", "自由切换配置文件中或导入的节点")
	ins.MSupplierMenu = systray.AddMenuItem("🗂️ 选择供应商", "切换不同配置的供应商")
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
		fmt.Println("⚠️ 启动时未找到有效的配置文件，节点列表将为空。请通过托盘菜单导入节点或订阅。")
	}

	// 渲染供应商和节点选择列表
	ins.RefreshSupplierMenu()
	ins.RefreshNodeMenu(nil)
	if len(ins.AllNodes) > 0 && len(ins.NodeMenuItems) > 0 {
		ins.NodeMenuItems[0].Check()
		ins.SwitchNode(ins.AllNodes[0])
	} else if len(ins.AllNodes) == 0 {
		ins.MNodeMenu.AddSubMenuItem("⚠️ 暂无可用节点，请粘贴链接后导入", "").Disable()
	}

	// 其他基础菜单
	mToggleProxy := systray.AddMenuItem("🟢 系统代理: [已开启]", "点击切换系统浏览器代理")
	mToggleMode := systray.AddMenuItem("🔄 路由模式: [规则分流]", "点击切换全局/分流")
	systray.AddSeparator()
	mToggleTun := systray.AddMenuItem("🔌 虚拟网卡 (TUN): [已关闭]", "接管所有流量")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("❌ 安全退出", "退出程序")

	go ins.StartLocalDNS()

	// 🚀 在这里调用！启动本地 10808 端口的 HTTP 代理服务
	// 必须加 go 关键字让它在后台跑，千万不能漏掉 go！
	go ins.StartAnyTLSHttpServer()

	// 开启系统全局代理
	ins.SetSystemProxy(true)

	if len(ins.AllNodes) > 0 {
		go ins.ShowWindowsMsgBox("启动成功", "智能代理已成功运行！")
	} else {
		go ins.ShowWindowsMsgBox("代理已启动", "目前暂无节点可用，请复制订阅或节点链接后，在托盘点击「导入」！")
	}

	go func() {
		for {
			select {
			case <-mImportLink.ClickedCh:
				ins.ImportNodeFromClipboard()
			case <-mToggleProxy.ClickedCh:
				ins.IsSystemProxyOn = !ins.IsSystemProxyOn
				ins.SetSystemProxy(ins.IsSystemProxyOn)
				if ins.IsSystemProxyOn {
					mToggleProxy.SetTitle("🟢 系统代理: [已开启]")
				} else {
					mToggleProxy.SetTitle("⚪ 系统代理: [已关闭]")
				}
			case <-mToggleMode.ClickedCh:
				if ins.ProxyMode == "Rule" {
					ins.ProxyMode = "Global"
					mToggleMode.SetTitle("🌐 路由模式: [全局代理]")
				} else {
					ins.ProxyMode = "Rule"
					mToggleMode.SetTitle("🔄 路由模式: [规则分流]")
				}
			case <-mToggleTun.ClickedCh:
				ins.ToggleTunMode(mToggleTun, tun2socksBytes, wintunBytes)
			case <-mQuit.ClickedCh:
				systray.Quit()
			}
		}
	}()
}

func onExit() {
	ins.SetSystemProxy(false)
	if ins.IsTunModeOn {
		exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", ins.TunIP).Run()
		if ins.GlobalNodeIP != "" {
			exec.Command("route", "delete", ins.GlobalNodeIP, "mask", "255.255.255.255").Run()
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
