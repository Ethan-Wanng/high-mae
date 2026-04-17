package ins

import (
	_ "embed"
	"github.com/getlantern/systray"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func ToggleTunMode(mToggleTun *systray.MenuItem, tun2socksBytes []byte, wintunBytes []byte) {
	if !IsAdmin() {
		ShowWindowsMsgBox("权限不足", "开启虚拟网卡(TUN)需要管理员权限！\n请退出程序，右键选择「以管理员身份运行」。")
		return
	}
	if IsTunModeOn {
		if TunCmd != nil && TunCmd.Process != nil {
			TunCmd.Process.Kill()
		}
		exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", TunIP).Run()
		if GlobalNodeIP != "" {
			exec.Command("route", "delete", GlobalNodeIP, "mask", "255.255.255.255").Run()
		}
		os.Remove("tun2socks.exe")
		os.Remove("wintun.dll")
		IsTunModeOn = false
		mToggleTun.SetTitle("🔌 虚拟网卡 (TUN): [已关闭]")
		ShowWindowsMsgBox("TUN 已关闭", "虚拟网卡已安全卸载。")
	} else {
		realGateway := GetDefaultGateway()
		if realGateway == "" {
			ShowWindowsMsgBox("网关错误", "无法识别系统的默认网关。")
			return
		}
		os.WriteFile("tun2socks.exe", tun2socksBytes, 0755)
		os.WriteFile("wintun.dll", wintunBytes, 0644)

		TunCmd = exec.Command("./tun2socks.exe", "-device", "tun://AnyTLS-TUN", "-proxy", "http://127.0.0.1:"+LocalHttpPort, "-loglevel", "error")
		TunCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := TunCmd.Start(); err != nil {
			ShowWindowsMsgBox("启动失败", "无法启动底层引擎: "+err.Error())
			return
		}
		time.Sleep(2 * time.Second)

		exec.Command("netsh", "interface", "ip", "set", "address", "AnyTLS-TUN", "static", TunIP, "255.255.255.0", "10.0.0.1").Run()

		if GlobalNodeIP != "" {
			exec.Command("route", "add", GlobalNodeIP, "mask", "255.255.255.255", realGateway, "metric", "1").Run()
		}

		exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", TunIP, "metric", "1").Run()
		exec.Command("netsh", "interface", "ip", "set", "dns", "AnyTLS-TUN", "static", "127.0.0.2").Run()

		IsTunModeOn = true
		mToggleTun.SetTitle("🔌 虚拟网卡 (TUN): [已开启]")
		ShowWindowsMsgBox("启动成功", "全网流量接管已启动！现在命令行、游戏等都会强制经过代理。")
	}
}
