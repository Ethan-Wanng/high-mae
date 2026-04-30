package ins

import (
	_ "embed"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/getlantern/systray"
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
		RunHiddenCommand("route", "delete", "0.0.0.0", "mask", "0.0.0.0", TunIP)
		if GlobalNodeIP != "" {
			RunHiddenCommand("route", "delete", GlobalNodeIP, "mask", "255.255.255.255")
		}
		os.Remove("tun2socks.exe")
		os.Remove("wintun.dll")
		IsTunModeOn = false
	} else {
		realGateway := GetDefaultGateway()
		if realGateway == "" {
			ShowWindowsMsgBox("网关错误", "无法识别系统的默认网关。")
			return
		}

		// 增强健壮性：启动前确保没有僵尸进程和残留路由
		RunHiddenCommand("taskkill", "/F", "/IM", "tun2socks.exe")
		RunHiddenCommand("route", "delete", "0.0.0.0", "mask", "0.0.0.0", TunIP)

		os.WriteFile("tun2socks.exe", tun2socksBytes, 0755)
		os.WriteFile("wintun.dll", wintunBytes, 0644)

		TunCmd = exec.Command("./tun2socks.exe", "-device", "tun://AnyTLS-TUN", "-proxy", "http://127.0.0.1:"+LocalHttpPort, "-loglevel", "error")
		TunCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := TunCmd.Start(); err != nil {
			ShowWindowsMsgBox("启动失败", "无法启动底层引擎: "+err.Error())
			return
		}
		time.Sleep(3 * time.Second) // 增加到 3 秒，防止 wintun 还没初始化完毕导致 netsh 失败

		RunHiddenCommand("netsh", "interface", "ip", "set", "address", "AnyTLS-TUN", "static", TunIP, "255.255.255.0", "10.0.0.1")

		if GlobalNodeIP != "" {
			RunHiddenCommand("route", "add", GlobalNodeIP, "mask", "255.255.255.255", realGateway, "metric", "1")
		}

		RunHiddenCommand("route", "add", "0.0.0.0", "mask", "0.0.0.0", TunIP, "metric", "1")
		RunHiddenCommand("netsh", "interface", "ip", "set", "dns", "AnyTLS-TUN", "static", "127.0.0.2")

		IsTunModeOn = true
	}
}
