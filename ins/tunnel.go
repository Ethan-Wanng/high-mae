package ins

import (
	_ "embed"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/getlantern/systray"
)

// ToggleTunMode 切换 TUN 模式，返回非空字符串表示错误信息
func ToggleTunMode(mToggleTun *systray.MenuItem) string {
	if !IsAdmin() {
		return "开启虚拟网卡(TUN)需要管理员权限！\n请退出程序，右键选择「以管理员身份运行」。"
	}
	if IsTunModeOn {
		if TunCmd != nil && TunCmd.Process != nil {
			TunCmd.Process.Kill()
		}
		RunHiddenCommand("route", "delete", "0.0.0.0", "mask", "0.0.0.0", TunIP)
		if GlobalNodeIP != "" {
			RunHiddenCommand("route", "delete", GlobalNodeIP, "mask", "255.255.255.255")
		}
		IsTunModeOn = false
	} else {
		realGateway := GetDefaultGateway()
		if realGateway == "" {
			return "无法识别系统的默认网关。"
		}

		// 增强健壮性：启动前确保没有僵尸进程和残留路由
		RunHiddenCommand("taskkill", "/F", "/IM", "tun2socks.exe")
		RunHiddenCommand("route", "delete", "0.0.0.0", "mask", "0.0.0.0", TunIP)

		// 🚀 优化：不再写入，如果文件被意外删除则提示用户重启程序释放
		if _, err := os.Stat("tun2socks.exe"); os.IsNotExist(err) {
			return "核心文件 tun2socks.exe 不存在，请重启程序以释放。"
		}
		if _, err := os.Stat("wintun.dll"); os.IsNotExist(err) {
			return "核心文件 wintun.dll 不存在，请重启程序以释放。"
		}

		TunCmd = exec.Command("./tun2socks.exe", "-device", "tun://AnyTLS-TUN", "-proxy", "http://127.0.0.1:"+LocalHttpPort, "-loglevel", "error")
		TunCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := TunCmd.Start(); err != nil {
			return "无法启动底层引擎: " + err.Error()
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
	return ""
}
