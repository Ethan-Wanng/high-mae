package ins

import (
	"fmt"
	"os/exec"
	"strings"
)

// ToggleWebRTCLeak 尝试通过修改 Windows 注册表策略来防止 WebRTC 真实 IP 泄露。
func ToggleWebRTCLeak(enable bool) {
	var script string

	if enable {
		script = `reg add HKLM\SOFTWARE\Policies\Google\Chrome /v WebRtcIPHandlingPolicy /t REG_SZ /d disable_non_proxied_udp /f; ` +
			`reg add HKCU\SOFTWARE\Policies\Google\Chrome /v WebRtcIPHandlingPolicy /t REG_SZ /d disable_non_proxied_udp /f; ` +
			`reg add HKLM\SOFTWARE\Policies\Microsoft\Edge /v WebRtcIPHandlingPolicy /t REG_SZ /d disable_non_proxied_udp /f; ` +
			`reg add HKCU\SOFTWARE\Policies\Microsoft\Edge /v WebRtcIPHandlingPolicy /t REG_SZ /d disable_non_proxied_udp /f`
	} else {
		script = `reg delete HKLM\SOFTWARE\Policies\Google\Chrome /v WebRtcIPHandlingPolicy /f; ` +
			`reg delete HKCU\SOFTWARE\Policies\Google\Chrome /v WebRtcIPHandlingPolicy /f; ` +
			`reg delete HKLM\SOFTWARE\Policies\Microsoft\Edge /v WebRtcIPHandlingPolicy /f; ` +
			`reg delete HKCU\SOFTWARE\Policies\Microsoft\Edge /v WebRtcIPHandlingPolicy /f`
	}

	// 使用单一 UAC 提示执行所有命令
	cmdStr := fmt.Sprintf(`Start-Process powershell -ArgumentList "-NoProfile -Command %s" -Verb RunAs -WindowStyle Hidden`, script)
	exec.Command("powershell", "-Command", cmdStr).Run()
}

// CheckWebRTCLeakStatus 检查是否已经启用了防 WebRTC 泄露
func CheckWebRTCLeakStatus() bool {
	chromeInstalled := isBrowserInstalled("chrome.exe")
	edgeInstalled := isBrowserInstalled("msedge.exe")

	chromeOk := !chromeInstalled
	if chromeInstalled {
		// 检查 Chrome HKLM 或 HKCU 策略
		if regValueExists(`HKLM\SOFTWARE\Policies\Google\Chrome`, "WebRtcIPHandlingPolicy") ||
			regValueExists(`HKCU\SOFTWARE\Policies\Google\Chrome`, "WebRtcIPHandlingPolicy") {
			chromeOk = true
		}
	}

	edgeOk := !edgeInstalled
	if edgeInstalled {
		// 检查 Edge HKLM 或 HKCU 策略
		if regValueExists(`HKLM\SOFTWARE\Policies\Microsoft\Edge`, "WebRtcIPHandlingPolicy") ||
			regValueExists(`HKCU\SOFTWARE\Policies\Microsoft\Edge`, "WebRtcIPHandlingPolicy") {
			edgeOk = true
		}
	}

	return chromeOk && edgeOk
}

func isBrowserInstalled(exeName string) bool {
	path := fmt.Sprintf(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\%s`, exeName)
	cmd := exec.Command("reg", "query", path)
	return cmd.Run() == nil
}

func regValueExists(keyPath, valueName string) bool {
	cmd := exec.Command("reg", "query", keyPath, "/v", valueName)
	return cmd.Run() == nil
}

// StunDomains 常见的 STUN 服务器域名，用于拦截和伪造响应
var StunDomains = []string{
	"stun.l.google.com",
	"stun1.l.google.com",
	"stun2.l.google.com",
	"stun3.l.google.com",
	"stun4.l.google.com",
	"stun.voipbuster.com",
	"stun.voipstunt.com",
	"stun.ekiga.net",
	"stun.ideasip.com",
	"stun.schlund.de",
	"stun.softjoys.com",
	"stun.voiparound.com",
	"stun.voipgate.com",
	"stun.xten.com",
	"stun.turnserver.net",
	"stun.rixtelecom.se",
	"stun.iptel.org",
	"stun.fwdnet.net",
	"stun.mit.edu",
	"stun.callwithus.com",
	"stun.counterpath.com",
	"stun.internetcalls.com",
}

// IsStunDomain 检查域名是否为 STUN 服务器
func IsStunDomain(domain string) bool {
	domain = strings.ToLower(domain)
	for _, d := range StunDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}
