package routing

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// ToggleWebRTCLeak 尝试通过修改 Windows 注册表策略来防止 WebRTC 真实 IP 泄露。
func ToggleWebRTCLeak(enable bool) {
	var script string

	if enable {
		script = `reg add HKLM\SOFTWARE\Policies\Google\Chrome /v WebRtcIPHandlingPolicy /t REG_SZ /d disable_non_proxied_udp /f; ` +
			`reg add HKCU\SOFTWARE\Policies\Google\Chrome /v WebRtcIPHandlingPolicy /t REG_SZ /d disable_non_proxied_udp /f; ` +
			`reg add HKLM\SOFTWARE\Policies\Microsoft\Edge /v WebRtcLocalhostIpHandling /t REG_SZ /d disable_non_proxied_udp /f; ` +
			`reg add HKCU\SOFTWARE\Policies\Microsoft\Edge /v WebRtcLocalhostIpHandling /t REG_SZ /d disable_non_proxied_udp /f`
	} else {
		script = `reg delete HKLM\SOFTWARE\Policies\Google\Chrome /v WebRtcIPHandlingPolicy /f; ` +
			`reg delete HKCU\SOFTWARE\Policies\Google\Chrome /v WebRtcIPHandlingPolicy /f; ` +
			`reg delete HKLM\SOFTWARE\Policies\Microsoft\Edge /v WebRtcLocalhostIpHandling /f; ` +
			`reg delete HKCU\SOFTWARE\Policies\Microsoft\Edge /v WebRtcLocalhostIpHandling /f`
	}

	// 使用单一 UAC 提示执行所有命令
	cmdStr := fmt.Sprintf(`Start-Process powershell -ArgumentList "-NoProfile -Command %s" -Verb RunAs -WindowStyle Hidden`, script)
	exec.Command("powershell", "-Command", cmdStr).Run()
}

// CheckWebRTCLeakStatus 检查是否已经启用了防 WebRTC 泄露
func CheckWebRTCLeakStatus() bool {
	chromeInstalled := isBrowserInstalled(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe`)
	edgeInstalled := isBrowserInstalled(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe`)

	chromeOk := !chromeInstalled
	if chromeInstalled {
		if regValueExists(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Google\Chrome`, "WebRtcIPHandlingPolicy") ||
			regValueExists(registry.CURRENT_USER, `SOFTWARE\Policies\Google\Chrome`, "WebRtcIPHandlingPolicy") {
			chromeOk = true
		}
	}

	edgeOk := !edgeInstalled
	if edgeInstalled {
		if regValueExists(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Edge`, "WebRtcLocalhostIpHandling") ||
			regValueExists(registry.CURRENT_USER, `SOFTWARE\Policies\Microsoft\Edge`, "WebRtcLocalhostIpHandling") {
			edgeOk = true
		}
	}

	return chromeOk && edgeOk
}

func isBrowserInstalled(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func regValueExists(root registry.Key, keyPath, valueName string) bool {
	k, err := registry.OpenKey(root, keyPath, registry.READ)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(valueName)
	return err == nil
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
	if host, _, found := strings.Cut(domain, ":"); found {
		domain = host
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if isStunLikeLabel(label) {
			return true
		}
	}
	for _, d := range StunDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func isStunLikeLabel(label string) bool {
	for _, prefix := range []string{"stun", "turn"} {
		if label == prefix {
			return true
		}
		if strings.HasPrefix(label, prefix) && len(label) > len(prefix) {
			next := label[len(prefix)]
			if next >= '0' && next <= '9' {
				return true
			}
		}
	}
	return false
}
