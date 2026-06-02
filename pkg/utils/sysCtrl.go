//go:build windows

package utils

import (
	"wing/pkg/common"

	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

func ShowWindowsMsgBox(title, message string) {
	if runtime.GOOS == "windows" {
		user32 := syscall.NewLazyDLL("user32.dll")
		messageBox := user32.NewProc("MessageBoxW")
		tPtr, _ := syscall.UTF16PtrFromString(title)
		mPtr, _ := syscall.UTF16PtrFromString(message)
		messageBox.Call(0, uintptr(unsafe.Pointer(mPtr)), uintptr(unsafe.Pointer(tPtr)), 0x40)
	}
}

func IsAdmin() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func SetSystemProxy(enable bool) {
	if runtime.GOOS != "windows" {
		return
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		fmt.Printf("⚠️ 无法打开注册表项: %v\n", err)
		return
	}
	defer k.Close()

	if enable {
		proxyStr := fmt.Sprintf("127.0.0.1:%s", common.LocalHttpPort)
		k.SetDWordValue("ProxyEnable", 1)
		k.SetStringValue("ProxyServer", proxyStr)
	} else {
		k.SetDWordValue("ProxyEnable", 0)
	}

	// 🚀 核心稳定性增强：通知 Windows 设置已变更，防止浏览器反应迟钝
	// INTERNET_OPTION_SETTINGS_CHANGED = 39
	// INTERNET_OPTION_REFRESH = 37
	wininet := syscall.NewLazyDLL("wininet.dll")
	setOption := wininet.NewProc("InternetSetOptionW")
	setOption.Call(0, 39, 0, 0)
	setOption.Call(0, 37, 0, 0)
}

func SetSystemDNS(enable bool, dnsIP string) {
	if runtime.GOOS != "windows" {
		return
	}
	if enable {
		// powershell -Command "Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses -ne $null} | Set-DnsClientServerAddress -ServerAddresses '127.0.0.2'"
		script := fmt.Sprintf(`Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceAlias -notmatch 'TUN'} | Set-DnsClientServerAddress -ServerAddresses '%s'`, dnsIP)
		cmdStr := fmt.Sprintf(`Start-Process powershell -ArgumentList "-NoProfile -Command %s" -Verb RunAs -WindowStyle Hidden`, script)
		exec.Command("powershell", "-Command", cmdStr).Run()
	} else {
		script := `Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceAlias -notmatch 'TUN'} | Set-DnsClientServerAddress -ResetServerAddresses`
		cmdStr := fmt.Sprintf(`Start-Process powershell -ArgumentList "-NoProfile -Command %s" -Verb RunAs -WindowStyle Hidden`, script)
		exec.Command("powershell", "-Command", cmdStr).Run()
	}
}

func GetDefaultGatewayAndIP() (gateway string, localIP string) {
	out, err := RunHiddenCommand("cmd", "/c", "route print 0.0.0.0")
	if err != nil {
		return "", ""
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "0.0.0.0" {
			gw := fields[2]
			ip := fields[3]
			// 只排除 wing 自己的 TUN 地址；真实局域网也可能使用 10.0.0.x。
			if ip != common.TunIP && gw != common.TunIP && ip != "10.0.0.2" && gw != "10.0.0.1" && ip != "172.19.0.1" {
				return gw, ip
			}
		}
	}
	return "", ""
}

func GetDefaultGateway() string {
	gw, _ := GetDefaultGatewayAndIP()
	return gw
}

func GetRealLocalIP() string {
	_, ip := GetDefaultGatewayAndIP()
	return ip
}

// RunHiddenCommand 运行命令并隐藏终端窗口
func RunHiddenCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Output()
}

// RestartAsAdmin 自动提权重启
func RestartAsAdmin() error {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 // SW_NORMAL
	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecute := shell32.NewProc("ShellExecuteW")

	ret, _, err := shellExecute.Call(0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(argPtr)),
		uintptr(unsafe.Pointer(cwdPtr)),
		uintptr(showCmd))

	if ret <= 32 {
		return fmt.Errorf("ShellExecute failed with code %d: %v", ret, err)
	}
	return nil
}
