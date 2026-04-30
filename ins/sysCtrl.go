package ins

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
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
	proxyStr := fmt.Sprintf("127.0.0.1:%s", LocalHttpPort)
	if enable {
		exec.Command("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f").Run()
		exec.Command("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxyStr, "/f").Run()
	} else {
		exec.Command("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f").Run()
	}
}

func GetDefaultGatewayAndIP() (gateway string, localIP string) {
	out, err := exec.Command("cmd", "/c", "route print 0.0.0.0").Output()
	if err != nil {
		return "", ""
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "0.0.0.0" {
			gw := fields[2]
			ip := fields[3]
			// 排除 TUN 的网关和 IP
			if gw != "10.0.0.1" && ip != "10.0.0.2" && !strings.HasPrefix(gw, "10.0.0.") {
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
