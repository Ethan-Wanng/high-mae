//go:build !windows

package utils

import (
	"fmt"
	"os"
	"os/exec"
)

func ShowWindowsMsgBox(title, message string) {
	fmt.Printf("%s: %s\n", title, message)
}

func IsAdmin() bool {
	return os.Geteuid() == 0
}

func SetSystemProxy(enable bool) {}

func SetSystemDNS(enable bool, dnsIP string) {}

func GetDefaultGatewayAndIP() (gateway string, localIP string) {
	return "", ""
}

func GetDefaultGateway() string {
	return ""
}

func GetRealLocalIP() string {
	return ""
}

func RunHiddenCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func RestartAsAdmin() error {
	return fmt.Errorf("administrator restart is only supported on Windows")
}

func SetStartupEnabled(enable bool) error {
	return fmt.Errorf("startup setting is only supported on Windows")
}

func IsStartupEnabled() bool {
	return false
}
