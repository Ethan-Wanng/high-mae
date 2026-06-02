//go:build !windows

package utils

import "fmt"

func GetPIDByLocalPort(port uint16) (uint32, error) {
	return 0, fmt.Errorf("process lookup by local port is only supported on Windows")
}

func GetCommandLineByPID(pid uint32) (string, error) {
	return "", fmt.Errorf("process command line lookup is only supported on Windows")
}

func GetProcessCommandLineFromRemoteAddr(remoteAddr string) (string, error) {
	return "", fmt.Errorf("process command line routing is only supported on Windows")
}
