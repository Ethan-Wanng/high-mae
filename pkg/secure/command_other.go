//go:build !windows

package secure

import "os/exec"

func runMachineIDCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}
