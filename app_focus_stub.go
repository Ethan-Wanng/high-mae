//go:build !windows

package main

import "os/exec"

func focusFlutterWindow(_ *exec.Cmd) bool {
	return false
}
