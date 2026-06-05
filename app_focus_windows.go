//go:build windows

package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

func focusFlutterWindow(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}
	user32 := syscall.NewLazyDLL("user32.dll")
	enumWindows := user32.NewProc("EnumWindows")
	getWindowThreadProcessID := user32.NewProc("GetWindowThreadProcessId")
	isWindowVisible := user32.NewProc("IsWindowVisible")
	showWindow := user32.NewProc("ShowWindow")
	setForegroundWindow := user32.NewProc("SetForegroundWindow")

	targetPID := uint32(cmd.Process.Pid)
	var found uintptr
	cb := syscall.NewCallback(func(hwnd uintptr, lparam uintptr) uintptr {
		var pid uint32
		getWindowThreadProcessID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		visible, _, _ := isWindowVisible.Call(hwnd)
		if pid == targetPID && visible != 0 {
			found = hwnd
			return 0
		}
		return 1
	})
	enumWindows.Call(cb, 0)
	if found == 0 {
		return false
	}
	const swRestore = 9
	showWindow.Call(found, swRestore)
	setForegroundWindow.Call(found)
	return true
}
