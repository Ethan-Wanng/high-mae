//go:build windows

package utils

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

var highMaeInstanceMutex windows.Handle

func AcquireSingleInstanceLock() (bool, error) {
	name, err := syscall.UTF16PtrFromString(`Local\wingSingleInstance`)
	if err != nil {
		return false, err
	}

	handle, err := windows.CreateMutex(nil, false, name)
	if handle == 0 {
		return false, fmt.Errorf("create mutex failed: %w", err)
	}
	if err == windows.ERROR_ALREADY_EXISTS {
		_ = windows.CloseHandle(handle)
		return false, nil
	}
	highMaeInstanceMutex = handle
	return true, nil
}

func ReleaseSingleInstanceLock() {
	if highMaeInstanceMutex == 0 {
		return
	}
	_, _, _ = syscall.SyscallN(
		windows.NewLazySystemDLL("kernel32.dll").NewProc("ReleaseMutex").Addr(),
		uintptr(highMaeInstanceMutex),
	)
	_ = windows.CloseHandle(highMaeInstanceMutex)
	highMaeInstanceMutex = 0
}
