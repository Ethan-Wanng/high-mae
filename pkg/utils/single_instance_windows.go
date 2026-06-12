//go:build windows

package utils

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

var highMaeInstanceMutex windows.Handle

const restartFromPIDArgPrefix = "--wing-restart-from-pid="

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

func AcquireSingleInstanceLockWithRetry(timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		locked, err := AcquireSingleInstanceLock()
		if locked || err != nil || time.Now().After(deadline) {
			return locked, err
		}
		time.Sleep(120 * time.Millisecond)
	}
}

func RestartHandoffArg() string {
	return restartFromPIDArgPrefix + strconv.Itoa(os.Getpid())
}

func HasRestartHandoffArg() bool {
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, restartFromPIDArgPrefix) {
			return true
		}
	}
	return false
}

func StripRestartHandoffArgs(args []string) []string {
	filtered := args[:0]
	for _, arg := range args {
		if !strings.HasPrefix(arg, restartFromPIDArgPrefix) {
			filtered = append(filtered, arg)
		}
	}
	return filtered
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
