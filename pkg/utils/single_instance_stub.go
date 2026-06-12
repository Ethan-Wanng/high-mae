//go:build !windows

package utils

import "time"

func AcquireSingleInstanceLock() (bool, error) {
	return true, nil
}

func AcquireSingleInstanceLockWithRetry(timeout time.Duration) (bool, error) {
	return AcquireSingleInstanceLock()
}

func RestartHandoffArg() string {
	return ""
}

func HasRestartHandoffArg() bool {
	return false
}

func StripRestartHandoffArgs(args []string) []string {
	return args
}

func ReleaseSingleInstanceLock() {}
