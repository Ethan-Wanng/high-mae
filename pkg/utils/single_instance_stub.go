//go:build !windows

package utils

func AcquireSingleInstanceLock() (bool, error) {
	return true, nil
}

func ReleaseSingleInstanceLock() {}
