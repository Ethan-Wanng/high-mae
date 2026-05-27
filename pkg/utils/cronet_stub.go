//go:build !windows
package utils

// EnsureCronetDll 在非 Windows 平台是空操作
func EnsureCronetDll() {}
