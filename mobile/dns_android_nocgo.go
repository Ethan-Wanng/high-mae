//go:build android && !cgo

package main

import (
	"os"
	"wing/pkg/proxy"
)

func configureAndroidDNS() {
	proxy.ConfigureAndroidFallbackResolver(os.Getenv(proxy.AndroidDNSServersEnv))
}
