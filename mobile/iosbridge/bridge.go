// Package iosbridge exposes the wing control core to the native iOS process.
// It is compiled into WingCore.xcframework with gomobile.
package iosbridge

import (
	"os"
	"path/filepath"
	"sync"
	"wing/pkg/proxy"
	"wing/pkg/routing"
	"wing/pkg/storage"
	"wing/pkg/sub"
	"wing/pkg/webui"
)

var (
	startOnce sync.Once
	startErr  error
)

// Start initializes the local API and proxy core once. It returns an empty
// string on success so the generated Objective-C/Swift binding stays simple.
func Start(dataDir, token string) string {
	startOnce.Do(func() {
		_ = os.Setenv("WING_DB_PATH", filepath.Join(dataDir, "wing.db"))
		_ = os.Setenv("WING_MOBILE_API_TOKEN", token)
		if err := storage.Init(); err != nil {
			startErr = err
			return
		}
		proxy.LoadSystemConfig()
		if err := webui.EnsureStartupState(); err != nil {
			startErr = err
			return
		}
		routing.LoadUserRules()
		proxy.LoadDNSConfig()
		go proxy.StartLocalDNS()
		go webui.StartWebUI()
		go proxy.StartAnyTLSHttpServer()
		go sub.StartAutoUpdateSubscriptions()
	})
	if startErr != nil {
		return startErr.Error()
	}
	return ""
}
