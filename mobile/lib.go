//go:build android

package main

import (
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
	"wing/pkg/common"
	"wing/pkg/proxy"
	"wing/pkg/routing"
	"wing/pkg/stats"
	"wing/pkg/storage"
	"wing/pkg/sub"
	"wing/pkg/utils"
	"wing/pkg/webui"
)

func raiseAndroidFDLimit() {
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err != nil {
		return
	}
	target := uint64(8192)
	if rlim.Max > 0 && rlim.Max < target {
		target = rlim.Max
	}
	if rlim.Cur < target {
		rlim.Cur = target
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlim)
	}
}

func main() {
	debug.SetMemoryLimit(64 << 20)
	debug.SetGCPercent(20)
	raiseAndroidFDLimit()

	if err := storage.Init(); err != nil {
		log.Printf("[Android Core] storage.Init failed: %v", err)
		os.Exit(1)
	}

	_ = os.WriteFile("wing_backend.pid", []byte(strconv.Itoa(os.Getpid())), 0o600)
	defer os.Remove("wing_backend.pid")

	proxy.LoadSystemConfig()
	if err := webui.EnsureStartupState(); err != nil {
		log.Printf("[Android Core] EnsureStartupState error: %v", err)
	}
	routing.LoadUserRules()
	proxy.LoadDNSConfig()

	proxy.StartAnyTLSHttpServer()
	utils.SafeGo("local dns server", proxy.StartLocalDNS)
	utils.SafeGo("web ui server", webui.StartWebUI)
	utils.SafeGo("net speed monitor", func() { stats.StartNetSpeedMonitor(nil) })
	sub.StartAutoUpdateSubscriptions()
	proxy.StartAndroidTunListener()

	stopMemTrim := make(chan struct{})
	utils.SafeGo("android idle memory trim", func() {
		ticker := time.NewTicker(3 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if atomic.LoadInt32(&stats.ActiveConnections) == 0 {
					debug.FreeOSMemory()
				}
			case <-stopMemTrim:
				return
			}
		}
	})

	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	close(stopMemTrim)

	// Cleanup
	if common.GetTunModeOn() {
		proxy.StopTun()
		common.SetTunModeOn(false)
	}
	common.SetSystemProxyOn(false)
	_ = storage.Close()
}
