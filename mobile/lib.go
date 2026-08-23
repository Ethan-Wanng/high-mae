package main

import (
	"os"
	"os/signal"
	"syscall"
	"wing/pkg/common"
	"wing/pkg/proxy"
	"wing/pkg/routing"
	"wing/pkg/storage"
	"wing/pkg/sub"
	"wing/pkg/webui"
)

func main() {
	os.Setenv("GOMEMLIMIT", "150MiB")
	
	if err := storage.Init(); err != nil {
		return
	}

	proxy.LoadSystemConfig()
	webui.EnsureStartupState()
	routing.LoadUserRules()
	proxy.LoadDNSConfig()

	go proxy.StartLocalDNS()
	go webui.StartWebUI()
	go proxy.StartAnyTLSHttpServer()
	go sub.StartAutoUpdateSubscriptions()
	
	proxy.RestoreLastNetworkMode()

	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Cleanup
	proxy.SaveShutdownNetworkMode()
	if common.GetTunModeOn() {
		proxy.StopTun()
		common.SetTunModeOn(false)
	}
	common.SetSystemProxyOn(false)
	storage.Close()
}
