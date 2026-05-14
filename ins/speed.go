package ins

import (
	"fmt"
	"sync/atomic"
	"time"
	"github.com/getlantern/systray"
)

var (
	GlobalProxyIn  uint64
	GlobalProxyOut uint64
)

func getNetTraffic() (uint64, uint64) {
	in := atomic.LoadUint64(&GlobalProxyIn)
	out := atomic.LoadUint64(&GlobalProxyOut)
	return in, out
}

func formatSpeed(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B/s", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.2f MB/s", float64(bytes)/1024/1024)
}

var (
	CurrentSpeedIn  string = "0 B/s"
	CurrentSpeedOut string = "0 B/s"
	RawSpeedIn      uint64
	RawSpeedOut     uint64
)

func StartNetSpeedMonitor(menuItem *systray.MenuItem) {
	var lastIn, lastOut uint64
	lastIn, lastOut = getNetTraffic()

	for {
		time.Sleep(1 * time.Second)
		in, out := getNetTraffic()
		
		speedIn := in - lastIn
		speedOut := out - lastOut
		
		if in < lastIn { speedIn = 0 } // Handle wrap-around
		if out < lastOut { speedOut = 0 }

		RawSpeedIn = speedIn
		RawSpeedOut = speedOut
		CurrentSpeedIn = formatSpeed(speedIn)
		CurrentSpeedOut = formatSpeed(speedOut)

		// Update total traffic
		atomic.AddUint64(&GlobalTotalIn, speedIn)
		atomic.AddUint64(&GlobalTotalOut, speedOut)

		// Update history for dashboard
		UpdateHistory(speedIn, speedOut, GetMemUsage())

		if menuItem != nil {
			menuItem.SetTitle(fmt.Sprintf("🚀 实时网速: ↑ %s  ↓ %s", CurrentSpeedOut, CurrentSpeedIn))
		}

		lastIn = in
		lastOut = out
	}
}

