package stats

import (
	"fmt"
	"github.com/getlantern/systray"
	"high-mae/pkg/common"
	"sync/atomic"
	"time"
)

func getNetTraffic() (uint64, uint64) {
	in := atomic.LoadUint64(&common.GlobalProxyIn)
	out := atomic.LoadUint64(&common.GlobalProxyOut)
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
)

func StartNetSpeedMonitor(menuItem *systray.MenuItem) {
	var lastIn, lastOut uint64
	lastIn, lastOut = getNetTraffic()

	for {
		time.Sleep(1 * time.Second)
		in, out := getNetTraffic()

		speedIn := in - lastIn
		speedOut := out - lastOut

		if in < lastIn {
			speedIn = 0
		} // Handle wrap-around
		if out < lastOut {
			speedOut = 0
		}

		CurrentSpeedIn = formatSpeed(speedIn)
		CurrentSpeedOut = formatSpeed(speedOut)

		if menuItem != nil {
			menuItem.SetTitle(fmt.Sprintf("🚀 实时网速: ↑ %s  ↓ %s", CurrentSpeedOut, CurrentSpeedIn))
		}

		lastIn = in
		lastOut = out
	}
}
