package stats

import (
	"fmt"
	"github.com/getlantern/systray"
	"sync"
	"sync/atomic"
	"time"
	"wing/pkg/common"
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
	speedMu         sync.RWMutex
	CurrentSpeedIn  string = "0 B/s"
	CurrentSpeedOut string = "0 B/s"
)

func GetCurrentSpeeds() (in string, out string) {
	speedMu.RLock()
	defer speedMu.RUnlock()
	return CurrentSpeedIn, CurrentSpeedOut
}

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

		currentIn := formatSpeed(speedIn)
		currentOut := formatSpeed(speedOut)
		speedMu.Lock()
		CurrentSpeedIn = currentIn
		CurrentSpeedOut = currentOut
		speedMu.Unlock()

		if menuItem != nil {
			menuItem.SetTitle(fmt.Sprintf("🚀 实时网速: ↑ %s  ↓ %s", currentOut, currentIn))
		}

		lastIn = in
		lastOut = out
	}
}
