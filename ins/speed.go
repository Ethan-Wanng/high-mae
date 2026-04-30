package ins

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
	"github.com/getlantern/systray"
)

type MIB_IFROW struct {
	wszName           [256]uint16
	dwIndex           uint32
	dwType            uint32
	dwMtu             uint32
	dwSpeed           uint32
	dwPhysAddrLen     uint32
	bPhysAddr         [8]byte
	dwAdminStatus     uint32
	dwOperStatus      uint32
	dwLastChange      uint32
	dwInOctets        uint32
	dwInUcastPkts     uint32
	dwInNUcastPkts    uint32
	dwInDiscards      uint32
	dwInErrors        uint32
	dwInUnknownProtos uint32
	dwOutOctets       uint32
	dwOutUcastPkts    uint32
	dwOutNUcastPkts   uint32
	dwOutDiscards     uint32
	dwOutErrors       uint32
	dwOutQLen         uint32
	dwDescrLen        uint32
	bDescr            [256]byte
}

var (
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIfTable = modiphlpapi.NewProc("GetIfTable")
)

// trafficBuf 持久化缓冲区，避免每秒 GC 抖动
var trafficBuf []byte

func getNetTraffic() (uint64, uint64) {
	var bufLen uint32
	procGetIfTable.Call(0, uintptr(unsafe.Pointer(&bufLen)), 0)
	if bufLen == 0 {
		return 0, 0
	}
	// 只在需要更大空间时重新分配
	if int(bufLen) > len(trafficBuf) {
		trafficBuf = make([]byte, bufLen)
	}
	buf := trafficBuf[:bufLen]
	ret, _, _ := procGetIfTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufLen)), 0)
	if ret != 0 {
		return 0, 0
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	var totalIn, totalOut uint64
	offset := uint32(4)
	rowSize := uint32(unsafe.Sizeof(MIB_IFROW{}))

	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_IFROW)(unsafe.Pointer(&buf[offset+i*rowSize]))
		// Filter software loopback (dwType == 24) to show only actual network traffic
		if row.dwType != 24 {
			totalIn += uint64(row.dwInOctets)
			totalOut += uint64(row.dwOutOctets)
		}
	}
	return totalIn, totalOut
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
		
		if in < lastIn { speedIn = 0 } // Handle wrap-around
		if out < lastOut { speedOut = 0 }

		CurrentSpeedIn = formatSpeed(speedIn)
		CurrentSpeedOut = formatSpeed(speedOut)

		if menuItem != nil {
			menuItem.SetTitle(fmt.Sprintf("🚀 实时网速: ↑ %s  ↓ %s", CurrentSpeedOut, CurrentSpeedIn))
		}

		lastIn = in
		lastOut = out
	}
}

