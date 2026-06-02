//go:build windows

package utils

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	getExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	TCP_TABLE_OWNER_PID_ALL = 5
)

// MIB_TCPROW_OWNER_PID structure
type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// GetPIDByLocalPort finds the PID that owns the given local TCP port
func GetPIDByLocalPort(port uint16) (uint32, error) {
	var size uint32
	// First call to get required size
	ret, _, _ := getExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1, // Sorted
		syscall.AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	// ERROR_INSUFFICIENT_BUFFER = 122
	if ret != 122 {
		return 0, fmt.Errorf("GetExtendedTcpTable failed to get size: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = getExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, // Sorted
		syscall.AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	if ret != 0 {
		return 0, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	// Number of entries is the first uint32
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))

	// Entries start after the count
	entrySize := unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*entrySize
		entry := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))

		// Port in table is in big endian (network byte order)
		tablePort := uint16(entry.LocalPort>>8) | (uint16(entry.LocalPort) << 8)
		if tablePort == port {
			return entry.OwningPid, nil
		}
	}

	return 0, fmt.Errorf("port %d not found in TCP table", port)
}

var (
	cmdlineCache   = make(map[uint32]string)
	cmdlineCacheMu sync.RWMutex
	cacheTTL       = 3 * time.Second
	lastCleanup    time.Time
)

// GetCommandLineByPID retrieves the process name and full command line of a PID with caching
func GetCommandLineByPID(pid uint32) (string, error) {
	if pid == 0 {
		return "", fmt.Errorf("invalid PID")
	}

	// Read cache
	cmdlineCacheMu.RLock()
	cmd, exists := cmdlineCache[pid]
	cmdlineCacheMu.RUnlock()
	if exists {
		return cmd, nil
	}

	// Fetch via PowerShell Get-CimInstance (highly compatible and stable on Windows).
	// HideWindow is required because this path can run for the first connection
	// of every new process when command-line routing is enabled.
	script := fmt.Sprintf("(Get-CimInstance Win32_Process -Filter 'ProcessId = %d').CommandLine", pid)
	out, err := runHiddenOutput("powershell", "-NoProfile", "-Command", script)
	if err != nil {
		// Fallback to Get-Process if Get-CimInstance fails
		scriptFallback := fmt.Sprintf("(Get-Process -Id %d).CommandLine", pid)
		out, err = runHiddenOutput("powershell", "-NoProfile", "-Command", scriptFallback)
		if err != nil {
			return "", err
		}
	}

	cmdline := strings.TrimSpace(string(out))

	// Write cache
	cmdlineCacheMu.Lock()
	if len(cmdlineCache) > 1000 { // Prevent unbounded growth
		cmdlineCache = make(map[uint32]string)
	}
	cmdlineCache[pid] = cmdline
	cmdlineCacheMu.Unlock()

	return cmdline, nil
}

// GetProcessCommandLineFromRemoteAddr parses a RemoteAddr string (e.g. "127.0.0.1:54321")
// and returns the process command line that opened the connection
func GetProcessCommandLineFromRemoteAddr(remoteAddr string) (string, error) {
	_, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return "", err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", err
	}

	pid, err := GetPIDByLocalPort(uint16(port))
	if err != nil {
		return "", err
	}

	return GetCommandLineByPID(pid)
}

func runHiddenOutput(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Output()
}
