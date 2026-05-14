package ins

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type ConnInfo struct {
	ID        int64     `json:"id"`
	Addr      string    `json:"addr"`
	Type      string    `json:"type"` // Direct, Proxy, TUN
	StartTime time.Time `json:"startTime"`
}

var (
	connIDCounter   int64
	activeConns     sync.Map // int64 -> *ConnInfo
	ConnHistory     []int64
)

func RegisterConn(addr string, connType string) int64 {
	id := atomic.AddInt64(&connIDCounter, 1)
	info := &ConnInfo{
		ID:        id,
		Addr:      addr,
		Type:      connType,
		StartTime: time.Now(),
	}
	activeConns.Store(id, info)
	return id
}

func UnregisterConn(id int64) {
	activeConns.Delete(id)
}

func GetActiveConns() []*ConnInfo {
	var list []*ConnInfo
	activeConns.Range(func(key, value interface{}) bool {
		list = append(list, value.(*ConnInfo))
		return true
	})
	return list
}

func GetMemUsage() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc
}

var (
	SpeedHistoryIn  []uint64
	SpeedHistoryOut []uint64
	MemHistory      []uint64
	historyMu       sync.Mutex
)

const MaxHistory = 60

func UpdateHistory(in, out, mem uint64) {
	historyMu.Lock()
	defer historyMu.Unlock()

	SpeedHistoryIn = append(SpeedHistoryIn, in)
	if len(SpeedHistoryIn) > MaxHistory {
		SpeedHistoryIn = SpeedHistoryIn[1:]
	}

	SpeedHistoryOut = append(SpeedHistoryOut, out)
	if len(SpeedHistoryOut) > MaxHistory {
		SpeedHistoryOut = SpeedHistoryOut[1:]
	}

	MemHistory = append(MemHistory, mem)
	if len(MemHistory) > MaxHistory {
		MemHistory = MemHistory[1:]
	}
}

func GetHistory() (in, out, mem []uint64) {
	historyMu.Lock()
	defer historyMu.Unlock()
	return SpeedHistoryIn, SpeedHistoryOut, MemHistory
}
