package stats

import (
	"sort"
	"sync"
	"time"
)

type ConnectionLog struct {
	ID        int64     `json:"id"`
	StartTime time.Time `json:"startTime"`
	EndTime   time.Time `json:"endTime,omitempty"`
	Duration  string    `json:"duration,omitempty"`
	Target    string    `json:"target"`
	Node      string    `json:"node"` // Node name or "Direct"
	Inbound   uint64    `json:"inbound"`
	Outbound  uint64    `json:"outbound"`
	Status    string    `json:"status"` // "Active", "Closed"
}

type NodeTrafficStats struct {
	Node     string `json:"node"`
	Inbound  uint64 `json:"inbound"`
	Outbound uint64 `json:"outbound"`
	Total    uint64 `json:"total"`
}

type HistoryResponse struct {
	Logs        []*ConnectionLog   `json:"logs"`
	NodeTraffic []NodeTrafficStats `json:"nodeTraffic"`
}

var (
	connLogs          []*ConnectionLog
	connMap           = make(map[int64]*ConnectionLog)
	connMu            sync.Mutex
	nextConnID        int64
	ActiveConnections int32
)

func AddConnLog(target, node string) int64 {
	connMu.Lock()
	defer connMu.Unlock()
	nextConnID++
	log := &ConnectionLog{
		ID:        nextConnID,
		StartTime: time.Now(),
		Target:    target,
		Node:      node,
		Status:    "Active",
	}
	connLogs = append(connLogs, log)
	if connMap == nil {
		connMap = make(map[int64]*ConnectionLog)
	}
	connMap[log.ID] = log
	// Keep last 5000 logs for history queries.
	// 🚀 修复 Go slice 内存泄漏：connLogs[1:] 只移动头指针，底层数组永远不被 GC 回收。
	// 改用 copy 缩容，让旧底层数组可以被 GC 释放。
	const maxLogs = 5000
	if len(connLogs) > maxLogs {
		removeCount := len(connLogs) - maxLogs
		for i := 0; i < removeCount; i++ {
			delete(connMap, connLogs[i].ID)
		}
		newLogs := make([]*ConnectionLog, maxLogs)
		copy(newLogs, connLogs[removeCount:])
		connLogs = newLogs
	}
	return log.ID
}

func UpdateConnLog(id int64, in, out uint64, closed bool) {
	connMu.Lock()
	defer connMu.Unlock()
	if connMap == nil {
		return
	}
	if l, exists := connMap[id]; exists {
		l.Inbound = in
		l.Outbound = out
		if closed {
			l.EndTime = time.Now()
			l.Duration = l.EndTime.Sub(l.StartTime).Round(time.Millisecond * 100).String()
			l.Status = "Closed"
		}
	}
}

func ClearConnLogs() {
	connMu.Lock()
	defer connMu.Unlock()
	connLogs = nil
	connMap = make(map[int64]*ConnectionLog)
}

func GetConnLogs() []*ConnectionLog {
	connMu.Lock()
	defer connMu.Unlock()
	// Return a copy in reverse order (newest first)
	n := len(connLogs)
	res := make([]*ConnectionLog, n)
	for i, l := range connLogs {
		res[n-1-i] = l
	}
	return res
}

// GetRecentConnLogs 返回最新的 limit 条日志（逆序），用于 Dashboard 实时面板。
// 避免每秒序列化全部数千条日志，大幅降低 JSON 编码的内存和 CPU 开销。
func GetRecentConnLogs(limit int) []*ConnectionLog {
	connMu.Lock()
	defer connMu.Unlock()
	n := len(connLogs)
	if limit > n {
		limit = n
	}
	res := make([]*ConnectionLog, limit)
	for i := 0; i < limit; i++ {
		res[i] = connLogs[n-1-i]
	}
	return res
}

func GetHistory(start, end time.Time) HistoryResponse {
	connMu.Lock()
	defer connMu.Unlock()

	var filteredLogs []*ConnectionLog
	trafficMap := make(map[string]*NodeTrafficStats)

	for _, l := range connLogs {
		// In range if its StartTime is before end, and (EndTime is zero or after start)
		inRange := l.StartTime.Before(end) && (l.EndTime.IsZero() || l.EndTime.After(start))
		if inRange {
			filteredLogs = append(filteredLogs, l)

			nodeName := l.Node
			if nodeName == "" {
				nodeName = "Direct"
			}
			t, exists := trafficMap[nodeName]
			if !exists {
				t = &NodeTrafficStats{Node: nodeName}
				trafficMap[nodeName] = t
			}
			t.Inbound += l.Inbound
			t.Outbound += l.Outbound
			t.Total += (l.Inbound + l.Outbound)
		}
	}

	var nodeTraffic []NodeTrafficStats
	for _, t := range trafficMap {
		nodeTraffic = append(nodeTraffic, *t)
	}

	sort.Slice(nodeTraffic, func(i, j int) bool {
		return nodeTraffic[i].Total > nodeTraffic[j].Total
	})

	n := len(filteredLogs)
	reversedLogs := make([]*ConnectionLog, n)
	for i, l := range filteredLogs {
		reversedLogs[n-1-i] = l
	}

	return HistoryResponse{
		Logs:        reversedLogs,
		NodeTraffic: nodeTraffic,
	}
}

