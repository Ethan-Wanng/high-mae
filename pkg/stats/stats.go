package stats

import (
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

var (
	connLogs          []*ConnectionLog
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
	// Keep last 200 logs for professional view
	if len(connLogs) > 200 {
		connLogs = connLogs[1:]
	}
	return log.ID
}

func UpdateConnLog(id int64, in, out uint64, closed bool) {
	connMu.Lock()
	defer connMu.Unlock()
	for _, l := range connLogs {
		if l.ID == id {
			l.Inbound = in
			l.Outbound = out
			if closed {
				l.EndTime = time.Now()
				l.Duration = l.EndTime.Sub(l.StartTime).Round(time.Millisecond * 100).String()
				l.Status = "Closed"
			}
			break
		}
	}
}

func ClearConnLogs() {
	connMu.Lock()
	defer connMu.Unlock()
	connLogs = nil
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
