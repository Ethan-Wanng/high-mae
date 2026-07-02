package stats

import (
	"testing"
	"time"
)

func TestGetHistory(t *testing.T) {
	ClearConnLogs()

	// Add mock logs
	id1 := AddConnLog("google.com", "US-Proxy")
	UpdateConnLog(id1, 100, 200, true)

	id2 := AddConnLog("baidu.com", "Direct")
	UpdateConnLog(id2, 50, 50, true)

	// Fetch history with the entire range
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)

	res := GetHistory(start, end)
	if len(res.Logs) != 2 {
		t.Errorf("Expected 2 logs, got %d", len(res.Logs))
	}

	if len(res.NodeTraffic) != 2 {
		t.Errorf("Expected 2 node traffic records, got %d", len(res.NodeTraffic))
	}

	// Verify US-Proxy stats
	var usProxyFound bool
	for _, traffic := range res.NodeTraffic {
		if traffic.Node == "US-Proxy" {
			usProxyFound = true
			if traffic.Inbound != 100 || traffic.Outbound != 200 || traffic.Total != 300 {
				t.Errorf("US-Proxy traffic statistics mismatch: %+v", traffic)
			}
		}
	}
	if !usProxyFound {
		t.Errorf("US-Proxy was not found in traffic results")
	}
}

func TestConnLogAccessorsReturnCopies(t *testing.T) {
	ClearConnLogs()
	id := AddConnLog("example.com", "node-a")
	UpdateConnLog(id, 1, 2, false)

	logs := GetConnLogs()
	if len(logs) != 1 {
		t.Fatalf("GetConnLogs() len = %d, want 1", len(logs))
	}
	logs[0].Target = "mutated"

	recent := GetRecentConnLogs(1)
	if len(recent) != 1 {
		t.Fatalf("GetRecentConnLogs() len = %d, want 1", len(recent))
	}
	if recent[0].Target != "example.com" {
		t.Fatalf("recent log target = %q, want original target", recent[0].Target)
	}
	recent[0].Target = "mutated-again"

	history := GetHistory(time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if len(history.Logs) != 1 {
		t.Fatalf("GetHistory() len = %d, want 1", len(history.Logs))
	}
	if history.Logs[0].Target != "example.com" {
		t.Fatalf("history log target = %q, want original target", history.Logs[0].Target)
	}
}
