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
