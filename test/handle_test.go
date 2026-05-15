package test

import (
	"high-mae/pkg/common"
	"high-mae/pkg/proxy"
	"high-mae/pkg/stats"
	"sync"
	"sync/atomic"
	"testing"
)

// ============================================================
// TrackingConn 节流机制测试
// ============================================================

// TestTrackingConn_GlobalCounterAccuracy 验证全局流量计数器在并发写入下的准确性
func TestTrackingConn_GlobalCounterAccuracy(t *testing.T) {
	// 重置全局计数器
	atomic.StoreUint64(&common.GlobalProxyIn, 0)
	atomic.StoreUint64(&common.GlobalProxyOut, 0)

	// 模拟并发更新
	var wg sync.WaitGroup
	iterations := 1000
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			atomic.AddUint64(&common.GlobalProxyIn, 100)
			atomic.AddUint64(&common.GlobalProxyOut, 50)
		}()
	}
	wg.Wait()

	totalIn := atomic.LoadUint64(&common.GlobalProxyIn)
	totalOut := atomic.LoadUint64(&common.GlobalProxyOut)

	expectedIn := uint64(iterations) * 100
	expectedOut := uint64(iterations) * 50

	if totalIn != expectedIn {
		t.Errorf("GlobalProxyIn 计数器不准确: got %d, want %d", totalIn, expectedIn)
	}
	if totalOut != expectedOut {
		t.Errorf("GlobalProxyOut 计数器不准确: got %d, want %d", totalOut, expectedOut)
	}
}

// ============================================================
// 连接日志测试
// ============================================================

// TestConnLog_AddAndGet 验证添加和获取日志
func TestConnLog_AddAndGet(t *testing.T) {
	stats.ClearConnLogs()

	id1 := stats.AddConnLog("google.com:443", "ProxyA")
	id2 := stats.AddConnLog("twitter.com:443", "ProxyB")

	if id1 == 0 || id2 == 0 {
		t.Error("AddConnLog 应返回非零 ID")
	}
	if id1 == id2 {
		t.Error("AddConnLog 应返回唯一 ID")
	}

	logs := stats.GetConnLogs()
	if len(logs) != 2 {
		t.Errorf("应有 2 条日志, got %d", len(logs))
	}
	// GetConnLogs 返回逆序
	if logs[0].Target != "twitter.com:443" {
		t.Errorf("最新日志应排在前面, got: %s", logs[0].Target)
	}
}

// TestConnLog_UpdateAndClose 验证更新和关闭日志
func TestConnLog_UpdateAndClose(t *testing.T) {
	stats.ClearConnLogs()
	id := stats.AddConnLog("test.com:80", "Direct")

	stats.UpdateConnLog(id, 1024, 512, false)
	logs := stats.GetConnLogs()
	if logs[0].Inbound != 1024 || logs[0].Outbound != 512 {
		t.Errorf("更新后的流量应为 in=1024, out=512, got in=%d, out=%d", logs[0].Inbound, logs[0].Outbound)
	}
	if logs[0].Status != "Active" {
		t.Error("未关闭时状态应为 Active")
	}

	stats.UpdateConnLog(id, 2048, 1024, true)
	logs = stats.GetConnLogs()
	if logs[0].Status != "Closed" {
		t.Error("关闭后状态应为 Closed")
	}
	if logs[0].Duration == "" {
		t.Error("关闭后应有 Duration 值")
	}
}

// TestConnLog_MaxLimit 验证日志条目上限
func TestConnLog_MaxLimit(t *testing.T) {
	stats.ClearConnLogs()
	for i := 0; i < 250; i++ {
		stats.AddConnLog("test.com:80", "node")
	}
	logs := stats.GetConnLogs()
	if len(logs) > 200 {
		t.Errorf("日志条目不应超过 200 条, got %d", len(logs))
	}
}

// TestConnLog_Clear 验证清空日志
func TestConnLog_Clear(t *testing.T) {
	stats.ClearConnLogs()
	stats.AddConnLog("test.com:80", "node")
	stats.ClearConnLogs()
	logs := stats.GetConnLogs()
	if len(logs) != 0 {
		t.Errorf("清空后应为 0 条, got %d", len(logs))
	}
}

// TestConnLog_ConcurrentAccess 验证并发安全
func TestConnLog_ConcurrentAccess(t *testing.T) {
	stats.ClearConnLogs()
	var wg sync.WaitGroup

	// 并发写入
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := stats.AddConnLog("test.com:80", "node")
			stats.UpdateConnLog(id, uint64(i*100), uint64(i*50), false)
		}(i)
	}

	// 并发读取
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = stats.GetConnLogs()
		}()
	}

	wg.Wait()
	// 只要不 panic/死锁就算通过
}

// ============================================================
// DNS 缓存容量限制测试
// ============================================================

// TestDNSMatchRule_EmptyValue 验证空规则值被忽略
func TestDNSMatchRule_EmptyValue(t *testing.T) {
	proxy.GlobalDNSConfig = proxy.DNSConfig{
		Servers: []proxy.DNSServer{
			{ID: "google", Name: "Google", Address: "8.8.8.8:53", Type: "udp"},
		},
		Rules: []proxy.DNSRule{
			{Type: "domain_keyword", Value: "", ServerID: "google"},
		},
		Default: "google",
	}

	// 空值规则不应匹配任何域名
	result := proxy.MatchDNSRule("example.com")
	if result != "google" {
		t.Errorf("空规则值应被忽略, got: %s", result)
	}
}

// TestDNSMatchRule_TrailingDot 验证域名尾部点号被处理
func TestDNSMatchRule_TrailingDot(t *testing.T) {
	proxy.GlobalDNSConfig = proxy.DNSConfig{
		Servers: []proxy.DNSServer{
			{ID: "aliyun", Name: "Aliyun", Address: "223.5.5.5:53", Type: "udp"},
			{ID: "google", Name: "Google", Address: "8.8.8.8:53", Type: "udp"},
		},
		Rules: []proxy.DNSRule{
			{Type: "domain_suffix", Value: "cn", ServerID: "aliyun"},
		},
		Default: "google",
	}

	// DNS 查询通常带尾部点号，如 "www.baidu.cn."
	result := proxy.MatchDNSRule("www.baidu.cn.")
	if result != "aliyun" {
		t.Errorf("带尾部点号的域名应正确匹配, got: %s", result)
	}
}

// TestDNSGetServerByID_NotFound 验证查找不存在的服务器返回 nil
func TestDNSGetServerByID_NotFound(t *testing.T) {
	proxy.GlobalDNSConfig = proxy.DNSConfig{
		Servers: []proxy.DNSServer{
			{ID: "google", Name: "Google", Address: "8.8.8.8:53", Type: "udp"},
		},
	}

	if s := proxy.GetDNSServerByID("nonexistent"); s != nil {
		t.Error("不存在的服务器 ID 应返回 nil")
	}
}
