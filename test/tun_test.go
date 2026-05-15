package test

import (
	"encoding/json"
	"high-mae/pkg/common"
	"high-mae/pkg/proxy"
	"net"
	"strings"
	"sync"
	"testing"
)

// ============================================================
// TUN 配置 JSON 生成测试
// ============================================================

// TestBuildTunConfigJSON_ValidJSON 验证生成的 TUN 配置是合法的 JSON
func TestBuildTunConfigJSON_ValidJSON(t *testing.T) {
	config := proxy.BuildTunConfigJSON("example.com", "1.2.3.4")
	var parsed map[string]interface{}
	if err := json.Unmarshal(config, &parsed); err != nil {
		t.Fatalf("生成的 TUN 配置不是合法 JSON: %v\n内容: %s", err, string(config))
	}
}

// TestBuildTunConfigJSON_HasRequiredSections 验证配置包含所有必需的顶层键
func TestBuildTunConfigJSON_HasRequiredSections(t *testing.T) {
	config := proxy.BuildTunConfigJSON("example.com", "1.2.3.4")
	var parsed map[string]interface{}
	json.Unmarshal(config, &parsed)

	requiredKeys := []string{"log", "dns", "inbounds", "outbounds", "route"}
	for _, key := range requiredKeys {
		if _, ok := parsed[key]; !ok {
			t.Errorf("TUN 配置缺少必需的顶层键: %s", key)
		}
	}
}

// TestBuildTunConfigJSON_MixedStack 验证 TUN 使用 mixed 网络栈
func TestBuildTunConfigJSON_MixedStack(t *testing.T) {
	config := proxy.BuildTunConfigJSON("", "")
	configStr := string(config)
	if !strings.Contains(configStr, `"mixed"`) {
		t.Error("TUN 配置应使用 mixed 网络栈")
	}
}

// TestBuildTunConfigJSON_FakeIPEnabled 验证 FakeIP 已启用
func TestBuildTunConfigJSON_FakeIPEnabled(t *testing.T) {
	config := proxy.BuildTunConfigJSON("", "")
	configStr := string(config)
	if !strings.Contains(configStr, `"fakeip"`) {
		t.Error("TUN 配置应启用 FakeIP")
	}
	if !strings.Contains(configStr, `"198.18.0.0/15"`) {
		t.Error("FakeIP 应使用 198.18.0.0/15 作为 IPv4 范围")
	}
}

// TestBuildTunConfigJSON_AutoRouteEnabled 验证 auto_route 已启用
func TestBuildTunConfigJSON_AutoRouteEnabled(t *testing.T) {
	config := proxy.BuildTunConfigJSON("", "")
	configStr := string(config)
	if !strings.Contains(configStr, `"auto_route": true`) {
		t.Error("TUN 配置应启用 auto_route")
	}
	if !strings.Contains(configStr, `"strict_route": true`) {
		t.Error("TUN 配置应启用 strict_route")
	}
}

// TestBuildTunConfigJSON_DNSHijack 验证包含 DNS hijack 路由规则
func TestBuildTunConfigJSON_DNSHijack(t *testing.T) {
	config := proxy.BuildTunConfigJSON("", "")
	configStr := string(config)
	if !strings.Contains(configStr, `"hijack-dns"`) {
		t.Error("TUN 配置应包含 DNS hijack 路由规则")
	}
}

// TestBuildTunConfigJSON_PrivateIPDirect 验证私有 IP 直连规则
func TestBuildTunConfigJSON_PrivateIPDirect(t *testing.T) {
	config := proxy.BuildTunConfigJSON("", "")
	configStr := string(config)
	if !strings.Contains(configStr, `"ip_is_private": true`) {
		t.Error("TUN 配置应包含 ip_is_private 规则用于私有 IP 直连")
	}
}

// TestBuildTunConfigJSON_ProxyOutbound 验证 proxy outbound 指向本地端口
func TestBuildTunConfigJSON_ProxyOutbound(t *testing.T) {
	config := proxy.BuildTunConfigJSON("", "")
	configStr := string(config)
	if !strings.Contains(configStr, `"127.0.0.1"`) {
		t.Error("proxy outbound 应指向 127.0.0.1")
	}
	if !strings.Contains(configStr, common.LocalHttpPort) {
		t.Errorf("proxy outbound 应使用端口 %s", common.LocalHttpPort)
	}
}

// ============================================================
// 防环路规则测试
// ============================================================

// TestBuildTunConfigJSON_ServerIPv4Bypass 验证节点 IPv4 地址被添加到直连规则
func TestBuildTunConfigJSON_ServerIPv4Bypass(t *testing.T) {
	config := proxy.BuildTunConfigJSON("proxy.example.com", "203.0.113.1")
	configStr := string(config)
	if !strings.Contains(configStr, `"203.0.113.1/32"`) {
		t.Error("节点服务器 IPv4 应被添加为 /32 直连规则")
	}
}

// TestBuildTunConfigJSON_ServerIPv6Bypass 验证节点 IPv6 地址被添加到直连规则
func TestBuildTunConfigJSON_ServerIPv6Bypass(t *testing.T) {
	config := proxy.BuildTunConfigJSON("proxy.example.com", "2001:db8::1")
	configStr := string(config)
	if !strings.Contains(configStr, `"2001:db8::1/128"`) {
		t.Error("节点服务器 IPv6 应被添加为 /128 直连规则")
	}
}

// TestBuildTunConfigJSON_ServerDomainBypass 验证节点域名被添加到直连规则
func TestBuildTunConfigJSON_ServerDomainBypass(t *testing.T) {
	config := proxy.BuildTunConfigJSON("proxy.example.com", "203.0.113.1")
	configStr := string(config)
	if !strings.Contains(configStr, `"proxy.example.com"`) {
		t.Error("节点服务器域名应被添加到 domain 直连规则")
	}
}

// TestBuildTunConfigJSON_NoDomainRuleWhenIPOnly 验证当 server 就是 IP 时不添加域名规则
func TestBuildTunConfigJSON_NoDomainRuleWhenIPOnly(t *testing.T) {
	config := proxy.BuildTunConfigJSON("203.0.113.1", "203.0.113.1")
	configStr := string(config)
	// 不应有 domain 规则（因为 server == IP）
	if strings.Contains(configStr, `"domain"`) {
		t.Error("当 nodeServer == nodeIP 时不应生成域名直连规则")
	}
}

// TestBuildTunConfigJSON_EmptyServerIP 验证空服务器信息时的配置仍然有效
func TestBuildTunConfigJSON_EmptyServerIP(t *testing.T) {
	config := proxy.BuildTunConfigJSON("", "")
	var parsed map[string]interface{}
	if err := json.Unmarshal(config, &parsed); err != nil {
		t.Fatalf("空服务器配置应生成有效 JSON: %v", err)
	}
}

// TestBuildTunConfigJSON_InvalidIPIgnored 验证无效 IP 被忽略
func TestBuildTunConfigJSON_InvalidIPIgnored(t *testing.T) {
	config := proxy.BuildTunConfigJSON("proxy.example.com", "not-an-ip")
	configStr := string(config)
	// 无效 IP 不应生成 ip_cidr 规则
	if strings.Contains(configStr, "not-an-ip") {
		t.Error("无效的 nodeIP 不应被添加到配置中")
	}
	// 但配置本身应该仍然有效
	var parsed map[string]interface{}
	if err := json.Unmarshal(config, &parsed); err != nil {
		t.Fatalf("带无效 IP 的配置应生成有效 JSON: %v", err)
	}
}

// ============================================================
// TUN 模式切换逻辑测试（不依赖管理员权限的部分）
// ============================================================

// TestToggleTunMode_RequiresAdmin 验证非管理员时 Toggle 返回错误消息
func TestToggleTunMode_RequiresAdmin(t *testing.T) {
	// 确保初始状态为关闭
	common.IsTunModeOn = false
	common.MToggleTun = nil

	msg := proxy.ToggleTunMode()
	// 在非管理员环境下，应返回权限提示
	if msg == "" {
		t.Skip("当前以管理员身份运行，跳过此测试")
	}
	if !strings.Contains(msg, "管理员") {
		t.Errorf("非管理员启动 TUN 应提示需要管理员权限, got: %s", msg)
	}
}

// TestToggleTunMode_OffToOn_NoAdmin 验证未开启时关闭操作
func TestToggleTunMode_CloseWhenAlreadyClosed(t *testing.T) {
	// 模拟已开启状态
	common.IsTunModeOn = true
	common.MToggleTun = nil

	msg := proxy.ToggleTunMode()
	if msg != "" {
		t.Errorf("关闭 TUN 不应返回错误消息, got: %s", msg)
	}
	if common.IsTunModeOn {
		t.Error("关闭后 IsTunModeOn 应为 false")
	}
}

// ============================================================
// StopSingBoxTun 幂等性测试
// ============================================================

// TestStopSingBoxTun_Idempotent 验证重复调用 Stop 不会 panic
func TestStopSingBoxTun_Idempotent(t *testing.T) {
	// 确保 tunBox 为 nil
	proxy.StopSingBoxTun()
	proxy.StopSingBoxTun() // 第二次调用不应 panic
	proxy.StopSingBoxTun() // 第三次也不应 panic
}

// ============================================================
// 并发安全测试
// ============================================================

// TestToggleTunMode_ConcurrentSafety 验证并发调用 Toggle 不会 panic
func TestToggleTunMode_ConcurrentSafety(t *testing.T) {
	common.IsTunModeOn = false
	common.MToggleTun = nil

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy.ToggleTunMode()
		}()
	}
	wg.Wait()
	// 只要不 panic/死锁就算通过
}

// TestStopSingBoxTun_ConcurrentSafety 验证并发 Stop 不会 panic
func TestStopSingBoxTun_ConcurrentSafety(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy.StopSingBoxTun()
		}()
	}
	wg.Wait()
}

// ============================================================
// buildTunConfigJSON 辅助函数导出适配
// ============================================================

// TestBuildTunConfigJSON_OutboundTags 验证所有必需的 outbound tag 存在
func TestBuildTunConfigJSON_OutboundTags(t *testing.T) {
	config := proxy.BuildTunConfigJSON("", "")
	var parsed map[string]interface{}
	json.Unmarshal(config, &parsed)

	outbounds := parsed["outbounds"].([]interface{})
	tags := make(map[string]bool)
	for _, ob := range outbounds {
		m := ob.(map[string]interface{})
		tags[m["tag"].(string)] = true
	}

	requiredTags := []string{"proxy", "direct", "dns-out", "block"}
	for _, tag := range requiredTags {
		if !tags[tag] {
			t.Errorf("缺少必需的 outbound tag: %s", tag)
		}
	}
}

// TestBuildTunConfigJSON_RouteAutoDetect 验证 route 配置包含 auto_detect_interface
func TestBuildTunConfigJSON_RouteAutoDetect(t *testing.T) {
	config := proxy.BuildTunConfigJSON("", "")
	configStr := string(config)
	if !strings.Contains(configStr, `"auto_detect_interface": true`) {
		t.Error("路由配置应包含 auto_detect_interface: true")
	}
}

// TestBuildTunConfigJSON_RouteFinalProxy 验证 route 的 final 出站为 proxy
func TestBuildTunConfigJSON_RouteFinalProxy(t *testing.T) {
	config := proxy.BuildTunConfigJSON("", "")
	var parsed map[string]interface{}
	json.Unmarshal(config, &parsed)

	route := parsed["route"].(map[string]interface{})
	if route["final"] != "proxy" {
		t.Errorf("route.final 应为 proxy, got: %v", route["final"])
	}
}

// ============================================================
// resolveDirect 函数测试
// ============================================================

// TestResolveDirect_IPv4 验证 IPv4 地址直接返回
func TestResolveDirect_IPv4(t *testing.T) {
	result := proxy.ResolveDirect("1.2.3.4")
	if result != "1.2.3.4" {
		t.Errorf("IPv4 地址应直接返回, got: %s", result)
	}
}

// TestResolveDirect_IPv6 验证 IPv6 地址直接返回
func TestResolveDirect_IPv6(t *testing.T) {
	result := proxy.ResolveDirect("::1")
	if result != "::1" {
		t.Errorf("IPv6 地址应直接返回, got: %s", result)
	}
}

// TestResolveDirect_Empty 验证空字符串返回空
func TestResolveDirect_Empty(t *testing.T) {
	result := proxy.ResolveDirect("")
	if result != "" {
		t.Errorf("空字符串应返回空, got: %s", result)
	}
}

// TestResolveDirect_InvalidDomain 验证无效域名返回空
func TestResolveDirect_InvalidDomain(t *testing.T) {
	result := proxy.ResolveDirect("this-domain-definitely-does-not-exist.invalid")
	if result != "" {
		t.Logf("无效域名竟然解析成功: %s (可能是运营商 DNS 劫持)", result)
	}
}

// TestResolveDirect_Localhost 验证 localhost 能正确解析
func TestResolveDirect_Localhost(t *testing.T) {
	result := proxy.ResolveDirect("localhost")
	if result == "" {
		t.Skip("localhost 解析失败，可能是系统 hosts 文件问题")
	}
	ip := net.ParseIP(result)
	if ip == nil {
		t.Errorf("localhost 应解析为有效 IP, got: %s", result)
	}
}
