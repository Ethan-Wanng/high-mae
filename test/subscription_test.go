package test

import (
	"encoding/json"
	"high-mae/ins"
	"high-mae/protocol"
	"os"
	"strings"
	"testing"
)

// ============================================================
// Helper: 隔离文件系统副作用
// ============================================================
func setupTestDir(t *testing.T) func() {
	t.Helper()
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal("无法切换到临时目录:", err)
	}
	return func() { os.Chdir(origDir) }
}

// ============================================================
// 1. ReadSubscriptions
// ============================================================

func TestReadSubscriptions_FileNotExist(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	subs, err := ins.ReadSubscriptions()
	if err != nil {
		t.Fatalf("文件不存在时应返回空切片而非错误, got err=%v", err)
	}
	if len(subs) != 0 {
		t.Fatalf("期望空切片, got len=%d", len(subs))
	}
}

func TestReadSubscriptions_ValidJSON(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	data := `[{"name":"TestSub","url":"https://example.com/sub","file_name":"sub_1.yml"}]`
	os.WriteFile(ins.SubscriptionsFile, []byte(data), 0644)

	subs, err := ins.ReadSubscriptions()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("期望1条记录, got %d", len(subs))
	}
	if subs[0].Name != "TestSub" {
		t.Errorf("Name 不匹配, got %q", subs[0].Name)
	}
}

func TestReadSubscriptions_InvalidJSON(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	os.WriteFile(ins.SubscriptionsFile, []byte("{invalid_json}"), 0644)

	_, err := ins.ReadSubscriptions()
	if err == nil {
		t.Fatal("损坏的JSON应返回错误")
	}
}

// ============================================================
// 2. AppendSubscription
// ============================================================

func TestAppendSubscription_NewLink(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	fileName, existed, err := ins.AppendSubscription("https://example.com/subscribe")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if existed {
		t.Fatal("新链接不应标记为已存在")
	}
	if fileName != "sub_1.yml" {
		t.Errorf("期望 sub_1.yml, got %q", fileName)
	}

	subs, _ := ins.ReadSubscriptions()
	if len(subs) != 1 {
		t.Fatalf("期望1条记录, got %d", len(subs))
	}
	if subs[0].Name != "example.com" {
		t.Errorf("域名提取不正确, got %q", subs[0].Name)
	}
}

func TestAppendSubscription_DuplicateLink(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	url := "https://provider.com/api/sub"
	ins.AppendSubscription(url)

	fileName, existed, err := ins.AppendSubscription(url)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !existed {
		t.Fatal("重复链接应标记为已存在")
	}
	if fileName != "sub_1.yml" {
		t.Errorf("期望返回原文件名 sub_1.yml, got %q", fileName)
	}

	subs, _ := ins.ReadSubscriptions()
	if len(subs) != 1 {
		t.Fatalf("重复导入后应仍然只有1条, got %d", len(subs))
	}
}

func TestAppendSubscription_MultipleLinks(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	ins.AppendSubscription("https://a.com/sub")
	f2, _, _ := ins.AppendSubscription("https://b.com/sub")

	if f2 != "sub_2.yml" {
		t.Errorf("第二条链接应分配 sub_2.yml, got %q", f2)
	}

	subs, _ := ins.ReadSubscriptions()
	if len(subs) != 2 {
		t.Fatalf("期望2条记录, got %d", len(subs))
	}
}

func TestAppendSubscription_NameExtraction(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	tests := []struct {
		url      string
		wantName string
	}{
		{"https://api.proxy.com/subscribe?token=abc", "api.proxy.com"},
		{"http://fast-node.net/get/nodes", "fast-node.net"},
		{"no-scheme-link", "未知供应商"},
	}

	for i, tt := range tests {
		ins.AppendSubscription(tt.url)
		subs, _ := ins.ReadSubscriptions()
		if subs[i].Name != tt.wantName {
			t.Errorf("case %d: 期望Name=%q, got %q", i, tt.wantName, subs[i].Name)
		}
	}
}

// ============================================================
// 3. DeleteSubscription
// ============================================================

func TestDeleteSubscription_RemovesEntry(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	url1 := "https://a.com/sub"
	url2 := "https://b.com/sub"
	ins.AppendSubscription(url1)
	ins.AppendSubscription(url2)

	os.WriteFile("sub_1.yml", []byte("test"), 0644)

	ins.DeleteSubscription(url1)

	subs, _ := ins.ReadSubscriptions()
	if len(subs) != 1 {
		t.Fatalf("删除后应剩1条, got %d", len(subs))
	}
	if subs[0].URL != url2 {
		t.Errorf("剩余的应是第二条, got %q", subs[0].URL)
	}
	if _, err := os.Stat("sub_1.yml"); !os.IsNotExist(err) {
		t.Error("sub_1.yml 应已被删除")
	}
}

func TestDeleteSubscription_NonExistent(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	ins.AppendSubscription("https://keep.com/sub")
	ins.DeleteSubscription("https://nonexistent.com/sub")

	subs, _ := ins.ReadSubscriptions()
	if len(subs) != 1 {
		t.Fatalf("删除不存在的链接不应影响数据, got %d", len(subs))
	}
}

func TestDeleteSubscription_AllEntries(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	url := "https://only.com/sub"
	ins.AppendSubscription(url)
	ins.DeleteSubscription(url)

	subs, _ := ins.ReadSubscriptions()
	if len(subs) != 0 {
		t.Fatalf("全部删除后应为空, got %d", len(subs))
	}
}

// ============================================================
// 4. 订阅全生命周期集成测试
// ============================================================

func TestSubscriptionLifecycle(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	// 新增3个
	ins.AppendSubscription("https://provider-a.com/sub")
	ins.AppendSubscription("https://provider-b.com/sub")
	ins.AppendSubscription("https://provider-c.com/sub")
	subs, _ := ins.ReadSubscriptions()
	if len(subs) != 3 {
		t.Fatalf("新增3个后应有3条, got %d", len(subs))
	}

	// 重复导入
	_, existed, _ := ins.AppendSubscription("https://provider-a.com/sub")
	if !existed {
		t.Error("重复导入应标记为已存在")
	}
	subs, _ = ins.ReadSubscriptions()
	if len(subs) != 3 {
		t.Fatalf("重复导入后仍应是3条, got %d", len(subs))
	}

	// 删除 b
	ins.DeleteSubscription("https://provider-b.com/sub")
	subs, _ = ins.ReadSubscriptions()
	if len(subs) != 2 {
		t.Fatalf("删除一条后应剩2条, got %d", len(subs))
	}
	for _, s := range subs {
		if s.URL == "https://provider-b.com/sub" {
			t.Error("provider-b 应已被删除")
		}
	}

	// 删除剩余全部
	ins.DeleteSubscription("https://provider-a.com/sub")
	ins.DeleteSubscription("https://provider-c.com/sub")
	subs, _ = ins.ReadSubscriptions()
	if len(subs) != 0 {
		t.Fatalf("全部删除后应为空, got %d", len(subs))
	}
}

// ============================================================
// 5. JSON 格式验证
// ============================================================

func TestSubscriptionJSON_Format(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	ins.AppendSubscription("https://my-vpn.com/api/sub?token=xyz")

	data, err := os.ReadFile(ins.SubscriptionsFile)
	if err != nil {
		t.Fatalf("无法读取JSON文件: %v", err)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("输出不是合法的JSON数组: %v", err)
	}
	if !strings.Contains(string(data), "\n") {
		t.Error("JSON应是美化格式(含换行)")
	}
}

// ============================================================
// 6. SaveNodesToYAML + ParseNodes 往返
// ============================================================

func TestSaveNodesToYAML_TrojanRoundTrip(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	nodes := []protocol.Node{
		{Type: "trojan", Name: "JP-Trojan-01", Server: "jp.example.com", Port: 443, Password: "secret", SNI: "jp.example.com"},
	}
	if err := ins.SaveNodesToYAML("test.yml", nodes); err != nil {
		t.Fatalf("SaveNodesToYAML failed: %v", err)
	}

	parsed, err := protocol.ParseNodes("test.yml")
	if err != nil {
		t.Fatalf("ParseNodes failed: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("期望1个节点, got %d", len(parsed))
	}
	if parsed[0].Type != "trojan" || parsed[0].Name != "JP-Trojan-01" || parsed[0].Server != "jp.example.com" || parsed[0].Port != 443 {
		t.Errorf("字段不匹配: %+v", parsed[0])
	}
}

func TestSaveNodesToYAML_MultipleNodes(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	nodes := []protocol.Node{
		{Type: "vmess", Name: "Node-A", Server: "a.com", Port: 443, UUID: "uuid-a", Cipher: "auto"},
		{Type: "ss", Name: "Node-B", Server: "b.com", Port: 8388, Password: "pass-b", Method: "aes-256-gcm"},
	}
	if err := ins.SaveNodesToYAML("multi.yml", nodes); err != nil {
		t.Fatalf("SaveNodesToYAML failed: %v", err)
	}

	data, _ := os.ReadFile("multi.yml")
	if !strings.Contains(string(data), "---") {
		t.Error("多节点YAML应包含 --- 分隔符")
	}

	parsed, err := protocol.ParseNodes("multi.yml")
	if err != nil {
		t.Fatalf("ParseNodes failed: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("期望2个节点, got %d", len(parsed))
	}
}

func TestSaveNodesToYAML_Socks5(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	nodes := []protocol.Node{
		{Type: "socks5", Name: "HK-SOCKS", Server: "proxy.example.com", Port: 22881,
			Username: "user-id", Password: "pass-id", TLS: true, SNI: "proxy.example.com"},
	}
	if err := ins.SaveNodesToYAML("socks5.yml", nodes); err != nil {
		t.Fatalf("SaveNodesToYAML failed: %v", err)
	}

	data, _ := os.ReadFile("socks5.yml")
	content := string(data)
	for _, expect := range []string{"socks5", "username: user-id", "tls: true", "sni: proxy.example.com", "skip-cert-verify: false"} {
		if !strings.Contains(content, expect) {
			t.Errorf("YAML中缺少: %q", expect)
		}
	}
}

func TestSaveNodesToYAML_VlessWithWSOpts(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	nodes := []protocol.Node{
		{Type: "vless", Name: "VLESS-WS", Server: "vless.example.com", Port: 443,
			UUID: "some-uuid", TLS: true, Network: "ws", Flow: "xtls-rprx-vision",
			ClientFingerprint: "chrome",
			WSOpts:            protocol.WSOpts{Path: "/ws-path", Headers: map[string]string{"Host": "cdn.example.com"}}},
	}
	if err := ins.SaveNodesToYAML("vless.yml", nodes); err != nil {
		t.Fatalf("SaveNodesToYAML failed: %v", err)
	}

	data, _ := os.ReadFile("vless.yml")
	content := string(data)
	for _, expect := range []string{"vless", "uuid: some-uuid", "tls: true", "network: ws", "ws-opts:", "/ws-path", "flow: xtls-rprx-vision"} {
		if !strings.Contains(content, expect) {
			t.Errorf("YAML中缺少: %q", expect)
		}
	}
}

func TestSaveNodesToYAML_EmptyNodes(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	if err := ins.SaveNodesToYAML("empty.yml", []protocol.Node{}); err != nil {
		t.Fatalf("空节点列表应正常保存, got err: %v", err)
	}
	data, _ := os.ReadFile("empty.yml")
	if len(strings.TrimSpace(string(data))) != 0 {
		t.Error("空节点列表应生成空文件")
	}
}
