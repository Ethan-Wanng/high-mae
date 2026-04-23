package test

import (
	"encoding/base64"
	"encoding/json"
	"high-mae/protocol"
	"os"
	"strings"
	"testing"
)

// ============================================================
// 1. ParseTrojan
// ============================================================

func TestParseTrojan_Basic(t *testing.T) {
	link := "trojan://my-password@trojan.example.com:443?sni=trojan.example.com#JP-Trojan-Node"
	n, err := protocol.ParseTrojan(link)
	if err != nil {
		t.Fatalf("ParseTrojan failed: %v", err)
	}
	if n.Type != "trojan" {
		t.Errorf("Type: want trojan, got %q", n.Type)
	}
	if n.Name != "JP-Trojan-Node" {
		t.Errorf("Name: want JP-Trojan-Node, got %q", n.Name)
	}
	if n.Server != "trojan.example.com" {
		t.Errorf("Server: got %q", n.Server)
	}
	if n.Port != 443 {
		t.Errorf("Port: want 443, got %d", n.Port)
	}
	if n.Password != "my-password" {
		t.Errorf("Password: got %q", n.Password)
	}
	if n.SNI != "trojan.example.com" {
		t.Errorf("SNI: got %q", n.SNI)
	}
}

func TestParseTrojan_DefaultPort(t *testing.T) {
	link := "trojan://pass@host.com#name"
	n, err := protocol.ParseTrojan(link)
	if err != nil {
		t.Fatalf("ParseTrojan failed: %v", err)
	}
	if n.Port != 443 {
		t.Errorf("默认端口应为443, got %d", n.Port)
	}
}

func TestParseTrojan_InsecureFlag(t *testing.T) {
	link := "trojan://pass@host.com:443?allowInsecure=1#insecure-node"
	n, _ := protocol.ParseTrojan(link)
	if !n.SkipCertVerify {
		t.Error("allowInsecure=1 时 SkipCertVerify 应为 true")
	}
}

// ============================================================
// 2. ParseAnyTLS
// ============================================================

func TestParseAnyTLS_Basic(t *testing.T) {
	link := "anytls://my-pass@atls.example.com:4430?sni=cdn.example.com#AnyTLS-Node"
	n, err := protocol.ParseAnyTLS(link)
	if err != nil {
		t.Fatalf("ParseAnyTLS failed: %v", err)
	}
	if n.Type != "anytls" {
		t.Errorf("Type: got %q", n.Type)
	}
	if n.Password != "my-pass" {
		t.Errorf("Password: got %q", n.Password)
	}
	if n.SNI != "cdn.example.com" {
		t.Errorf("SNI: got %q", n.SNI)
	}
	if n.ClientFingerprint != "firefox" {
		t.Errorf("ClientFingerprint 默认应为 firefox, got %q", n.ClientFingerprint)
	}
	if !n.SkipCertVerify {
		t.Error("AnyTLS 默认应跳过证书验证")
	}
	if !n.UDP || !n.TFO {
		t.Error("AnyTLS 应启用 UDP 和 TFO")
	}
}

func TestParseAnyTLS_SkipCertFalse(t *testing.T) {
	link := "anytls://pass@host.com:4430?skip_cert_verify=false#name"
	n, _ := protocol.ParseAnyTLS(link)
	if n.SkipCertVerify {
		t.Error("明确设置 skip_cert_verify=false 时应为 false")
	}
}

func TestParseAnyTLS_DefaultPort(t *testing.T) {
	link := "anytls://pass@host.com#name"
	n, _ := protocol.ParseAnyTLS(link)
	if n.Port != 4430 {
		t.Errorf("AnyTLS 默认端口应为4430, got %d", n.Port)
	}
}

// ============================================================
// 3. ParseVMess
// ============================================================

func TestParseVMess_Basic(t *testing.T) {
	vmessJSON := map[string]any{
		"v":    "2",
		"ps":   "VMess-WS-Node",
		"add":  "vmess.example.com",
		"port": 443,
		"id":   "test-uuid-1234",
		"aid":  0,
		"scy":  "auto",
		"net":  "ws",
		"host": "cdn.example.com",
		"path": "/vmess-ws",
		"tls":  "tls",
		"sni":  "vmess.example.com",
	}
	data, _ := json.Marshal(vmessJSON)
	link := "vmess://" + base64.StdEncoding.EncodeToString(data)

	n, err := protocol.ParseVMess(link)
	if err != nil {
		t.Fatalf("ParseVMess failed: %v", err)
	}
	if n.Type != "vmess" {
		t.Errorf("Type: got %q", n.Type)
	}
	if n.Name != "VMess-WS-Node" {
		t.Errorf("Name: got %q", n.Name)
	}
	if n.UUID != "test-uuid-1234" {
		t.Errorf("UUID: got %q", n.UUID)
	}
	if n.Port != 443 {
		t.Errorf("Port: got %d", n.Port)
	}
	if n.Network != "ws" {
		t.Errorf("Network: got %q", n.Network)
	}
	if n.Host != "cdn.example.com" {
		t.Errorf("Host: got %q", n.Host)
	}
	if n.WSOpts.Path != "/vmess-ws" {
		t.Errorf("WSOpts.Path: got %q", n.WSOpts.Path)
	}
	if !n.Tls {
		t.Error("tls 应为 true")
	}
}

func TestParseVMess_PortAsString(t *testing.T) {
	vmessJSON := map[string]any{
		"v": "2", "ps": "test", "add": "a.com", "port": "8080",
		"id": "uuid", "aid": "0", "scy": "auto", "net": "tcp", "tls": "",
	}
	data, _ := json.Marshal(vmessJSON)
	link := "vmess://" + base64.StdEncoding.EncodeToString(data)

	n, err := protocol.ParseVMess(link)
	if err != nil {
		t.Fatalf("ParseVMess with string port failed: %v", err)
	}
	if n.Port != 8080 {
		t.Errorf("Port: want 8080, got %d", n.Port)
	}
}

func TestParseVMess_InvalidBase64(t *testing.T) {
	link := "vmess://!!!invalid-base64!!!"
	_, err := protocol.ParseVMess(link)
	if err == nil {
		t.Fatal("无效 base64 应返回错误")
	}
}

// ============================================================
// 4. ParseSS
// ============================================================

func TestParseSS_Basic(t *testing.T) {
	// SS format: ss://base64(method:password)@server:port#name
	// The entire method:password part is base64 encoded, then @host:port appended
	raw := "aes-256-gcm:my-password@ss.example.com:8388"
	encoded := base64.URLEncoding.EncodeToString([]byte(raw))
	link := "ss://" + encoded + "#SS-Node"

	n, err := protocol.ParseSS(link)
	if err != nil {
		t.Fatalf("ParseSS failed: %v", err)
	}
	if n.Type != "ss" {
		t.Errorf("Type: got %q", n.Type)
	}
	if n.Server != "ss.example.com" {
		t.Errorf("Server: got %q", n.Server)
	}
	if n.Port != 8388 {
		t.Errorf("Port: got %d", n.Port)
	}
	if n.Method != "aes-256-gcm" {
		t.Errorf("Method: got %q", n.Method)
	}
	if n.Password != "my-password" {
		t.Errorf("Password: got %q", n.Password)
	}
	if n.Name != "SS-Node" {
		t.Errorf("Name: got %q", n.Name)
	}
}

func TestParseSS_InvalidNoAt(t *testing.T) {
	link := "ss://" + base64.URLEncoding.EncodeToString([]byte("no-at-sign"))
	_, err := protocol.ParseSS(link)
	if err == nil {
		t.Fatal("缺少 @ 应返回错误")
	}
}

// ============================================================
// 5. ParseSSocks
// ============================================================

func TestParseSSocks_Basic(t *testing.T) {
	auth := base64.URLEncoding.EncodeToString([]byte("user123:pass456@socks.example.com:22881"))
	link := "ssocks://" + auth + "?remarks=HK-SOCKS"

	n, err := protocol.ParseSSocks(link)
	if err != nil {
		t.Fatalf("ParseSSocks failed: %v", err)
	}
	if n.Type != "socks5" {
		t.Errorf("Type: want socks5, got %q", n.Type)
	}
	if n.Username != "user123" {
		t.Errorf("Username: got %q", n.Username)
	}
	if n.Password != "pass456" {
		t.Errorf("Password: got %q", n.Password)
	}
	if n.Server != "socks.example.com" {
		t.Errorf("Server: got %q", n.Server)
	}
	if n.Port != 22881 {
		t.Errorf("Port: got %d", n.Port)
	}
	if !n.TLS {
		t.Error("SSocks 应默认 TLS=true")
	}
}

// ============================================================
// 6. ParseTUIC
// ============================================================

func TestParseTUIC_Basic(t *testing.T) {
	link := "tuic://uuid-1234:pass-5678@tuic.example.com:12345?sni=tuic.example.com&alpn=h3&allow_insecure=1#TUIC-Node"
	n, err := protocol.ParseTUIC(link)
	if err != nil {
		t.Fatalf("ParseTUIC failed: %v", err)
	}
	if n.Type != "tuic" {
		t.Errorf("Type: got %q", n.Type)
	}
	if n.UUID != "uuid-1234" {
		t.Errorf("UUID: got %q", n.UUID)
	}
	if n.Password != "pass-5678" {
		t.Errorf("Password: got %q", n.Password)
	}
	if n.Port != 12345 {
		t.Errorf("Port: got %d", n.Port)
	}
	if n.SNI != "tuic.example.com" {
		t.Errorf("SNI: got %q", n.SNI)
	}
	if !n.SkipCertVerify {
		t.Error("allow_insecure=1 时应为 true")
	}
	if len(n.ALPN) == 0 || n.ALPN[0] != "h3" {
		t.Errorf("ALPN: got %v", n.ALPN)
	}
}

// ============================================================
// 7. ParseVLESS
// ============================================================

func TestParseVLESS_RealityNode(t *testing.T) {
	link := "vless://uuid-abc@vless.example.com:443?type=tcp&security=reality&pbk=pubkey123&sid=shortid456&fp=chrome&flow=xtls-rprx-vision&sni=www.microsoft.com#VLESS-Reality"
	n, err := protocol.ParseVLESS(link)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}
	if n.Type != "vless" {
		t.Errorf("Type: got %q", n.Type)
	}
	if n.UUID != "uuid-abc" {
		t.Errorf("UUID: got %q", n.UUID)
	}
	if !n.TLS {
		t.Error("security=reality 时 TLS 应为 true")
	}
	if n.RealityOpts == nil {
		t.Fatal("RealityOpts 不应为 nil")
	}
	if n.RealityOpts.PublicKey != "pubkey123" {
		t.Errorf("PublicKey: got %q", n.RealityOpts.PublicKey)
	}
	if n.RealityOpts.ShortID != "shortid456" {
		t.Errorf("ShortID: got %q", n.RealityOpts.ShortID)
	}
	if n.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow: got %q", n.Flow)
	}
	if n.ClientFingerprint != "chrome" {
		t.Errorf("ClientFingerprint: got %q", n.ClientFingerprint)
	}
}

func TestParseVLESS_WSNode(t *testing.T) {
	link := "vless://uuid-ws@ws.example.com:443?type=ws&security=tls&path=/ws-path&host=cdn.example.com&sni=cdn.example.com#VLESS-WS"
	n, err := protocol.ParseVLESS(link)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}
	if n.Network != "ws" {
		t.Errorf("Network: got %q", n.Network)
	}
	if n.WSOpts.Path != "/ws-path" {
		t.Errorf("WSOpts.Path: got %q", n.WSOpts.Path)
	}
	if n.WSOpts.Headers["Host"] != "cdn.example.com" {
		t.Errorf("WSOpts.Headers[Host]: got %q", n.WSOpts.Headers["Host"])
	}
	if !n.TLS {
		t.Error("security=tls 时应为 true")
	}
}

func TestParseVLESS_DefaultPort(t *testing.T) {
	link := "vless://uuid@host.com#name"
	n, _ := protocol.ParseVLESS(link)
	if n.Port != 443 {
		t.Errorf("默认端口应为443, got %d", n.Port)
	}
}

func TestParseVLESS_GRPCNode(t *testing.T) {
	link := "vless://uuid@grpc.example.com:443?type=grpc&security=tls&serviceName=my-grpc-service#VLESS-gRPC"
	n, _ := protocol.ParseVLESS(link)
	if n.Network != "grpc" {
		t.Errorf("Network: got %q", n.Network)
	}
	if n.WSOpts.Path != "my-grpc-service" {
		t.Errorf("gRPC serviceName: got %q", n.WSOpts.Path)
	}
}

// ============================================================
// 8. ParseHysteria2
// ============================================================

func TestParseHysteria2_Basic(t *testing.T) {
	link := "hysteria2://my-hy2-pass@hy2.example.com:8443?sni=hy2.example.com&insecure=1#HY2-Node"
	n, err := protocol.ParseHysteria2(link)
	if err != nil {
		t.Fatalf("ParseHysteria2 failed: %v", err)
	}
	if n.Type != "hysteria2" {
		t.Errorf("Type: got %q", n.Type)
	}
	if n.Password != "my-hy2-pass" {
		t.Errorf("Password: got %q", n.Password)
	}
	if n.Port != 8443 {
		t.Errorf("Port: got %d", n.Port)
	}
	if n.SNI != "hy2.example.com" {
		t.Errorf("SNI: got %q", n.SNI)
	}
	if !n.SkipCertVerify {
		t.Error("insecure=1 时应跳过证书验证")
	}
	if !n.UDP {
		t.Error("Hysteria2 应默认 UDP=true")
	}
}

func TestParseHysteria2_Hy2Prefix(t *testing.T) {
	link := "hy2://pass@host.com:443#name"
	n, err := protocol.ParseHysteria2(link)
	if err != nil {
		t.Fatalf("ParseHysteria2 with hy2:// prefix failed: %v", err)
	}
	if n.Type != "hysteria2" {
		t.Errorf("Type: got %q", n.Type)
	}
}

func TestParseHysteria2_PeerAsSNI(t *testing.T) {
	link := "hysteria2://pass@host.com:443?peer=peer-sni.com#name"
	n, _ := protocol.ParseHysteria2(link)
	if n.SNI != "peer-sni.com" {
		t.Errorf("peer 参数应回退为 SNI, got %q", n.SNI)
	}
}

// ============================================================
// 9. ParseHTTPLike
// ============================================================

func TestParseHTTPLike_HTTPS(t *testing.T) {
	link := "https://user:pass@http-proxy.com:8443#HTTP-Node"
	n, err := protocol.ParseHTTPLike(link)
	if err != nil {
		t.Fatalf("ParseHTTPLike failed: %v", err)
	}
	if n.Type != "http" {
		t.Errorf("Type: got %q", n.Type)
	}
	if n.Username != "user" {
		t.Errorf("Username: got %q", n.Username)
	}
	if n.Password != "pass" {
		t.Errorf("Password: got %q", n.Password)
	}
	if !n.Tls {
		t.Error("https 链接应设置 Tls=true")
	}
	if n.Port != 8443 {
		t.Errorf("Port: got %d", n.Port)
	}
}

func TestParseHTTPLike_HTTP_DefaultPort(t *testing.T) {
	link := "http://user:pass@host.com#name"
	n, _ := protocol.ParseHTTPLike(link)
	if n.Port != 80 {
		t.Errorf("HTTP 默认端口应为80, got %d", n.Port)
	}
	if n.Tls {
		t.Error("HTTP 链接 Tls 应为 false")
	}
}

// ============================================================
// 10. PreprocessYAML
// ============================================================

func TestPreprocessYAML(t *testing.T) {
	input := "}\n{"
	output := protocol.PreprocessYAML(input)
	if !strings.Contains(output, "---") {
		t.Error("相邻的 }{ 之间应插入 --- 分隔符")
	}

	// 紧挨型
	input2 := "}{"
	output2 := protocol.PreprocessYAML(input2)
	if !strings.Contains(output2, "---") {
		t.Error("紧挨的 }{ 应插入 --- 分隔符")
	}
}

// ============================================================
// 11. ParseNodes YAML 解析
// ============================================================

func TestParseNodes_WhitelistFilter(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	yml := `{
    name: 'TestNode',
    type: trojan,
    server: 'a.com',
    port: 443,
    password: pass
}
---
{
    name: 'UnsupportedNode',
    type: wireguard,
    server: 'b.com',
    port: 1234
}
`
	os.WriteFile("whitelist.yml", []byte(yml), 0644)

	nodes, err := protocol.ParseNodes("whitelist.yml")
	if err != nil {
		t.Fatalf("ParseNodes failed: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("白名单过滤后应只有1个节点, got %d", len(nodes))
	}
	if nodes[0].Type != "trojan" {
		t.Errorf("保留的应是 trojan, got %q", nodes[0].Type)
	}
}

func TestParseNodes_EmptyFile(t *testing.T) {
	cleanup := setupTestDir(t)
	defer cleanup()

	os.WriteFile("empty.yml", []byte(""), 0644)
	nodes, err := protocol.ParseNodes("empty.yml")
	if err != nil {
		t.Fatalf("空文件不应报错: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("空文件应返回0个节点, got %d", len(nodes))
	}
}

// ============================================================
// 12. NormalizeSubscription
// ============================================================

func TestNormalizeSubscription_PlainLinks(t *testing.T) {
	input := []byte("trojan://pass@host:443#name1\nvmess://base64data")
	out, err := protocol.NormalizeSubscription(input)
	if err != nil {
		t.Fatalf("NormalizeSubscription failed: %v", err)
	}
	if !strings.Contains(out, "trojan://") {
		t.Error("应直接原样返回包含 :// 的内容")
	}
}

func TestNormalizeSubscription_Base64Encoded(t *testing.T) {
	plain := "trojan://pass@host:443#name"
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	out, err := protocol.NormalizeSubscription([]byte(encoded))
	if err != nil {
		t.Fatalf("NormalizeSubscription failed: %v", err)
	}
	if !strings.Contains(out, "trojan://") {
		t.Error("应成功解码 base64 并返回原始链接")
	}
}

func TestNormalizeSubscription_BOM(t *testing.T) {
	bom := "\xEF\xBB\xBFtrojan://pass@host:443#name"
	out, err := protocol.NormalizeSubscription([]byte(bom))
	if err != nil {
		t.Fatalf("NormalizeSubscription failed: %v", err)
	}
	if !strings.Contains(out, "trojan://") {
		t.Error("应正确移除 BOM 头")
	}
}
