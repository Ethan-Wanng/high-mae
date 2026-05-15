package test

import (
	"high-mae/pkg/common"
	"high-mae/pkg/routing"
	"testing"
)

// ============================================================
// ShouldDirect 路由分流规则测试
// ============================================================

func TestShouldDirect_LoopbackIP(t *testing.T) {
	if !routing.ShouldDirect("127.0.0.1:80") {
		t.Error("回环地址应直连")
	}
}

func TestShouldDirect_PrivateIP(t *testing.T) {
	privates := []string{"192.168.1.1:80", "10.0.0.1:443", "172.16.0.1:8080"}
	for _, addr := range privates {
		if !routing.ShouldDirect(addr) {
			t.Errorf("私有IP %s 应直连", addr)
		}
	}
}

func TestShouldDirect_CNDomain(t *testing.T) {
	cnDomains := []string{
		"www.baidu.com:443",
		"api.weixin.qq.com:443",
		"www.taobao.com:443",
		"www.bilibili.com:443",
		"www.zhihu.com:443",
	}
	for _, addr := range cnDomains {
		if !routing.ShouldDirect(addr) {
			t.Errorf("国内域名 %s 应直连", addr)
		}
	}
}

func TestShouldDirect_ForeignDomain(t *testing.T) {
	foreign := []string{
		"www.google.com:443",
		"www.youtube.com:443",
		"twitter.com:443",
		"api.openai.com:443",
	}
	for _, addr := range foreign {
		if routing.ShouldDirect(addr) {
			t.Errorf("国外域名 %s 不应直连", addr)
		}
	}
}

func TestShouldDirect_KeywordMatch(t *testing.T) {
	keywords := []string{
		"cdn-cn.example.com:443", // 包含 -cn
		"alicdn.example.com:443", // 包含 alicdn
		"alipay.test.com:443",    // 包含 alipay
		"baidu.test.org:443",     // 包含 baidu
	}
	for _, addr := range keywords {
		if !routing.ShouldDirect(addr) {
			t.Errorf("关键词域名 %s 应直连", addr)
		}
	}
}

func TestShouldDirect_GlobalMode(t *testing.T) {
	origMode := common.ProxyMode
	defer func() { common.ProxyMode = origMode }()

	common.ProxyMode = "Global"

	// 全局模式下所有地址都不应直连（全部走代理）
	if routing.ShouldDirect("www.baidu.com:443") {
		t.Error("全局模式下 baidu.com 不应直连")
	}
	if routing.ShouldDirect("127.0.0.1:80") {
		t.Error("全局模式下 ShouldDirect 对所有地址返回 false")
	}
	if routing.ShouldDirect("192.168.1.1:80") {
		t.Error("全局模式下 ShouldDirect 对所有地址返回 false")
	}
}

func TestShouldDirect_ExactDomainMatch(t *testing.T) {
	// 精确匹配域名（来自 exactDomains 列表）
	if !routing.ShouldDirect("cn.bing.com:443") {
		t.Error("exactDomains 中的 cn.bing.com 应直连")
	}
}

func TestShouldDirect_SuffixDomainMatch(t *testing.T) {
	// .cn 后缀匹配
	if !routing.ShouldDirect("www.gov.cn:443") {
		t.Error(".cn 后缀应直连")
	}
	// .com.cn 也应匹配
	if !routing.ShouldDirect("app.example.com.cn:443") {
		t.Error(".com.cn 后缀应直连")
	}
}

func TestShouldDirect_NoPort(t *testing.T) {
	// 不带端口的地址
	if !routing.ShouldDirect("www.baidu.com") {
		t.Error("不带端口的国内域名也应直连")
	}
}

func TestEvaluateRouting_StunDomainsRejected(t *testing.T) {
	domains := []string{
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"global.stun.twilio.com:3478",
		"turn.cloudflare.com:3478",
	}
	for _, addr := range domains {
		if got := routing.EvaluateRouting(addr); got != 2 {
			t.Errorf("STUN/TURN 域名 %s 应被拦截, got %d", addr, got)
		}
	}
}
