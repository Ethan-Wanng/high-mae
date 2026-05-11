package test

import (
	"high-mae/ins"
	"testing"
)

// ============================================================
// ShouldDirect 路由分流规则测试
// ============================================================

func TestShouldDirect_LoopbackIP(t *testing.T) {
	if !ins.ShouldDirect("127.0.0.1:80") {
		t.Error("回环地址应直连")
	}
}

func TestShouldDirect_PrivateIP(t *testing.T) {
	privates := []string{"192.168.1.1:80", "10.0.0.1:443", "172.16.0.1:8080"}
	for _, addr := range privates {
		if !ins.ShouldDirect(addr) {
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
		if !ins.ShouldDirect(addr) {
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
		if ins.ShouldDirect(addr) {
			t.Errorf("国外域名 %s 不应直连", addr)
		}
	}
}

func TestShouldDirect_KeywordMatch(t *testing.T) {
	keywords := []string{
		"cdn-cn.example.com:443",  // 包含 -cn
		"alicdn.example.com:443",  // 包含 alicdn
		"alipay.test.com:443",     // 包含 alipay
		"baidu.test.org:443",      // 包含 baidu
	}
	for _, addr := range keywords {
		if !ins.ShouldDirect(addr) {
			t.Errorf("关键词域名 %s 应直连", addr)
		}
	}
}

func TestShouldDirect_GlobalMode(t *testing.T) {
	origMode := ins.ProxyMode
	defer func() { ins.ProxyMode = origMode }()

	ins.ProxyMode = "Global"

	// 全局模式下所有地址都不应直连（全部走代理）
	if ins.ShouldDirect("www.baidu.com:443") {
		t.Error("全局模式下 baidu.com 不应直连")
	}
	if ins.ShouldDirect("127.0.0.1:80") {
		t.Error("全局模式下 ShouldDirect 对所有地址返回 false")
	}
	if ins.ShouldDirect("192.168.1.1:80") {
		t.Error("全局模式下 ShouldDirect 对所有地址返回 false")
	}
}

func TestShouldDirect_ExactDomainMatch(t *testing.T) {
	// 精确匹配域名（来自 exactDomains 列表）
	if !ins.ShouldDirect("cn.bing.com:443") {
		t.Error("exactDomains 中的 cn.bing.com 应直连")
	}
}

func TestShouldDirect_SuffixDomainMatch(t *testing.T) {
	// .cn 后缀匹配
	if !ins.ShouldDirect("www.gov.cn:443") {
		t.Error(".cn 后缀应直连")
	}
	// .com.cn 也应匹配
	if !ins.ShouldDirect("app.example.com.cn:443") {
		t.Error(".com.cn 后缀应直连")
	}
}

func TestShouldDirect_NoPort(t *testing.T) {
	// 不带端口的地址
	if !ins.ShouldDirect("www.baidu.com") {
		t.Error("不带端口的国内域名也应直连")
	}
}
