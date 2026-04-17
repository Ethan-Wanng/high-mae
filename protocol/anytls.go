package protocol

import (
	"net/url"
	"strconv"
)

func ParseAnyTLS(link string) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, err
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 4430
	}
	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = u.Hostname() // 如果没有名字，默认用域名
	}

	// 🚀 核心修复：默认开启跳过证书验证！
	// 翻墙节点因为伪装了 SNI，证书 99% 都是对不上的，必须跳过验证。
	skipCert := true
	if u.Query().Get("skip_cert_verify") == "false" {
		skipCert = false // 只有明确要求不跳过时，才设为 false
	}

	return Node{
		Type:              "anytls",
		Name:              name,
		Server:            u.Hostname(),
		Port:              port,
		Password:          u.User.Username(),
		SNI:               u.Query().Get("sni"),
		SkipCertVerify:    skipCert,  // 应用修复后的布尔值
		ClientFingerprint: "firefox", // 保持火狐指纹特征
		UDP:               true,
		TFO:               true,
	}, nil
}
