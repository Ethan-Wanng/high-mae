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

	q := u.Query()
	skipCert := queryBool(q, "skip_cert_verify") ||
		queryBool(q, "allow_insecure") ||
		queryBool(q, "allowInsecure") ||
		queryBool(q, "insecure")

	return Node{
		Type:              "anytls",
		Name:              name,
		Server:            u.Hostname(),
		Port:              port,
		Password:          u.User.Username(),
		SNI:               u.Query().Get("sni"),
		SkipCertVerify:    skipCert,
		ClientFingerprint: "firefox", // 保持火狐指纹特征
		UDP:               true,
		TFO:               true,
	}, nil
}
