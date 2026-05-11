package protocol

import (
	"net/url"
	"strconv"
	"strings"
)

func ParseHysteria2(link string) (Node, error) {
	// 兼容 hy2:// 简写格式
	if strings.HasPrefix(link, "hy2://") {
		link = "hysteria2://" + strings.TrimPrefix(link, "hy2://")
	}

	u, err := url.Parse(link)
	if err != nil {
		return Node{}, err
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}

	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = u.Hostname()
	}

	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer") // 有些旧版客户端用 peer 表示 sni
	}

	// 判断是否允许不安全的证书
	insecure := q.Get("insecure") == "1" || q.Get("skip-cert-verify") == "true"

	return Node{
		Type:           "hysteria2",
		Name:           name,
		Server:         u.Hostname(),
		Port:           port,
		Password:       u.User.Username(),
		SNI:            sni,
		SkipCertVerify: insecure,
		UDP:            true, // Hysteria2 基于 QUIC，天然支持并且默认走 UDP
	}, nil
}
