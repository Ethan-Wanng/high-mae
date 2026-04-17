package protocol

import (
	"net/url"
	"strconv"
	"strings"
)

// 解析 http(s) 代理节点链接 (包含被整体 Base64 加密的特殊情况)
func ParseHTTPLike(link string) (Node, error) {
	// 判断原始链接是否是 https（用于决定是否开启 Tls）
	isTls := strings.HasPrefix(link, "https://")

	u, err := url.Parse(link)
	if err != nil {
		return Node{}, err
	}

	// 核心修复：尝试对 u.Host 进行 Base64 解码 (应对 user:pass@host:port 整体被加密的机场)
	if decoded, ok := tryBase64Variants(u.Host); ok {
		decStr := string(decoded)
		if strings.Contains(decStr, "@") {
			// 将解密后的明文还原为标准链接重新解析
			reconstructed := "http://"
			if isTls {
				reconstructed = "https://"
			}
			reconstructed += decStr
			if u.RawQuery != "" {
				reconstructed += "?" + u.RawQuery
			}

			if u2, err2 := url.Parse(reconstructed); err2 == nil {
				u2.Fragment = u.Fragment // 继承节点名称
				u = u2
			}
		}
	}

	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		if isTls {
			port = 443
		} else {
			port = 80
		}
	}

	name, _ := url.QueryUnescape(u.Fragment)

	var username, password string
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	// 兜底：如果只有 username 被加密为 Base64
	if password == "" && username != "" {
		if decoded, ok := tryBase64Variants(username); ok {
			decStr := string(decoded)
			if strings.Contains(decStr, ":") {
				parts := strings.SplitN(decStr, ":", 2)
				username = parts[0]
				password = parts[1]
			}
		}
	}

	// 强制设定为 http 协议（根据你的需求去掉 https）
	return Node{
		Type:     "http",
		Name:     name,
		Server:   u.Hostname(),
		Port:     port,
		Username: username,
		Password: password,
		SNI:      u.Query().Get("sni"),
		Tls:      isTls,
	}, nil
}
