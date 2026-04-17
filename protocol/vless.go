package protocol

import (
	"net/url"
	"strconv"
)

func ParseVLESS(link string) (Node, error) {
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
	node := Node{
		Type:              "vless",
		Name:              name,
		Server:            u.Hostname(),
		Port:              port,
		UUID:              u.User.Username(),
		UDP:               true, // VLESS 默认支持 UDP
		SkipCertVerify:    false,
		ClientFingerprint: q.Get("fp"),
		ServerName:        q.Get("sni"), // VLESS 分享链接中 sni 对应 ServerName
		Network:           q.Get("type"),
		Flow:              q.Get("flow"),
	}

	// 解析 TLS / REALITY 安全传输层
	security := q.Get("security")
	if security == "tls" || security == "reality" {
		node.TLS = true
	}

	// 解析 REALITY 参数
	if security == "reality" {
		node.RealityOpts = &RealityOpts{
			PublicKey: q.Get("pbk"),
			ShortID:   q.Get("sid"),
		}
	}

	// 解析 WebSocket 传输层参数
	if node.Network == "ws" {
		node.WSOpts = WSOpts{
			Path: q.Get("path"),
		}
		host := q.Get("host")
		if host != "" {
			node.WSOpts.Headers = map[string]string{
				"Host": host,
			}
		}
	}

	return node, nil
}
