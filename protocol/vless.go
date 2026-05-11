package protocol

import (
	"net/url"
	"strconv"
	"strings"
)

func ParseVLESS(link string) (Node, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Node{}, err
	}

	// 端口
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}

	// 名称
	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = u.Hostname()
	}

	q := u.Query()

	node := Node{
		Type:           "vless",
		Name:           name,
		Server:         u.Hostname(),
		Port:           port,
		UUID:           u.User.Username(),
		UDP:            true,
		SkipCertVerify: false,
	}

	// ===== 基础参数 =====

	// 网络类型（默认 tcp）
	network := strings.ToLower(q.Get("type"))
	if network == "" {
		network = "tcp"
	}
	node.Network = network

	// flow
	node.Flow = q.Get("flow")

	// 指纹
	if fp := q.Get("fp"); fp != "" {
		node.ClientFingerprint = fp
	}

	// ===== TLS / REALITY =====

	security := strings.ToLower(q.Get("security"))

	if security == "tls" || security == "reality" {
		node.TLS = true
	}

	// servername / sni
	if sni := q.Get("sni"); sni != "" {
		node.ServerName = sni
	} else {
		node.ServerName = u.Hostname()
	}

	// 跳过证书校验（allowInsecure=1）
	if q.Get("allowInsecure") == "1" {
		node.SkipCertVerify = true
	}

	// REALITY
	if security == "reality" {
		node.RealityOpts = &RealityOpts{
			PublicKey: q.Get("pbk"),
			ShortID:   q.Get("sid"),
		}
	}

	// ===== 传输层 =====

	switch network {

	case "ws":
		path := q.Get("path")
		if path == "" {
			path = "/"
		}

		node.WSOpts = WSOpts{
			Path: path,
		}

		if host := q.Get("host"); host != "" {
			node.WSOpts.Headers = map[string]string{
				"Host": host,
			}
		}

	case "grpc":
		serviceName := q.Get("serviceName")
		if serviceName == "" {
			serviceName = q.Get("path") // 兼容旧格式
		}

		if serviceName != "" {
			node.WSOpts = WSOpts{
				Path: serviceName,
			}
		}

	case "tcp", "h2", "":
		// 默认不需要额外处理

	default:
		// 兼容未知类型，直接透传
		node.Network = network
	}

	return node, nil
}
