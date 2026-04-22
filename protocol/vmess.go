package protocol

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func ParseVMess(link string) (Node, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	raw = strings.TrimSpace(raw)

	data, ok := tryBase64Variants(raw)
	if !ok {
		return Node{}, fmt.Errorf("vmess base64 decode failed")
	}

	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		return Node{}, err
	}

	// 基础字段
	name := getString(v, "ps")
	server := getString(v, "add")
	uuid := getString(v, "id")
	port, err := getPort(v["port"])
	if err != nil {
		return Node{}, err
	}

	// 🎯 提取 VMess 专属字段
	alterId, _ := strconv.Atoi(getString(v, "aid"))
	cipher := getString(v, "scy")
	if cipher == "" {
		cipher = "auto"
	}
	network := getString(v, "net")
	path := getString(v, "path")
	host := getString(v, "host")
	sni := getString(v, "sni")
	grpcServiceName := getString(v, "grpc-service-name")

	isTls := false
	if tlsStr := getString(v, "tls"); tlsStr == "tls" {
		isTls = true
	}

	// 拼装出完美的 Clash 风格 ws-opts
	var wsOpts WSOpts
	var wsHeaders map[string]string
	if network == "ws" {
		headers := make(map[string]string)
		if host != "" {
			headers["Host"] = host
		}
		wsOpts = WSOpts{
			Path:    path,
			Headers: headers,
		}
		wsHeaders = headers
	}

	var grpcOpts map[string]string
	if network == "grpc" {
		grpcOpts = map[string]string{
			"grpc-service-name": grpcServiceName,
		}
	}

	return Node{
		Type:      "vmess",
		Name:      name,
		Server:    server,
		Port:      port,
		UUID:      uuid,
		AlterId:   alterId, // ✅ 核心修复：读取机场的 AlterId
		Cipher:    cipher,  // ✅ auto / aes-128-gcm
		Network:   network, // ✅ ws / tcp / grpc
		Host:      host,
		SNI:       sni,
		Tls:       isTls,
		WSPath:    path,
		WSHeaders: wsHeaders,
		WSOpts:    wsOpts,
		GrpcOpts:  grpcOpts,
	}, nil
}
