package sub

import (
	"strconv"
	"strings"

	"wing/protocol"
)

// mergeSubscriptionVariants 合并同一订阅按不同客户端标识返回的节点列表。
// 以节点最多的变体为基准保持其顺序（数量相同时取靠前的变体），再追加其它变体独有的节点
// （如仅 sing-box 变体提供的 naive）。
func mergeSubscriptionVariants(variants [][]protocol.Node) []protocol.Node {
	baseIndex := -1
	for i, nodes := range variants {
		if baseIndex < 0 || len(nodes) > len(variants[baseIndex]) {
			baseIndex = i
		}
	}
	if baseIndex < 0 {
		return nil
	}

	merged := append([]protocol.Node(nil), variants[baseIndex]...)
	seen := make(map[string]bool, len(merged))
	for _, node := range merged {
		seen[subscriptionNodeKey(node)] = true
	}
	for i, nodes := range variants {
		if i == baseIndex {
			continue
		}
		for _, node := range nodes {
			key := subscriptionNodeKey(node)
			if seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, node)
		}
	}
	return merged
}

// subscriptionNodeKey 识别跨变体的同一节点：名称和 Hysteria2 端口在不同客户端格式中可能不同
// （端口跳跃 vs 随机单端口），因此只比较协议、服务器和凭据。
func subscriptionNodeKey(node protocol.Node) string {
	port := strconv.Itoa(node.Port)
	if node.Type == "hysteria2" || node.Type == "hy2" {
		port = ""
	}
	return strings.Join([]string{
		node.Type,
		strings.ToLower(strings.TrimSpace(node.Server)),
		port,
		node.UUID,
		node.Username,
		node.Password,
	}, "|")
}

// allPlaceholderNodes 判断订阅是否只返回了"客户端版本太老"一类的占位节点。
func allPlaceholderNodes(nodes []protocol.Node) bool {
	for _, node := range nodes {
		if !isPlaceholderNode(node) {
			return false
		}
	}
	return len(nodes) > 0
}

func isPlaceholderNode(node protocol.Node) bool {
	if strings.Contains(strings.ToLower(node.Password), "fake_node") {
		return true
	}
	switch strings.TrimSpace(node.Server) {
	case "", "0.0.0.0", "127.0.0.1", "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "114.114.114.114", "223.5.5.5":
		return true
	}
	return false
}
