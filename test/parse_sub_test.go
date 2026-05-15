package test

import (
	"flag"

	"high-mae/pkg/sub"
	"high-mae/protocol"
	"testing"
)

// TestParseSub 测试解析订阅，不支持的跳过
// go test -v TestParseSub -args "链接或订阅地址"
func TestParseSub(t *testing.T) {
	// 解析 go test 后面通过 -args 传进来的参数
	flag.Parse()
	args := flag.Args()

	var nodes []protocol.Node
	var err error

	// 1. 判断命令行是否传入了链接
	if len(args) > 0 {
		link := args[0]
		t.Logf("🔗 接收到命令行输入的链接，正在解析...\n%s", link)

		// 使用你之前写好的、极其强大的订阅/多协议解析器
		nodes, err = sub.ParseSubscription(link)
		if err != nil {
			t.Fatalf("❌ 解析命令行链接/订阅失败: %v", err)
		}
	} else {
		t.Skip("未传入真实订阅/节点链接，跳过需要外部节点数据的解析测试")
	}

	t.Logf("📦 共解析出 %d 个节点", len(nodes))
	for _, node := range nodes {
		t.Logf("✅ 解析到节点: [%s] %s (%s:%d)", node.Type, node.Name, node.Server, node.Port)
	}
}
