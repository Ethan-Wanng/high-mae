package test

import (
	"flag"
	"fmt"
	"high-mae/ins"
	"high-mae/protocol"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestProxyLatencyParallel go test -tags with_quic,with_utls -v -run TestProxyLatencyParallel -args "链接或订阅地址"
func TestProxyLatencyParallel(t *testing.T) {
	flag.Parse()
	args := flag.Args()

	var nodes []protocol.Node
	var err error

	if len(args) > 0 {
		link := args[0]
		t.Logf("🔗 接收到命令行输入的链接，正在解析...\n%s", link)

		nodes, err = ins.ParseSubscription(link)
		if err != nil {
			t.Fatalf("❌ 解析命令行链接/订阅失败: %v", err)
		}
	} else {
		t.Log("⚠️ 未检测到命令行链接参数，回退读取本地 output.yml...")
		nodes, err = protocol.ParseNodes("../output.yml")
		if err != nil {
			t.Fatalf("❌ 解析 output.yml 失败: %v", err)
		}
	}

	if len(nodes) == 0 {
		t.Skip("⚠️ 链接或文件中没有提取到任何可用节点")
	}

	t.Logf("📦 共解析出 %d 个节点，开始并发测速...", len(nodes))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	testURLs := []string{
		"http://www.google.com/generate_204",
		"https://www.google.com/generate_204",
	}

	for i, n := range nodes {
		wg.Add(1)

		go func(node protocol.Node, index int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			testName := fmt.Sprintf("[%03d] %s", index, node.Name)

			client, cleanup, err := ins.CreateTempHTTPClient(node)
			if err != nil {
				t.Errorf("❌ %s | 初始化失败: %v", testName, err)
				return
			}
			defer cleanup()

			var ok bool
			var latency int64
			var finalErr error

			for _, u := range testURLs {
				start := time.Now()
				resp, err := client.Get(u)
				if err == nil {
					_ = resp.Body.Close()
					latency = time.Since(start).Milliseconds()
					ok = true
					break
				}
				finalErr = err
			}

			if !ok {
				t.Logf("❌ %s | 测速失败: %v", testName, finalErr)
				return
			}

			status := "🟢 优秀"
			if latency > 500 {
				status = "🟡 一般"
			}

			t.Logf("✅ %s | %s | 延迟: %d ms | 协议: %s", testName, status, latency, strings.ToUpper(node.Type))
		}(n, i+1)
	}

	wg.Wait()
	t.Log("🎉 所有节点并发测速完毕！")
}
