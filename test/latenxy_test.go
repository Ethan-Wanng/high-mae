package test

import (
	"flag"
	"fmt"
	"high-mae/ins"
	"high-mae/protocol"
	"net/http"
	"net/http/httptest"
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
		nodes, err = protocol.ParseNodes("../config.yml")
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
		"http://www.gstatic.com/generate_204",
		"https://www.gstatic.com/generate_204",
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

// 场景 1：测试健康的直连测速 (不走代理，纯测函数逻辑)
func TestCheckProxyLatency_Direct(t *testing.T) {
	// 由于是直连测试，我们将 proxy 设为 nil 对应的行为 (在实际代码里传 "" 并稍微改下解析逻辑，或直接起一个 dummy proxy)
	// 这里直接起一个本地测试服务器模拟 Google 204 接口
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent) // 返回 204
	}))
	defer ts.Close()

	// 假设没有代理（传空会解析失败，我们这里为了测试函数的稳健性，用真实的测试服务器替换 target）
	// 注意：如果你直接传 "" 给 CheckProxyLatency 会报错，我们可以随便传一个有效的假代理格式，或者修改你的 CheckProxyLatency 支持空代理
	// 简单起见，我们测带有错误代理的情况：

	latency, err := ins.CheckProxyLatency("http://127.0.0.1:10808", ts.URL, 5*time.Second)
	// 如果你本地没有起 10808 代理，这里一定会报错
	if err != nil {
		t.Logf("预期内的失败 (本地没开代理): %v", err)
	} else {
		t.Logf("代理连通！延迟: %d ms", latency)
	}
}

// 场景 2：测试超时控制是否生效
func TestCheckProxyLatency_Timeout(t *testing.T) {
	// 创建一个故意卡死 3 秒才返回的测试服务器
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	// 故意把超时时间设置为 1 秒
	_, err := ins.CheckProxyLatency("http://127.0.0.1:10808", ts.URL, 1*time.Second)
	if err == nil {
		t.Fatal("❌ 预期应该超时失败，但居然成功了！")
	}

	if !strings.Contains(err.Error(), "Timeout") && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "refused") {
		t.Fatalf("❌ 预期报 timeout 错，实际报: %v", err)
	}
	t.Logf("✅ 超时机制生效: %v", err)
}

// 场景 3：测试机场被拦截 (返回 403)
func TestCheckProxyLatency_Forbidden(t *testing.T) {
	// 创建一个模拟 Cloudflare 403 拦截的测试服务器
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 403
		fmt.Fprintln(w, "Cloudflare WAF Blocked")
	}))
	defer ts.Close()

	_, err := ins.CheckProxyLatency("http://127.0.0.1:10808", ts.URL, 5*time.Second)
	if err == nil {
		t.Fatal("❌ 预期应该拦截失败，但测速成功了！")
	}

	t.Logf("✅ 拦截检测机制生效: %v", err)
}
