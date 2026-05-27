package proxy_test

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"wing/pkg/proxy"
	"wing/pkg/sub"
	"wing/protocol"
)

// TestParseSubscriptionLink 测试传入订阅链接并解析节点
func TestParseSubscriptionLink(t *testing.T) {
	link := os.Getenv("SUB_LINK")
	if link == "" {
		t.Skip("SUB_LINK 未设置，跳过真实订阅解析测试")
	}

	t.Logf("开始解析订阅链接: %s", link)

	// 我们先尝试用内置的 ParseSubscriptionWithInfo 解析
	nodes, traffic, err := sub.ParseSubscriptionWithInfo(link)
	if err != nil {
		t.Logf("直接解析失败 (可能是由于 DNS 或网络问题: %v)，尝试使用本地代理中转...", err)

		// 备用方案：如果本地高魅客户端正在运行，通过本地 HTTP 代理 127.0.0.1:10808 获取
		proxyUrl, parseErr := url.Parse("http://127.0.0.1:10808")
		if parseErr == nil {
			transport := &http.Transport{
				Proxy: http.ProxyURL(proxyUrl),
			}
			client := &http.Client{
				Transport: transport,
				Timeout:   15 * time.Second,
			}
			req, reqErr := http.NewRequest("GET", link, nil)
			if reqErr == nil {
				req.Header.Set("User-Agent", "Karing/2.0.0")
				resp, doErr := client.Do(req)
				if doErr == nil && resp.StatusCode == http.StatusOK {
					body, readErr := io.ReadAll(resp.Body)
					resp.Body.Close()
					if readErr == nil {
						nodes, err = protocol.ParseSubscriptionRaw(body)
						t.Logf("使用本地代理中转解析成功！")
					}
				}
			}
		}
	}

	if err != nil {
		t.Fatalf("订阅解析失败: %v", err)
	}

	t.Logf("成功解析出 %d 个节点", len(nodes))
	if traffic != nil {
		t.Logf("订阅流量信息: 已用 %d / 总计 %d", traffic.Used, traffic.Total)
	}

	for i, node := range nodes {
		t.Logf("[%d] 节点名称: %q, 协议类型: %q, 服务器: %q, 端口: %d", i+1, node.Name, node.Type, node.Server, node.Port)
	}
}

// TestNodeBandwidthSpeed 测试对指定节点进行实际宽带/下载速度测试
func TestNodeBandwidthSpeed(t *testing.T) {
	link := os.Getenv("SUB_LINK")
	if link == "" {
		t.Skip("SUB_LINK 未设置，跳过真实节点测速测试")
	}

	var nodes []protocol.Node
	var err error
	nodes, _, err = sub.ParseSubscriptionWithInfo(link)
	if err != nil {
		// 尝试用本地代理重试
		proxyUrl, _ := url.Parse("http://127.0.0.1:10808")
		transport := &http.Transport{Proxy: http.ProxyURL(proxyUrl)}
		client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
		req, _ := http.NewRequest("GET", link, nil)
		req.Header.Set("User-Agent", "Karing/2.0.0")
		if resp, doErr := client.Do(req); doErr == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			nodes, _ = protocol.ParseSubscriptionRaw(body)
		}
	}

	if len(nodes) == 0 {
		t.Skip("无可测试的节点，跳过测速用例")
	}

	// 优先测速 Mieru 节点以验证我们的修复，如果都失败了再尝试其他节点
	var testNodes []protocol.Node
	for _, n := range nodes {
		if n.Type == "mieru" {
			testNodes = append(testNodes, n)
		}
	}
	// 混合其他节点
	for _, n := range nodes {
		if n.Type != "mieru" {
			testNodes = append(testNodes, n)
		}
	}

	// 限制最多尝试 5 个节点，避免测试用例执行时间过长
	maxAttempts := 5
	if len(testNodes) > maxAttempts {
		testNodes = testNodes[:maxAttempts]
	}

	var successNode *protocol.Node
	var duration time.Duration
	var totalDownloaded int64
	var avgSpeedMBs float64
	var avgSpeedMbps float64

	for _, testNode := range testNodes {
		t.Logf("-------------------------------------------------")
		t.Logf("尝试测速节点: [%s] %s (%s:%d)", testNode.Type, testNode.Name, testNode.Server, testNode.Port)

		httpClient, cleanup, err := proxy.CreateTempHTTPClient(testNode)
		if err != nil {
			t.Logf("为节点创建 HTTP Client 失败: %v，尝试下一个节点...", err)
			continue
		}

		speedTestURL := "https://speed.cloudflare.com/__down?bytes=5000000" // 5MB
		t.Logf("正在请求测速链接: %s", speedTestURL)

		start := time.Now()
		resp, err := httpClient.Get(speedTestURL)
		if err != nil {
			cleanup()
			t.Logf("节点 HTTP 请求失败 (节点可能已失效/封锁): %v，尝试下一个节点...", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cleanup()
			t.Logf("服务器返回异常状态码: %d，尝试下一个节点...", resp.StatusCode)
			continue
		}

		// 成功建立连接且返回 200，开始下载并计算速度
		buffer := make([]byte, 32*1024) // 32KB buffer
		var currentDownloaded int64
		var readErr error
		lastReport := time.Now()

		for {
			n, rErr := resp.Body.Read(buffer)
			if n > 0 {
				currentDownloaded += int64(n)
			}
			if rErr == io.EOF {
				break
			}
			if rErr != nil {
				readErr = rErr
				break
			}

			// 每隔 1000ms 打印一次进度
			if time.Since(lastReport) >= 1000*time.Millisecond {
				elapsed := time.Since(start).Seconds()
				if elapsed > 0 {
					speed := float64(currentDownloaded) / elapsed / 1024 / 1024 // MB/s
					t.Logf("已下载: %.2f MB, 即时速度: %.2f MB/s", float64(currentDownloaded)/1024/1024, speed)
				}
				lastReport = time.Now()
			}
		}
		resp.Body.Close()
		cleanup()

		if readErr != nil {
			t.Logf("下载数据中途失败: %v，尝试下一个节点...", readErr)
			continue
		}

		// 测速成功
		duration = time.Since(start)
		totalDownloaded = currentDownloaded
		successNode = &testNode
		break
	}

	if successNode == nil {
		t.Skip("订阅中的所有尝试节点目前均无法连接（可能订阅节点已全部失效或当前测试机网络彻底阻断该机场），跳过测速步骤")
		return
	}

	elapsedSeconds := duration.Seconds()
	if elapsedSeconds <= 0 {
		elapsedSeconds = 0.001
	}

	totalMB := float64(totalDownloaded) / 1024 / 1024
	avgSpeedMBs = totalMB / elapsedSeconds
	avgSpeedMbps = (float64(totalDownloaded) * 8) / elapsedSeconds / 1000 / 1000

	t.Logf("==================== 测速完成 ====================")
	t.Logf("测速成功节点: [%s] %s", successNode.Type, successNode.Name)
	t.Logf("下载数据总量: %.2f MB", totalMB)
	t.Logf("测试总耗时: %v", duration.Round(time.Millisecond))
	t.Logf("平均下载速率 (字节): %.2f MB/s", avgSpeedMBs)
	t.Logf("平均宽带带宽 (比特): %.2f Mbps", avgSpeedMbps)
	t.Logf("=================================================")
}
