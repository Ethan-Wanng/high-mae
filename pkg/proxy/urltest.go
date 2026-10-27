package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"wing/pkg/common"
	"wing/protocol"

	"github.com/sagernet/sing/common/metadata"
)

// 延迟测试与 Clash Party（mihomo 内核 URLTest + unified-delay）保持一致：
// 经节点代理向测试地址发送 HEAD 请求，在同一连接上再请求一次并以第二次耗时为准，
// 排除 TCP/TLS/代理握手开销，只反映经代理访问测试地址的往返延迟。
const (
	DefaultLatencyTestURL     = "https://www.gstatic.com/generate_204"
	DefaultLatencyTestTimeout = 5 * time.Second
)

// MeasureNodeLatency 使用默认测试地址和超时测量节点延迟。
func MeasureNodeLatency(node protocol.Node) (int64, error) {
	return MeasureNodeLatencyWithURL(node, DefaultLatencyTestURL, DefaultLatencyTestTimeout)
}

func MeasureNodeLatencyWithURL(node protocol.Node, testURL string, timeout time.Duration) (int64, error) {
	dial, cleanup, err := newTempNodeDialer(node)
	if err != nil {
		return 0, err
	}
	defer cleanup()

	// 与 mihomo 一致，超时只覆盖代理拨号与请求，不含本地临时客户端的初始化。
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return URLTest(ctx, dial, testURL)
}

// MeasureActiveLatency 通过当前正在使用的节点连接测量延迟。
func MeasureActiveLatency(timeout time.Duration) (int64, error) {
	client := common.GetActiveClient()
	if client == nil {
		return 0, errors.New("当前没有正在工作的节点连接")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return URLTest(ctx, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return client.CreateProxy(ctx, metadata.ParseSocksaddr(addr))
	}, DefaultLatencyTestURL)
}

// URLTest 复刻 mihomo adapter.URLTest 在 unified-delay 开启时的行为。
func URLTest(ctx context.Context, dial DialContextFunc, testURL string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, testURL, nil)
	if err != nil {
		return 0, err
	}

	transport := &http.Transport{
		DialContext:           dial,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// 自定义拨号 + 显式 TLS 配置时 Go 不会启用 HTTP/2，与 mihomo 一样走 HTTP/1.1 keep-alive。
		TLSClientConfig: &tls.Config{},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()

	// unified-delay：第二次请求复用已建立的连接；失败时退回第一次（含握手）的耗时。
	second := time.Now()
	if secondResp, secondErr := client.Do(req); secondErr == nil {
		_ = secondResp.Body.Close()
		start = second
	}

	elapsed := time.Since(start).Milliseconds()
	if elapsed < 1 {
		elapsed = 1
	}
	return elapsed, nil
}
