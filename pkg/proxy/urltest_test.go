package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestURLTestReportsSecondRequestOnReusedConnection(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method = %s, want HEAD", r.Method)
		}
		// 首次请求模拟握手/冷启动开销，统一延迟应只计第二次。
		if requests.Add(1) == 1 {
			time.Sleep(300 * time.Millisecond)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	var dials atomic.Int32
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultLatencyTestTimeout)
	defer cancel()
	latency, err := URLTest(ctx, dial, server.URL+"/generate_204")
	if err != nil {
		t.Fatalf("URLTest() error = %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1 (second request must reuse the connection)", got)
	}
	if latency <= 0 || latency >= 300 {
		t.Fatalf("latency = %dms, want the second request only (<300ms)", latency)
	}
}

func TestURLTestFallsBackToFirstRequestWhenSecondTimesOut(t *testing.T) {
	var requests atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) > 1 {
			<-release // 第二次请求卡住直到超时
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	defer close(release)

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	latency, err := URLTest(ctx, dial, server.URL+"/generate_204")
	if err != nil {
		t.Fatalf("URLTest() error = %v", err)
	}
	if latency >= 400 {
		t.Fatalf("latency = %dms, want first request duration, not the timed-out second request", latency)
	}
}

func TestURLTestFailsWhenProxyDialFails(t *testing.T) {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("proxy unreachable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := URLTest(ctx, dial, DefaultLatencyTestURL); err == nil {
		t.Fatal("URLTest() error = nil, want dial failure")
	}
}
