package ins

import (
	"fmt"
	"github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type TrackingConn struct {
	net.Conn
}

func (c *TrackingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&GlobalProxyIn, uint64(n))
	}
	return
}

func (c *TrackingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&GlobalProxyOut, uint64(n))
	}
	return
}

type HTTPProxyHandler struct{}

func (h *HTTPProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	clientMu.RLock()
	client := activeClient
	clientMu.RUnlock()

	if client == nil {
		http.Error(w, "尚未选择或初始化任何节点！", http.StatusServiceUnavailable)
		return
	}

	targetAddr := req.Host
	if !strings.Contains(targetAddr, ":") {
		if req.Method == http.MethodConnect {
			targetAddr += ":443"
		} else {
			targetAddr += ":80"
		}
	}

	var upstream net.Conn
	var err error
	routeResult := EvaluateRouting(targetAddr)
	
	if routeResult == 2 {
		http.Error(w, "已根据规则拦截", http.StatusForbidden)
		return
	} else if routeResult == 1 {
		upstream, err = net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if err != nil {
			http.Error(w, "直连失败: "+err.Error(), http.StatusBadGateway)
			return
		}
	} else {
		dest := metadata.ParseSocksaddr(targetAddr)
		upstream, err = client.CreateProxy(req.Context(), dest)
		if err != nil {
			http.Error(w, "AnyTLS代理失败", http.StatusServiceUnavailable)
			return
		}
	}
	defer upstream.Close()

	// 代理节点流量监控包装
	upstream = &TrackingConn{upstream}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	if req.Method == http.MethodConnect {
		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	} else {
		path := req.URL.Path
		if path == "" {
			path = "/"
		}
		if req.URL.RawQuery != "" {
			path += "?" + req.URL.RawQuery
		}
		fmt.Fprintf(upstream, "%s %s HTTP/1.1\r\n", req.Method, path)
		req.Header.Write(upstream)
		fmt.Fprintf(upstream, "\r\n")
	}
	go io.Copy(upstream, bufrw)
	io.Copy(clientConn, upstream)
}
