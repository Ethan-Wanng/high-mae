package proxy

import (
	"high-mae/pkg/common"
	"high-mae/pkg/routing"
	"high-mae/pkg/stats"
	"high-mae/pkg/utils"

	"fmt"
	"github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 16*1024)
	},
}

// updateThreshold 限制 UpdateConnLog 的调用频率：
// 只有当累计传输量增加超过此阈值时才更新日志，避免每次 Read/Write 都加锁
const updateThreshold = 64 * 1024 // 64KB

type TrackingConn struct {
	net.Conn
	logID       int64
	node        string
	in          uint64
	out         uint64
	lastLogIn   uint64 // 上次记录日志时的 in 值
	lastLogOut  uint64 // 上次记录日志时的 out 值
	lastStatIn  uint64
	lastStatOut uint64
}

func (c *TrackingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		bytes := uint64(n)
		atomic.AddUint64(&common.GlobalProxyIn, bytes)
		c.in += bytes
		if c.in-c.lastStatIn >= updateThreshold {
			stats.AddSessionTraffic(c.node, c.in-c.lastStatIn, 0)
			c.lastStatIn = c.in
		}
		// 限制 UpdateConnLog 调用频率，减少锁竞争
		if c.in-c.lastLogIn >= updateThreshold {
			stats.UpdateConnLog(c.logID, c.in, c.out, false)
			c.lastLogIn = c.in
		}
	}
	return
}

func (c *TrackingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		bytes := uint64(n)
		atomic.AddUint64(&common.GlobalProxyOut, bytes)
		c.out += bytes
		if c.out-c.lastStatOut >= updateThreshold {
			stats.AddSessionTraffic(c.node, 0, c.out-c.lastStatOut)
			c.lastStatOut = c.out
		}
		if c.out-c.lastLogOut >= updateThreshold {
			stats.UpdateConnLog(c.logID, c.in, c.out, false)
			c.lastLogOut = c.out
		}
	}
	return
}

type HTTPProxyHandler struct{}

func (h *HTTPProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	atomic.AddInt32(&stats.ActiveConnections, 1)
	defer atomic.AddInt32(&stats.ActiveConnections, -1)

	common.ClientMu.RLock()
	client := common.ActiveClient
	nodeName := common.ActiveNodeName
	common.ClientMu.RUnlock()

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
	var nodeUsed string
	routeAction := routing.EvaluateRouting(targetAddr)

	// 🚀 新增命令行进程路由规则匹配
	cmdline, _ := utils.GetProcessCommandLineFromRemoteAddr(req.RemoteAddr)
	if cmdline != "" {
		if action, matched := routing.EvaluateCmdRouting(cmdline); matched {
			routeAction = action
		}
	}

	if routeAction == "reject" {
		http.Error(w, "已根据规则拦截", http.StatusForbidden)
		stats.AddConnLog(targetAddr, "Blocked")
		return
	} else if routeAction == "direct" {
		nodeUsed = "Direct"
		upstream, err = net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if err != nil {
			http.Error(w, "直连失败: "+err.Error(), http.StatusBadGateway)
			return
		}
	} else {
		var targetClient common.GenericClient
		if routeAction == "proxy" || routeAction == "" {
			nodeUsed = nodeName
			if nodeUsed == "" {
				nodeUsed = "Proxy"
			}
			targetClient = client
		} else {
			if node, found := GetNodeForRoute(routeAction); found {
				nodeUsed = node.Name
				targetClient, err = GetNodeClient(node)
				if err != nil {
					http.Error(w, "规则代理节点初始化失败: "+err.Error(), http.StatusServiceUnavailable)
					return
				}
			} else {
				nodeUsed = nodeName
				if nodeUsed == "" {
					nodeUsed = "Proxy"
				}
				targetClient = client
			}
		}

		if targetClient == nil {
			http.Error(w, "尚未选择或初始化任何节点！", http.StatusServiceUnavailable)
			return
		}
		dest := metadata.ParseSocksaddr(targetAddr)
		upstream, err = targetClient.CreateProxy(req.Context(), dest)
		if err != nil {
			http.Error(w, "代理连接失败: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
	}

	var logID int64
	if !common.PrivacyMode {
		logID = stats.AddConnLog(targetAddr, nodeUsed)
	}
	// 代理节点流量监控包装
	tc := &TrackingConn{Conn: upstream, logID: logID, node: nodeUsed}
	upstream = tc

	defer func() {
		tc.Conn.Close()
		stats.AddSessionTraffic(tc.node, tc.in-tc.lastStatIn, tc.out-tc.lastStatOut)
		if !common.PrivacyMode {
			stats.UpdateConnLog(logID, tc.in, tc.out, true)
		}
	}()

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

	utils.SafeGo("proxy upload copy", func() {
		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)
		io.CopyBuffer(upstream, bufrw, buf)
	})

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	io.CopyBuffer(clientConn, upstream, buf)
}
