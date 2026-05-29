package proxy

import (
	"wing/pkg/common"
	"wing/pkg/freeflow"
	"wing/pkg/routing"
	"wing/pkg/stats"
	"wing/pkg/utils"

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
	in          atomic.Uint64
	out         atomic.Uint64
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
		totalIn := c.in.Add(bytes)
		if totalIn-c.lastStatIn >= updateThreshold {
			delta := totalIn - c.lastStatIn
			stats.AddSessionTraffic(c.node, delta, 0)
			if freeflow.IsNodeName(c.node) && freeflow.AddUsage(c.node, delta).Exceeded {
				_ = c.Conn.Close()
			}
			c.lastStatIn = totalIn
		}
		// 限制 UpdateConnLog 调用频率，减少锁竞争
		if totalIn-c.lastLogIn >= updateThreshold {
			stats.UpdateConnLog(c.logID, totalIn, c.out.Load(), false)
			c.lastLogIn = totalIn
		}
	}
	return
}

func (c *TrackingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		bytes := uint64(n)
		atomic.AddUint64(&common.GlobalProxyOut, bytes)
		totalOut := c.out.Add(bytes)
		if totalOut-c.lastStatOut >= updateThreshold {
			delta := totalOut - c.lastStatOut
			stats.AddSessionTraffic(c.node, 0, delta)
			if freeflow.IsNodeName(c.node) && freeflow.AddUsage(c.node, delta).Exceeded {
				_ = c.Conn.Close()
			}
			c.lastStatOut = totalOut
		}
		if totalOut-c.lastLogOut >= updateThreshold {
			stats.UpdateConnLog(c.logID, c.in.Load(), totalOut, false)
			c.lastLogOut = totalOut
		}
	}
	return
}

func (c *TrackingConn) Totals() (uint64, uint64) {
	return c.in.Load(), c.out.Load()
}

type HTTPProxyHandler struct{}

func dialDirect(targetAddr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if common.IsTunModeOn && common.RealLocalIPBeforeTun != "" {
		if ip := net.ParseIP(common.RealLocalIPBeforeTun); ip != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: 0}
		}
	}
	return dialer.Dial("tcp", targetAddr)
}

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

	// 🚀 TUN Mode IP -> Domain Restore
	if host, port, err := net.SplitHostPort(targetAddr); err == nil && net.ParseIP(host) != nil {
		if d, ok := IPToDomainMap.Load(host); ok {
			domain := strings.TrimSuffix(d.(string), ".")
			targetAddr = net.JoinHostPort(domain, port)
		}
	} else if err != nil && net.ParseIP(targetAddr) != nil {
		if d, ok := IPToDomainMap.Load(targetAddr); ok {
			targetAddr = strings.TrimSuffix(d.(string), ".")
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
		logID := stats.AddConnLog(targetAddr, "Blocked")
		stats.UpdateConnLog(logID, 0, 0, true)
		return
	} else if routeAction == "direct" {
		nodeUsed = "Direct"
		upstream, err = dialDirect(targetAddr)
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
			if !freeflow.CanUse(nodeUsed) {
				http.Error(w, "本周免费流量已用完，下周自动恢复。", http.StatusTooManyRequests)
				return
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
			nodeUsed = "Direct"
			upstream, err = dialDirect(targetAddr)
			if err != nil {
				http.Error(w, "直连失败: "+err.Error(), http.StatusBadGateway)
				return
			}
		} else {
			dest := metadata.ParseSocksaddr(targetAddr)
			upstream, err = targetClient.CreateProxy(req.Context(), dest)
			if err != nil {
				http.Error(w, "代理连接失败: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
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
		in, out := tc.Totals()
		finalIn := in - tc.lastStatIn
		finalOut := out - tc.lastStatOut
		stats.AddSessionTraffic(tc.node, finalIn, finalOut)
		if freeflow.IsNodeName(tc.node) {
			freeflow.AddUsage(tc.node, finalIn+finalOut)
		}
		if !common.PrivacyMode {
			stats.UpdateConnLog(logID, in, out, true)
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
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = upstream.Close()
			_ = clientConn.Close()
		})
	}
	defer closeBoth()

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

	uploadDone := make(chan struct{})
	utils.SafeGo("proxy upload copy", func() {
		defer close(uploadDone)
		defer closeBoth()
		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)
		io.CopyBuffer(upstream, bufrw, buf)
	})

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	io.CopyBuffer(clientConn, upstream, buf)
	closeBoth()
	<-uploadDone
}
