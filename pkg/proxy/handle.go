package proxy

import (
	"wing/pkg/common"
	"wing/pkg/routing"
	"wing/pkg/stats"
	"wing/pkg/utils"

	"context"
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

func directTCPDialer() (*net.Dialer, net.IP) {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 15 * time.Second,
	}
	if !common.GetTunModeOn() {
		return dialer, nil
	}
	realIP := common.RealLocalIPBeforeTun
	if realIP == "" {
		realIP = utils.GetRealLocalIP()
	}
	ip := net.ParseIP(realIP)
	if ip != nil && realIP != common.TunIP {
		dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: 0}
		return dialer, ip
	}
	return dialer, nil
}

func dialDirectAddrWithLocalIP(baseDialer *net.Dialer, localIP net.IP, targetIPStr, port string) (net.Conn, error) {
	targetIP := net.ParseIP(targetIPStr)
	dialer := baseDialer
	if localIP != nil && targetIP != nil && (targetIP.IsLoopback() || (localIP.To4() != nil) != (targetIP.To4() != nil)) {
		copied := *baseDialer
		copied.LocalAddr = nil
		dialer = &copied
	}
	return dialer.Dial("tcp", net.JoinHostPort(targetIPStr, port))
}

func dialDirect(targetAddr string) (net.Conn, error) {
	dialer, localIP := directTCPDialer()

	host, port, err := net.SplitHostPort(targetAddr)
	if err == nil && net.ParseIP(host) == nil && !strings.EqualFold(host, "localhost") && strings.Contains(host, ".") {
		ctx, cancel := context.WithTimeout(context.Background(), directDNSQueryTimeout)
		ips, resolveErr := resolveDirectHost(ctx, host)
		cancel()
		if resolveErr == nil && len(ips) > 0 {
			var lastErr error
			for _, ip := range ips {
				conn, dialErr := dialDirectAddrWithLocalIP(dialer, localIP, ip, port)
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			if lastErr != nil {
				return nil, lastErr
			}
		}
	} else if err == nil && localIP != nil {
		if targetIP := net.ParseIP(host); targetIP != nil {
			return dialDirectAddrWithLocalIP(dialer, localIP, host, port)
		}
	}
	return dialer.Dial("tcp", targetAddr)
}

func restoreTargetAddr(rawTargetAddr string) (targetAddr string, directDialAddr string) {
	targetAddr = rawTargetAddr
	directDialAddr = rawTargetAddr

	// 🚀 TUN Mode IP -> Domain Restore
	if host, port, err := net.SplitHostPort(targetAddr); err == nil && net.ParseIP(host) != nil {
		if domain, ok := domainForIP(host); ok {
			domain = strings.TrimSuffix(domain, ".")
			directDialAddr = net.JoinHostPort(host, port)
			targetAddr = net.JoinHostPort(domain, port)
		}
	} else if err != nil && net.ParseIP(targetAddr) != nil {
		if domain, ok := domainForIP(targetAddr); ok {
			targetAddr = strings.TrimSuffix(domain, ".")
		}
	}
	return targetAddr, directDialAddr
}

func dialProxyUpstream(ctx context.Context, rawTargetAddr, remoteAddr string) (upstream net.Conn, targetAddr string, nodeUsed string, errStatus int, err error) {
	client := common.GetActiveClient()
	_, nodeName := common.ActiveNodeSnapshot()

	targetAddr, directDialAddr := restoreTargetAddr(rawTargetAddr)
	routeAction := routing.EvaluateRouting(targetAddr)

	// 🚀 新增命令行进程路由规则匹配
	cmdline, _ := utils.GetProcessCommandLineFromRemoteAddr(remoteAddr)
	if cmdline != "" {
		if action, matched := routing.EvaluateCmdRouting(cmdline); matched {
			routeAction = action
		}
	}

	if routeAction == "reject" {
		return nil, targetAddr, "Blocked", http.StatusForbidden, fmt.Errorf("已根据规则拦截")
	}
	if routeAction == "direct" {
		upstream, err = dialDirect(directDialAddr)
		if err != nil {
			return nil, targetAddr, "Direct", http.StatusBadGateway, fmt.Errorf("直连失败: %w", err)
		}
		return upstream, targetAddr, "Direct", 0, nil
	}

	var targetClient common.GenericClient
	if routeAction == "proxy" || routeAction == "" {
		nodeUsed = nodeName
		if nodeUsed == "" {
			nodeUsed = "Proxy"
		}
		targetClient = client
	} else if node, found := GetNodeForRoute(routeAction); found {
		nodeUsed = node.Name
		targetClient, err = GetNodeClient(node)
		if err != nil {
			return nil, targetAddr, nodeUsed, http.StatusServiceUnavailable, fmt.Errorf("规则代理节点初始化失败: %w", err)
		}
	} else {
		nodeUsed = nodeName
		if nodeUsed == "" {
			nodeUsed = "Proxy"
		}
		targetClient = client
	}

	if targetClient == nil {
		upstream, err = dialDirect(directDialAddr)
		if err != nil {
			return nil, targetAddr, "Direct", http.StatusBadGateway, fmt.Errorf("直连失败: %w", err)
		}
		return upstream, targetAddr, "Direct", 0, nil
	}

	dest := metadata.ParseSocksaddr(targetAddr)
	upstream, err = targetClient.CreateProxy(ctx, dest)
	if err != nil {
		return nil, targetAddr, nodeUsed, http.StatusServiceUnavailable, fmt.Errorf("代理连接失败: %w", err)
	}
	return upstream, targetAddr, nodeUsed, 0, nil
}

func startTrackingConn(upstream net.Conn, targetAddr, nodeUsed string) (*TrackingConn, func()) {
	var logID int64
	if !common.PrivacyMode {
		logID = stats.AddConnLog(targetAddr, nodeUsed)
	}
	tc := &TrackingConn{Conn: upstream, logID: logID, node: nodeUsed}
	finish := func() {
		_ = tc.Conn.Close()
		in, out := tc.Totals()
		finalIn := in - tc.lastStatIn
		finalOut := out - tc.lastStatOut
		stats.AddSessionTraffic(tc.node, finalIn, finalOut)
		if !common.PrivacyMode {
			stats.UpdateConnLog(logID, in, out, true)
		}
	}
	return tc, finish
}

func relayTrackedConn(clientConn net.Conn, clientReader io.Reader, upstream io.ReadWriteCloser) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = upstream.Close()
			_ = clientConn.Close()
		})
	}
	defer closeBoth()

	uploadDone := make(chan struct{})
	utils.SafeGo("proxy upload copy", func() {
		defer close(uploadDone)
		defer closeBoth()
		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)
		_, _ = io.CopyBuffer(upstream, clientReader, buf)
	})

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	_, _ = io.CopyBuffer(clientConn, upstream, buf)
	closeBoth()
	<-uploadDone
}

func (h *HTTPProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	atomic.AddInt32(&stats.ActiveConnections, 1)
	defer atomic.AddInt32(&stats.ActiveConnections, -1)

	targetAddr := req.Host
	if !strings.Contains(targetAddr, ":") {
		if req.Method == http.MethodConnect {
			targetAddr += ":443"
		} else {
			targetAddr += ":80"
		}
	}

	upstream, resolvedTarget, nodeUsed, errStatus, err := dialProxyUpstream(req.Context(), targetAddr, req.RemoteAddr)
	if err != nil {
		if errStatus == http.StatusForbidden {
			http.Error(w, "已根据规则拦截", http.StatusForbidden)
			if !common.PrivacyMode {
				logID := stats.AddConnLog(resolvedTarget, "Blocked")
				stats.UpdateConnLog(logID, 0, 0, true)
			}
			return
		}
		if errStatus == 0 {
			errStatus = http.StatusBadGateway
		}
		http.Error(w, err.Error(), errStatus)
		return
	}

	tc, finishTracking := startTrackingConn(upstream, resolvedTarget, nodeUsed)
	defer finishTracking()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			_ = clientConn.Close()
			return
		}
	} else {
		reqPath := req.URL.Path
		if reqPath == "" {
			reqPath = "/"
		}
		if req.URL.RawQuery != "" {
			reqPath += "?" + req.URL.RawQuery
		}
		if _, err := fmt.Fprintf(tc, "%s %s HTTP/1.1\r\n", req.Method, reqPath); err != nil {
			_ = clientConn.Close()
			return
		}
		if err := req.Header.Write(tc); err != nil {
			_ = clientConn.Close()
			return
		}
		if _, err := fmt.Fprintf(tc, "\r\n"); err != nil {
			_ = clientConn.Close()
			return
		}
	}

	relayTrackedConn(clientConn, bufrw, tc)
}

func domainForIP(ip string) (string, bool) {
	value, ok := IPToDomainMap.Load(ip)
	if !ok {
		return "", false
	}
	entry, ok := value.(ipDomainEntry)
	if !ok || time.Now().After(entry.expiresAt) {
		deleteIPDomainMapping(ip)
		return "", false
	}
	return entry.domain, true
}
