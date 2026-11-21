package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"wing/pkg/common"
	"wing/pkg/stats"
	"wing/pkg/utils"
)

var (
	localSocksServerMu sync.Mutex
	localSocksServer   net.Listener
)

func launchLocalSOCKSProxyServer() error {
	addr := "127.0.0.1:" + common.LocalSocksPort
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	localSocksServerMu.Lock()
	localSocksServer = ln
	localSocksServerMu.Unlock()

	log.Printf("SOCKS5 代理监听: %s", addr)
	utils.SafeGo("local socks5 proxy listener", func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				break
			}
			utils.SafeGo("socks5 conn", func() {
				handleSOCKS5(conn)
			})
		}
	})
	return nil
}

func shutdownLocalSOCKSProxyServer() {
	localSocksServerMu.Lock()
	ln := localSocksServer
	localSocksServer = nil
	localSocksServerMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

func handleSOCKS5(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 1. Read version and methods
	buf := make([]byte, 256)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}

	// 2. Reply with NO AUTHENTICATION REQUIRED
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 3. Read request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}

	cmd := buf[1]
	addrType := buf[3]

	var host string
	switch addrType {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		host = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return
		}
		host = string(buf[:domainLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	if cmd == 0x03 {
		// UDP ASSOCIATE
		// 拒绝 UDP 并返回 0x07 (Command not supported)
		// 这会让 TUN 栈立即给应用返回不可达，促使微信等应用快速回退到 TCP
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if cmd != 0x01 {
		// CONNECT only
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	atomic.AddInt32(&stats.ActiveConnections, 1)
	defer atomic.AddInt32(&stats.ActiveConnections, -1)

	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	remoteAddr := ""
	if conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}
	upstream, resolvedTarget, nodeUsed, errStatus, err := dialProxyUpstream(dialCtx, targetAddr, remoteAddr)
	cancel()
	if err != nil {
		if errStatus == http.StatusForbidden {
			if !common.PrivacyMode {
				logID := stats.AddConnLog(resolvedTarget, "Blocked")
				stats.UpdateConnLog(logID, 0, 0, true)
			}
			_, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	tc, finishTracking := startTrackingConn(upstream, resolvedTarget, nodeUsed)
	defer finishTracking()

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	relayTrackedConn(conn, conn, tc)
}
