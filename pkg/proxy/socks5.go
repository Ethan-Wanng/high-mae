package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
	"wing/pkg/common"
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
	targetAddr := fmt.Sprintf("%s:%d", host, port)

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

	// Reply Success
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	// 模拟 HTTP CONNECT 请求转发给本地 HTTPProxyHandler 处理
	// 这样可以复用所有路由规则和统计逻辑
	proxyConn, err := net.DialTimeout("tcp", "127.0.0.1:"+common.LocalHttpPort, 5*time.Second)
	if err != nil {
		return
	}
	defer proxyConn.Close()

	connectReq, _ := http.NewRequest(http.MethodConnect, "http://"+targetAddr, nil)
	connectReq.Host = targetAddr
	if err := connectReq.Write(proxyConn); err != nil {
		return
	}

	// 读取 200 OK 响应
	respBuf := make([]byte, 1024)
	n, err := proxyConn.Read(respBuf)
	if err != nil || n == 0 {
		return
	}
	// 不把 200 OK 发给 client，因为 SOCKS5 已经握手成功了，直接开始双向传输

	// 双向复制
	go func() {
		_, _ = io.Copy(proxyConn, conn)
		_ = proxyConn.Close()
	}()
	_, _ = io.Copy(conn, proxyConn)
}
