package ins

import (
	"context"
	"fmt"
	"github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

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
	if ShouldDirect(targetAddr) {
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

func StartLocalDNS() {
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 53}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}

	for {
		buf := make([]byte, 2048)
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		req := make([]byte, n)
		copy(req, buf[:n])

		go func(request []byte, cAddr *net.UDPAddr) {
			clientMu.RLock()
			client := activeClient
			clientMu.RUnlock()
			if client == nil {
				return
			}

			dest := metadata.ParseSocksaddr("8.8.8.8:53")
			stream, err := client.CreateProxy(context.Background(), dest)
			if err != nil {
				return
			}
			defer stream.Close()

			length := uint16(len(request))
			stream.Write([]byte{byte(length >> 8), byte(length)})
			stream.Write(request)

			respLenBuf := make([]byte, 2)
			if _, err := io.ReadFull(stream, respLenBuf); err != nil {
				return
			}
			respLen := int(respLenBuf[0])<<8 | int(respLenBuf[1])
			resp := make([]byte, respLen)
			if _, err := io.ReadFull(stream, resp); err != nil {
				return
			}

			conn.WriteToUDP(resp, cAddr)
		}(req, clientAddr)
	}
}
