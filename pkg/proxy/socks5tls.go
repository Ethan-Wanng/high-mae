package proxy

import (
	"high-mae/pkg/common"
	"high-mae/pkg/utils"

	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/sagernet/sing/common/metadata"
)

// Socks5TLSAdapter 实现 GenericClient 接口，
// 专门处理 sing-box 原生 SOCKS outbound 不支持的 SOCKS5-over-TLS 场景。
//
// 工作流程：TCP dial → uTLS 握手 → SOCKS5 协议协商 (auth + CONNECT) → 返回可用连接
type Socks5TLSAdapter struct {
	Server         string
	ResolvedIP     string // 预解析好的 IP（绕过 DNS 污染）
	Port           int
	Username       string
	Password       string
	SNI            string
	SkipCertVerify bool
}

func (s *Socks5TLSAdapter) CreateProxy(ctx context.Context, dest metadata.Socksaddr) (net.Conn, error) {
	// 1. 确定目标拨号地址
	dialHost := s.Server
	if s.ResolvedIP != "" {
		dialHost = s.ResolvedIP
	}
	addr := net.JoinHostPort(dialHost, fmt.Sprint(s.Port))

	// 2. 建立 TCP 连接
	var localAddr net.Addr
	if common.IsTunModeOn {
		realIP := utils.GetRealLocalIP()
		if realIP != "" && realIP != common.TunIP {
			localAddr = &net.TCPAddr{IP: net.ParseIP(realIP), Port: 0}
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, LocalAddr: localAddr}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5-TLS TCP 连接失败: %w", err)
	}

	// 3. TLS 握手（使用 uTLS 伪装浏览器指纹，与 AnyTLS 保持一致）
	sni := s.SNI
	if sni == "" {
		sni = s.Server
	}
	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: s.SkipCertVerify,
	}
	tlsConn := utls.UClient(rawConn, tlsConfig, utls.HelloFirefox_Auto)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("SOCKS5-TLS TLS 握手失败: %w", err)
	}

	// 4. 在 TLS 隧道内执行 SOCKS5 协议协商
	if err := socks5Handshake(tlsConn, s.Username, s.Password, dest); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// socks5Handshake 在已建立的连接上执行完整的 SOCKS5 握手流程：
//  1. 方法协商（无认证 / 用户名密码认证）
//  2. 如需认证，发送用户名密码
//  3. 发送 CONNECT 请求
//
// RFC 1928 - SOCKS Protocol Version 5
// RFC 1929 - Username/Password Authentication for SOCKS V5
func socks5Handshake(conn net.Conn, username, password string, dest metadata.Socksaddr) error {
	// ============================================================
	// 步骤 1: 方法协商
	// ============================================================
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	var greeting []byte
	if username != "" || password != "" {
		// 提供两种方法：0x00 (无认证) + 0x02 (用户名/密码)
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		// 只提供无认证
		greeting = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("SOCKS5 握手发送失败: %w", err)
	}

	// 读取服务器选择的方法
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodResp); err != nil {
		return fmt.Errorf("SOCKS5 握手响应读取失败: %w", err)
	}
	if methodResp[0] != 0x05 {
		return fmt.Errorf("SOCKS5 版本不匹配: 期望 0x05, 收到 0x%02x", methodResp[0])
	}

	// ============================================================
	// 步骤 2: 认证（如果服务器选择了 0x02）
	// ============================================================
	switch methodResp[1] {
	case 0x00:
		// 无需认证，直接进入下一步
	case 0x02:
		// RFC 1929 用户名/密码认证
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+
		authReq := make([]byte, 0, 3+len(username)+len(password))
		authReq = append(authReq, 0x01) // 子协商版本号
		authReq = append(authReq, byte(len(username)))
		authReq = append(authReq, []byte(username)...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, []byte(password)...)

		if _, err := conn.Write(authReq); err != nil {
			return fmt.Errorf("SOCKS5 认证请求发送失败: %w", err)
		}

		// +----+--------+
		// |VER | STATUS |
		// +----+--------+
		// | 1  |   1    |
		// +----+--------+
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return fmt.Errorf("SOCKS5 认证响应读取失败: %w", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("SOCKS5 认证被拒绝 (status=0x%02x)，请检查用户名和密码", authResp[1])
		}
	case 0xFF:
		return fmt.Errorf("SOCKS5 服务器拒绝所有认证方法")
	default:
		return fmt.Errorf("SOCKS5 服务器选择了不支持的认证方法: 0x%02x", methodResp[1])
	}

	// ============================================================
	// 步骤 3: 发送 CONNECT 请求
	// ============================================================
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	var connectReq []byte
	connectReq = append(connectReq, 0x05, 0x01, 0x00) // VER=5, CMD=CONNECT, RSV=0

	if dest.IsFqdn() {
		// ATYP = 0x03 (域名)
		domain := dest.Fqdn
		connectReq = append(connectReq, 0x03, byte(len(domain)))
		connectReq = append(connectReq, []byte(domain)...)
	} else {
		ip := dest.Addr.As16()
		if dest.Addr.Is4() {
			// ATYP = 0x01 (IPv4)
			ip4 := dest.Addr.As4()
			connectReq = append(connectReq, 0x01)
			connectReq = append(connectReq, ip4[:]...)
		} else {
			// ATYP = 0x04 (IPv6)
			connectReq = append(connectReq, 0x04)
			connectReq = append(connectReq, ip[:]...)
		}
	}

	// 端口（2 字节，大端序）
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, dest.Port)
	connectReq = append(connectReq, portBuf...)

	if _, err := conn.Write(connectReq); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT 请求发送失败: %w", err)
	}

	// 读取 CONNECT 响应
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return fmt.Errorf("SOCKS5 CONNECT 响应读取失败: %w", err)
	}
	if respHeader[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT 被拒绝 (REP=0x%02x): %s", respHeader[1], socks5RepMessage(respHeader[1]))
	}

	// 读取并丢弃 BND.ADDR + BND.PORT（我们不需要）
	switch respHeader[3] {
	case 0x01: // IPv4: 4 bytes + 2 bytes port
		discard := make([]byte, 4+2)
		io.ReadFull(conn, discard)
	case 0x03: // Domain: 1 byte len + N bytes + 2 bytes port
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		discard := make([]byte, int(lenBuf[0])+2)
		io.ReadFull(conn, discard)
	case 0x04: // IPv6: 16 bytes + 2 bytes port
		discard := make([]byte, 16+2)
		io.ReadFull(conn, discard)
	}

	return nil
}

// socks5RepMessage 将 SOCKS5 REP 字段翻译为人类可读的错误消息
func socks5RepMessage(rep byte) string {
	switch rep {
	case 0x01:
		return "一般性 SOCKS 服务器故障"
	case 0x02:
		return "规则不允许此连接"
	case 0x03:
		return "网络不可达"
	case 0x04:
		return "主机不可达"
	case 0x05:
		return "连接被拒绝"
	case 0x06:
		return "TTL 过期"
	case 0x07:
		return "不支持的命令"
	case 0x08:
		return "不支持的地址类型"
	default:
		return "未知错误"
	}
}
