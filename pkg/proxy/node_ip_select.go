package proxy

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"wing/pkg/common"
	"wing/pkg/utils"
	"wing/protocol"
)

// 机场常把一个节点域名解析到一组轮换 IP，其中部分可能已下线。mihomo 拨号时会依次尝试
// 全部地址，而这里只能把一个 IP 交给协议栈，因此先并发探测所有候选地址、取最先连通者：
// TCP 类协议用 TCP 握手，QUIC 类协议（Hysteria2/TUIC/Naive QUIC）用 QUIC 版本协商探测。

const (
	nodeIPProbeTimeout = 1500 * time.Millisecond
	nodeIPChoiceTTL    = 2 * time.Minute
)

type nodeIPChoice struct {
	ip      string
	expires time.Time
}

var (
	nodeIPChoiceMu sync.Mutex
	nodeIPChoices  = make(map[string]nodeIPChoice)
)

// pickReachableNodeIP 按优先级依次探测各组候选地址（如优先 IPv6 时先 IPv6 再 IPv4），
// 返回最先连通的地址；都探测不通时退回首选组的第一个地址。
func pickReachableNodeIP(node protocol.Node, groups [][]string) string {
	fallback := ""
	for _, group := range groups {
		if len(group) > 0 {
			fallback = group[0]
			break
		}
	}
	if fallback == "" {
		return ""
	}
	port := nodeProbePort(node)
	quic := isQUICNode(node)
	if !quic && isUDPNode(node) {
		// 非 QUIC 的 UDP 传输（如 Mieru UDP）没有通用的存活探测方式。
		return fallback
	}
	key := strings.ToLower(node.Server) + "|" + strconv.Itoa(port) + "|" + strconv.FormatBool(quic)

	nodeIPChoiceMu.Lock()
	if choice, ok := nodeIPChoices[key]; ok && time.Now().Before(choice.expires) && groupsContain(groups, choice.ip) {
		nodeIPChoiceMu.Unlock()
		return choice.ip
	}
	nodeIPChoiceMu.Unlock()

	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		if winner := raceNodeIPs(group, port, quic); winner != "" {
			nodeIPChoiceMu.Lock()
			nodeIPChoices[key] = nodeIPChoice{ip: winner, expires: time.Now().Add(nodeIPChoiceTTL)}
			nodeIPChoiceMu.Unlock()
			return winner
		}
	}
	return fallback
}

func groupsContain(groups [][]string, target string) bool {
	for _, group := range groups {
		if containsString(group, target) {
			return true
		}
	}
	return false
}

func raceNodeIPs(candidates []string, port int, quic bool) string {
	ctx, cancel := context.WithTimeout(context.Background(), nodeIPProbeTimeout)
	defer cancel()

	winners := make(chan string, len(candidates))
	for _, ip := range candidates {
		ip := ip
		go func() {
			addr := net.JoinHostPort(ip, strconv.Itoa(port))
			var err error
			if quic {
				err = probeQUIC(ctx, addr)
			} else {
				err = probeTCP(ctx, addr)
			}
			if err != nil {
				winners <- ""
				return
			}
			winners <- ip
		}()
	}
	for range candidates {
		if ip := <-winners; ip != "" {
			return ip
		}
	}
	return ""
}

func probeTCP(ctx context.Context, addr string) error {
	dialer := &net.Dialer{LocalAddr: tunBypassLocalAddr(false)}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// probeQUIC 发送一个使用保留版本号的 QUIC Long Header 包（≥1200 字节）。按 RFC 9000 §6.1，
// 存活的 QUIC 服务端必须回复 Version Negotiation，收到任何回包即视为可达。
func probeQUIC(ctx context.Context, addr string) error {
	dialer := &net.Dialer{LocalAddr: tunBypassLocalAddr(true)}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	packet := make([]byte, 1200)
	packet[0] = 0xC0                                                           // Long Header + Fixed Bit
	copy(packet[1:5], []byte{0xBA, 0xBA, 0xBA, 0xBA})                          // 不存在的版本号，强制触发版本协商
	packet[5] = 8                                                              // DCID 长度
	copy(packet[6:14], []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}) // DCID
	if _, err := conn.Write(packet); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	_, err = conn.Read(buf)
	return err
}

// tunBypassLocalAddr 在 TUN 开启时返回真实网卡地址，避免探测流量绕回隧道。
func tunBypassLocalAddr(udp bool) net.Addr {
	if !common.GetTunModeOn() {
		return nil
	}
	realIP := common.RealLocalIPBeforeTun
	if realIP == "" {
		realIP = utils.GetRealLocalIP()
	}
	if realIP == "" || realIP == common.TunIP {
		return nil
	}
	if udp {
		return &net.UDPAddr{IP: net.ParseIP(realIP)}
	}
	return &net.TCPAddr{IP: net.ParseIP(realIP)}
}

func nodeProbePort(node protocol.Node) int {
	if node.Port > 0 {
		return node.Port
	}
	for _, ports := range []string{node.PortRange, node.Ports, node.MPort} {
		if port := parseFirstPort(ports); port > 0 {
			return port
		}
	}
	return 443
}

func isQUICNode(node protocol.Node) bool {
	switch node.Type {
	case "tuic", "hysteria2", "hy2":
		return true
	case "naive":
		return node.QUIC
	}
	return false
}

func isUDPNode(node protocol.Node) bool {
	return isQUICNode(node) || (node.Type == "mieru" && strings.EqualFold(node.Transport, "UDP"))
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
