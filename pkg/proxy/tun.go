package proxy

import (
	"high-mae/pkg/common"
	"high-mae/pkg/utils"

	"context"
	"fmt"
	"log"
	"net"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// =====================================================
// sing-box TUN 管理器
// 采用 sing-box 推荐的 JSON 配置 → box.New 方式创建独立 TUN 实例
//
// 配置要点（遵循 sing-box 官方文档推荐）：
//   - mixed 网络栈（TCP 走系统栈高性能，UDP 走 gvisor 保兼容）
//   - FakeIP DNS 避免 DNS 泄漏
//   - auto_route + strict_route 全接管
//   - route 规则：DNS hijack → 节点服务器直连 → 私有 IP 直连 → 其余走 proxy
//   - proxy outbound 指向本地 HTTP 代理端口，兼容所有底层引擎
// =====================================================

var (
	tunBox *box.Box
	tunMu  sync.Mutex
)

// ToggleTunMode 切换 TUN 模式的开/关状态，返回需要展示给用户的消息（空串表示成功）
func ToggleTunMode() string {
	tunMu.Lock()
	defer tunMu.Unlock()

	if common.IsTunModeOn {
		// 关闭 TUN
		stopTunLocked()
		common.IsTunModeOn = false
		if common.MToggleTun != nil {
			common.MToggleTun.SetTitle("🔌 虚拟网卡 (TUN): [已关闭]")
		}
		log.Println("TUN 模式已关闭")
		return ""
	}

	// 开启 TUN
	if !utils.IsAdmin() {
		return "开启虚拟网卡(TUN)需要管理员权限！请以管理员身份运行。"
	}
	if err := startTunLocked(); err != nil {
		return fmt.Sprintf("启动 TUN 失败: %v", err)
	}
	common.IsTunModeOn = true
	if common.MToggleTun != nil {
		common.MToggleTun.SetTitle("🟢 虚拟网卡 (TUN): [已开启]")
	}
	log.Println("TUN 模式已开启")
	return ""
}

// RestartSingBoxTun 重启 TUN（在切换节点后由 proxy.go 调用）
func RestartSingBoxTun() error {
	tunMu.Lock()
	defer tunMu.Unlock()

	stopTunLocked()
	return startTunLocked()
}

// StopSingBoxTun 停止 TUN（程序退出时由 main.go 调用）
func StopSingBoxTun() {
	tunMu.Lock()
	defer tunMu.Unlock()

	stopTunLocked()
}

// =====================================================
// 内部实现
// =====================================================

// stopTunLocked 关闭正在运行的 TUN Box 实例（调用者必须持有 tunMu）
func stopTunLocked() {
	if tunBox != nil {
		tunBox.Close()
		tunBox = nil
		log.Println("旧 TUN 实例已关闭")
	}
}

// startTunLocked 启动一个全新的 TUN Box 实例（调用者必须持有 tunMu）
//
// 🏗️ 架构设计说明：
// sing-box 推荐的配置方式是构造完整 JSON → 通过 include.Context 解析 → box.New
// 这样所有 Inbound/Outbound/DNS/Route 的 Registry 会自动注入，
// 避免了手动构造 Inbound{Type:"tun", Options:...} 时缺少 registry 导致的空指针崩溃。
func startTunLocked() error {
	// ── 1. 获取当前活动节点的服务器信息（用于防环路路由规则） ──
	common.ClientMu.RLock()
	nodeServer := common.GlobalNodeServer
	nodeIP := common.GlobalNodeIP
	common.ClientMu.RUnlock()

	// ── 2. 构造完整的 sing-box JSON 配置 ──
	tunConfig := buildTunConfigJSON(nodeServer, nodeIP)

	// ── 3. 通过 JSON 解析创建 Options ──
	ctx := include.Context(context.Background())
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, tunConfig); err != nil {
		return fmt.Errorf("解析 TUN 配置失败: %w", err)
	}

	// ── 4. 创建并启动 Box ──
	b, err := box.New(box.Options{
		Options: opts,
		Context: ctx,
	})
	if err != nil {
		return fmt.Errorf("创建 TUN 引擎失败: %w", err)
	}
	if err := b.Start(); err != nil {
		b.Close()
		return fmt.Errorf("启动 TUN 引擎失败: %w", err)
	}

	tunBox = b
	return nil
}

// buildTunConfigJSON 构造完整的 sing-box TUN 配置 JSON
//
// 配置遵循 sing-box 官方推荐架构：
//
// ┌──────────────────────────────────────────────────────────┐
// │                    sing-box TUN 实例                       │
// │                                                          │
// │  ┌────────────┐    ┌───────────────┐    ┌──────────────┐ │
// │  │  TUN 入站   │ →  │  路由规则引擎  │ →  │  出站选择    │ │
// │  │ (mixed 栈)  │    │ DNS→hijack    │    │ proxy/direct │ │
// │  │ auto_route  │    │ 私有IP→direct │    │              │ │
// │  └────────────┘    │ 其余→proxy    │    └──────────────┘ │
// │                    └───────────────┘                      │
// │                                                          │
// │  ┌────────────────────────────────────┐                  │
// │  │           DNS 模块                  │                  │
// │  │ remote-dns: 谷歌 DoH → proxy      │                  │
// │  │ local-dns:  阿里 DoH → direct     │                  │
// │  │ fakeip:     198.18.0.0/15         │                  │
// │  └────────────────────────────────────┘                  │
// │                                                          │
// │  proxy outbound → 127.0.0.1:10808 (本地 HTTP 代理)       │
// └──────────────────────────────────────────────────────────┘
//
// DNS 配置采用 legacy 格式（address 字段），mbox 会自动升级为新格式。
// Route 规则使用 ip_is_private 匹配所有私有 IP 段，简洁且无遗漏。
func buildTunConfigJSON(nodeServer, nodeIP string) []byte {
	// ── 构造节点服务器 IP 直连规则（防止 TUN 流量环路） ──
	serverIPRule := ""
	if nodeIP != "" {
		ip := net.ParseIP(nodeIP)
		if ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			serverIPRule = fmt.Sprintf(`
				{
					"ip_cidr": ["%s/%d"],
					"outbound": "direct"
				},`, nodeIP, bits)
		}
	}

	// 如果节点地址是域名（与解析出的 IP 不同），也需要直连
	serverDomainRule := ""
	if nodeServer != "" && nodeServer != nodeIP {
		// 确保 nodeServer 确实是域名而非 IP
		if net.ParseIP(nodeServer) == nil {
			serverDomainRule = fmt.Sprintf(`
				{
					"domain": ["%s"],
					"outbound": "direct"
				},`, nodeServer)
		}
	}

	// ── sing-box 推荐的 TUN 配置模板 ──
	//
	// DNS 架构:
	//   - remote-dns: 谷歌 DoH，走 proxy 出站（解决 DNS 污染）
	//   - local-dns:  阿里 DoH，走 direct 出站（用于解析代理服务器本身的域名）
	//   - fakeip:     虚拟 IP 池，A/AAAA 查询走 fakeip（实现透明代理）
	//
	// DNS 规则:
	//   - outbound=any 的流量走 local-dns（代理服务器域名解析不能走代理）
	//   - A/AAAA 查询走 fakeip（普通域名用虚拟 IP 替代，由 TUN 接管）
	//   - 其余走 remote-dns（如 PTR、MX 等特殊查询）
	//
	// Route 规则:
	//   - DNS 协议流量→hijack-dns（劫持到内置 DNS 模块处理）
	//   - 节点服务器 IP/域名→direct（防止流量环路）
	//   - 私有 IP→direct（局域网/本地回环不走代理）
	//   - 其余→proxy（发往本地 HTTP 代理端口）
	config := fmt.Sprintf(`{
	"log": {
		"level": "warn"
	},
	"dns": {
		"servers": [
			{
				"tag": "remote-dns",
				"address": "https://dns.google/dns-query",
				"detour": "proxy"
			},
			{
				"tag": "local-dns",
				"address": "https://223.5.5.5/dns-query",
				"detour": "direct"
			},
			{
				"tag": "fakeip",
				"address": "fakeip"
			}
		],
		"rules": [
			{
				"outbound": ["any"],
				"server": "local-dns"
			},
			{
				"query_type": ["A", "AAAA"],
				"server": "fakeip"
			}
		],
		"final": "remote-dns",
		"fakeip": {
			"enabled": true,
			"inet4_range": "198.18.0.0/15",
			"inet6_range": "fc00::/18"
		},
		"strategy": "prefer_ipv4"
	},
	"inbounds": [
		{
			"type": "tun",
			"tag": "tun-in",
			"address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
			"stack": "mixed",
			"auto_route": true,
			"strict_route": true,
			"sniff": true,
			"sniff_override_destination": false
		}
	],
	"outbounds": [
		{
			"type": "http",
			"tag": "proxy",
			"server": "127.0.0.1",
			"server_port": %s
		},
		{
			"type": "direct",
			"tag": "direct"
		},
		{
			"type": "dns",
			"tag": "dns-out"
		},
		{
			"type": "block",
			"tag": "block"
		}
	],
	"route": {
		"rules": [
			{
				"protocol": "dns",
				"action": "hijack-dns"
			},%s%s
			{
				"ip_is_private": true,
				"outbound": "direct"
			}
		],
		"auto_detect_interface": true,
		"final": "proxy"
	}
}`, common.LocalHttpPort, serverIPRule, serverDomainRule)

	return []byte(config)
}
