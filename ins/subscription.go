package ins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/getlantern/systray"
	"high-mae/protocol"

	// 强烈建议使用跨平台剪贴板库，代替 powershell 命令
	// "github.com/atotto/clipboard"
	"os/exec"
	"runtime"
	"runtime/debug"
	"sync"
)

type SubInfo struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	FileName string `json:"file_name"`
}

const SubscriptionsFile = "subscription.json"

// ReadSubscriptions 读取保存的订阅信息
func ReadSubscriptions() ([]SubInfo, error) {
	if _, err := os.Stat(SubscriptionsFile); os.IsNotExist(err) {
		return []SubInfo{}, nil
	}

	data, err := os.ReadFile(SubscriptionsFile)
	if err != nil {
		return nil, err
	}

	var links []SubInfo
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, fmt.Errorf("解析 JSON 失败: %w", err)
	}
	return links, nil
}

// AppendSubscription 追加新链接到 JSON，并返回其文件名以及是否已存在
func AppendSubscription(newLink string) (string, bool, error) {
	links, _ := ReadSubscriptions()

	for _, existing := range links {
		if existing.URL == newLink {
			return existing.FileName, true, nil
		}
	}

	// 简单的域名提取作为供应商名
	name := "未知供应商"
	fileName := fmt.Sprintf("sub_%d.yml", len(links)+1)
	if strings.Contains(newLink, "://") {
		parts := strings.SplitN(newLink, "://", 2)
		if len(parts) == 2 {
			domainParts := strings.SplitN(parts[1], "/", 2)
			name = domainParts[0]
		}
	}

	links = append(links, SubInfo{
		Name:     name,
		URL:      newLink,
		FileName: fileName,
	})

	data, err := json.MarshalIndent(links, "", "  ")
	if err != nil {
		return "", false, err
	}

	return fileName, false, os.WriteFile(SubscriptionsFile, data, 0644)
}

func SaveNodesToYAML(path string, nodes []protocol.Node) error {
	var sb strings.Builder
	for i, n := range nodes {
		sb.WriteString("{\n")
		// 注意这里沿用了你的 name 格式，包裹在双引号中防特殊字符解析错误
		sb.WriteString(fmt.Sprintf("    name: '%s',\n", n.Name))
		sb.WriteString(fmt.Sprintf("    type: %s,\n", n.Type))
		sb.WriteString(fmt.Sprintf("    server: '%s',\n", n.Server))

		var inner strings.Builder
		if n.Type != "mieru" {
			inner.WriteString(fmt.Sprintf("    port: %d,\n", n.Port))
		}

		// 🎯 VLESS 专属格式排版
		if n.Type == "vless" {
			inner.WriteString(fmt.Sprintf("    uuid: %s,\n", n.UUID))
			if n.UDP {
				inner.WriteString("    udp: true,\n")
			}
			if n.TLS || n.Tls {
				inner.WriteString("    tls: true,\n")
			}
			inner.WriteString(fmt.Sprintf("    skip-cert-verify: %t,\n", n.SkipCertVerify))

			if n.Flow == "" {
				inner.WriteString("    flow: '',\n")
			} else {
				inner.WriteString(fmt.Sprintf("    flow: %s,\n", n.Flow))
			}
			if n.ClientFingerprint != "" {
				inner.WriteString(fmt.Sprintf("    client-fingerprint: %s,\n", n.ClientFingerprint))
			}
			if n.ServerName != "" {
				inner.WriteString(fmt.Sprintf("    servername: %s,\n", n.ServerName))
			}
			if n.Network != "" {
				inner.WriteString(fmt.Sprintf("    network: %s,\n", n.Network))
			}

			// 还原 ws-opts 花括号嵌套
			if n.Network == "ws" && n.WSOpts.Path != "" {
				inner.WriteString("    ws-opts:\n      {\n")
				if len(n.WSOpts.Headers) > 0 {
					inner.WriteString(fmt.Sprintf("          path: %s,\n", n.WSOpts.Path))
					inner.WriteString("          headers:\n            {\n")

					// 为了完美处理最后的逗号
					var hLines []string
					for k, v := range n.WSOpts.Headers {
						hLines = append(hLines, fmt.Sprintf("                %s: %s", k, v))
					}
					inner.WriteString(strings.Join(hLines, ",\n") + "\n")
					inner.WriteString("            }\n")
				} else {
					inner.WriteString(fmt.Sprintf("          path: %s\n", n.WSOpts.Path))
				}
				inner.WriteString("      },\n")
			}

			// 还原 reality-opts 花括号嵌套
			if n.RealityOpts != nil {
				inner.WriteString("    reality-opts:\n      {\n")
				inner.WriteString(fmt.Sprintf("          public-key: %s,\n", n.RealityOpts.PublicKey))
				inner.WriteString(fmt.Sprintf("          short-id: %s\n", n.RealityOpts.ShortID))
				inner.WriteString("      },\n")
			}

			// 🎯 Hysteria2 专属格式排版
		} else if n.Type == "hysteria2" || n.Type == "hy2" {
			if n.UDP {
				inner.WriteString("    udp: true,\n")
			}
			inner.WriteString(fmt.Sprintf("    skip-cert-verify: %t,\n", n.SkipCertVerify))
			if n.SNI != "" {
				inner.WriteString(fmt.Sprintf("    sni: %s,\n", n.SNI))
			}
			inner.WriteString(fmt.Sprintf("    password: %s,\n", n.Password))

			// 🎯 TUIC 专属格式排版
		} else if n.Type == "tuic" {
			if n.UUID != "" {
				inner.WriteString(fmt.Sprintf("    uuid: %s,\n", n.UUID))
			}
			if n.Password != "" {
				inner.WriteString(fmt.Sprintf("    password: %s,\n", n.Password))
			}
			inner.WriteString(fmt.Sprintf("    reduce-rtt: %t,\n", n.ReduceRTT))
			cc := n.CongestionControl
			if cc == "" {
				cc = "bbr"
			}
			inner.WriteString(fmt.Sprintf("    congestion-control: %s,\n", cc))
			udpMode := n.UDPRelayMode
			if udpMode == "" {
				udpMode = "native"
			}
			inner.WriteString(fmt.Sprintf("    udp-relay-mode: %s,\n", udpMode))
			if n.SNI == "" {
				inner.WriteString("    sni: '',\n")
			} else {
				inner.WriteString(fmt.Sprintf("    sni: %s,\n", n.SNI))
			}
			if len(n.ALPN) > 0 {
				inner.WriteString(fmt.Sprintf("    alpn: [%s],\n", strings.Join(n.ALPN, ",")))
			} else {
				inner.WriteString("    alpn: [h3],\n")
			}
			inner.WriteString(fmt.Sprintf("    disable-sni: %t,\n", n.DisableSNI))
			inner.WriteString(fmt.Sprintf("    skip-cert-verify: %t,\n", n.SkipCertVerify))

			// 🎯 AnyTLS 专属格式排版
		} else if n.Type == "anytls" {
			if n.Password != "" {
				inner.WriteString(fmt.Sprintf("    password: %s,\n", n.Password))
			}
			fp := n.ClientFingerprint
			if fp == "" {
				fp = "firefox"
			}
			inner.WriteString(fmt.Sprintf("    client-fingerprint: %s,\n", fp))
			inner.WriteString("    udp: true,\n")
			inner.WriteString("    tfo: true,\n")
			if n.SNI == "" {
				inner.WriteString("    sni: '',\n")
			} else {
				inner.WriteString(fmt.Sprintf("    sni: %s,\n", n.SNI))
			}
			inner.WriteString(fmt.Sprintf("    skip-cert-verify: %t,\n", n.SkipCertVerify))

			// 🎯 HTTP (NaiveProxy) 专属格式排版
		} else if n.Type == "http" || n.Type == "https" || n.Type == "socks" || n.Type == "socks5" {
			if n.Username != "" {
				inner.WriteString(fmt.Sprintf("    username: %s,\n", n.Username))
			}
			if n.Password != "" {
				inner.WriteString(fmt.Sprintf("    password: %s,\n", n.Password))
			}
			if n.Tls || n.TLS {
				inner.WriteString("    tls: true,\n")
			}
			if n.SNI == "" {
				inner.WriteString("    sni: '',\n")
			} else {
				inner.WriteString(fmt.Sprintf("    sni: %s,\n", n.SNI))
			}
			inner.WriteString(fmt.Sprintf("    skip-cert-verify: %t,\n", n.SkipCertVerify))

		} else if n.Type == "mieru" {
			if n.PortRange != "" {
				inner.WriteString(fmt.Sprintf("    port-range: %s,\n", n.PortRange))
			} else {
				inner.WriteString(fmt.Sprintf("    port: %d,\n", n.Port))
			}
			if n.Transport != "" {
				inner.WriteString(fmt.Sprintf("    transport: %s,\n", n.Transport))
			}
			if n.Username != "" {
				inner.WriteString(fmt.Sprintf("    username: %s,\n", n.Username))
			}
			if n.Password != "" {
				inner.WriteString(fmt.Sprintf("    password: %s,\n", n.Password))
			}
			if n.HashedPassword != "" {
				inner.WriteString(fmt.Sprintf("    hashed-password: %s,\n", n.HashedPassword))
			}
			if n.Multiplexing != "" {
				inner.WriteString(fmt.Sprintf("    multiplexing: %s,\n", n.Multiplexing))
			}
			if n.HandshakeMode != "" {
				inner.WriteString(fmt.Sprintf("    handshake-mode: %s,\n", n.HandshakeMode))
			}
			if n.TrafficPattern != "" {
				inner.WriteString(fmt.Sprintf("    traffic-pattern: %s,\n", n.TrafficPattern))
			}
			inner.WriteString("    udp: true,\n")

			// 兜底格式 (VMess, SS, Trojan 等)
		} else {
			if n.Type == "vmess" {
				inner.WriteString("    alterId: 0,\n")
				inner.WriteString("    udp: true,\n")
			}
			if n.UUID != "" {
				inner.WriteString(fmt.Sprintf("    uuid: %s,\n", n.UUID))
			}
			if n.AlterId != 0 {
				inner.WriteString(fmt.Sprintf("    alterId: %d,\n", n.AlterId))
			}
			if n.Username != "" {
				inner.WriteString(fmt.Sprintf("    username: %s,\n", n.Username))
			}
			if n.Password != "" {
				inner.WriteString(fmt.Sprintf("    password: %s,\n", n.Password))
			}
			//cipher := n.Cipher
			//if cipher == "" {
			//	cipher = "auto"
			//}
			//inner.WriteString(fmt.Sprintf("    cipher: %s,\n", cipher))
			//if n.SNI == "" {
			//	inner.WriteString("    sni: '',\n")
			//} else {
			//	inner.WriteString(fmt.Sprintf("    sni: %s,\n", n.SNI))
			//}
			if n.Port == 443 || n.TLS || n.Tls {
				inner.WriteString("    tls: true,\n")
				inner.WriteString("    skip-cert-verify: true,\n")
			}
			if n.ServerName != "" {
				inner.WriteString(fmt.Sprintf("    servername: %s,\n", n.ServerName))
			} else if n.SNI != "" {
				inner.WriteString(fmt.Sprintf("    servername: %s,\n", n.SNI))
			}
			//inner.WriteString(fmt.Sprintf("    skip-cert-verify: %t,\n", n.SkipCertVerify))

			cipher := n.Cipher
			if cipher == "" {
				cipher = "auto"
			}
			inner.WriteString(fmt.Sprintf("    cipher: %s,\n", cipher))
			if n.Network == "ws" || n.Network == "websocket" {
				path := n.WSOpts.Path
				if path == "" {
					path = n.WSPath
				}
				if path == "" {
					path = "/"
				}
				inner.WriteString("    network: ws,\n")
				inner.WriteString(fmt.Sprintf("    ws-path: %s,\n", path))

				host := ""
				if n.WSOpts.Headers != nil && n.WSOpts.Headers["Host"] != "" {
					host = n.WSOpts.Headers["Host"]
				} else if n.WSHeaders != nil && n.WSHeaders["Host"] != "" {
					host = n.WSHeaders["Host"]
				} else if n.Host != "" {
					host = n.Host
				}
				if host != "" {
					inner.WriteString(fmt.Sprintf("    ws-host: %s,\n", host))
				}
			} else if n.Network == "grpc" {
				inner.WriteString("    network: grpc,\n")

				serviceName := n.WSOpts.Path
				if serviceName == "" {
					serviceName = n.WSPath
				}

				if serviceName != "" {
					inner.WriteString("    grpc-opts:\n      {\n")
					inner.WriteString(fmt.Sprintf("          grpc-service-name: '%s'\n", serviceName))
					inner.WriteString("      },\n")
				}
			}
		}

		// 优雅去除最后一行多余的逗号
		innerContent := strings.TrimSuffix(inner.String(), ",\n")
		sb.WriteString(innerContent)
		sb.WriteString("\n}")

		// 多节点之间的分隔符
		if i < len(nodes)-1 {
			sb.WriteString("\n---\n")
		} else {
			sb.WriteString("\n")
		}
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func ImportNodeFromClipboard() {
	// 1. 读取剪贴板内容
	out, err := exec.Command("powershell", "-command", "Get-Clipboard").Output()
	if err != nil {
		ShowWindowsMsgBox("导入失败", "无法读取剪贴板内容！")
		return
	}

	input := strings.TrimSpace(string(out))
	if input == "" {
		ShowWindowsMsgBox("导入失败", "剪贴板为空！请复制订阅链接或节点内容。")
		return
	}

	// 2. 解析节点 (使用你强大的解析器)
	newNodes, err := ParseSubscription(input)
	if err != nil || len(newNodes) == 0 {
		ShowWindowsMsgBox("导入失败", fmt.Sprintf("无法解析剪贴板内的节点或订阅。\n原因: %v", err))
		return
	}

	// ==========================================
	// 🚀 新增逻辑：将合法的原始链接持久化保存到 JSON
	// ==========================================
	lines := strings.Split(input, "\n")
	targetFile := "config.yml" // default fallback
	isOldLink := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			fName, existed, err := AppendSubscription(line)
			if err != nil {
				fmt.Printf("⚠️ 警告: 无法将链接保存到 JSON: %v\n", err)
			} else if fName != "" {
				targetFile = fName
				isOldLink = existed
			}
		}
	}

	// 3. 将新节点追加到当前节点列表中（如果是导入的话，其实更应该覆盖该供应商的节点）
	// 为简单起见，这里覆盖当前所有节点（或者只保存当前新节点）
	AllNodes = newNodes

	// 4. 持久化到 YAML
	err = SaveNodesToYAML(targetFile, AllNodes)
	if err != nil {
		ShowWindowsMsgBox("保存失败", "写入 .yml 文件失败: "+err.Error())
		return
	}

	// 更新当前使用的配置文件
	CurrentConfigFile = targetFile

	// 5. 重新读取确保同步
	refreshedNodes, err := protocol.ParseNodes(targetFile)
	if err == nil {
		AllNodes = refreshedNodes
	}

	// 6. 刷新托盘菜单
	RefreshSupplierMenu()
	if isOldLink {
		RefreshNodeMenu(nil)
		ShowWindowsMsgBox("覆盖成功", fmt.Sprintf("🎉 成功更新/覆盖了已存在的订阅！\n共 %d 个节点。\n节点已保存至 %s", len(newNodes), targetFile))
	} else {
		RefreshNodeMenu(newNodes)
		ShowWindowsMsgBox("导入成功", fmt.Sprintf("🎉 成功解析并导入 %d 个新节点！\n\n📌 原始链接已保存，方便日后一键更新。\n节点已保存至 %s 并自动为您切换。", len(newNodes), targetFile))
	}
}

var CurrentConfigFile string = "config.yml"

func RefreshNodeMenu(newNodes []protocol.Node) {
	if nodeMenuCancel != nil {
		nodeMenuCancel()
	}
	var ctx context.Context
	ctx, nodeMenuCancel = context.WithCancel(context.Background())

	for _, mi := range NodeMenuItems {
		mi.Hide()
	}
	NodeMenuItems = nil

	var nodeParents []*systray.MenuItem

	for _, node := range AllNodes {
		itemLabel := fmt.Sprintf("[%s] %s", strings.ToUpper(node.Type), node.Name)
		item := MNodeMenu.AddSubMenuItem(itemLabel, "")
		NodeMenuItems = append(NodeMenuItems, item)
		nodeParents = append(nodeParents, item)

		go func(ctx context.Context, n protocol.Node, parent *systray.MenuItem) {
			for {
				select {
				case <-ctx.Done():
					return
				case <-parent.ClickedCh:
					for _, mi := range nodeParents {
						mi.Uncheck()
					}
					parent.Check()
					SwitchNode(n)
				}
			}
		}(ctx, node, item)
	}

	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			case <-MTestAll.ClickedCh:
				MTestAll.SetTitle("⏳ 极速测速中...")
				MTestAll.Disable()

				// 🚀 核心优化：改用极低内存消耗的 FastTCPPing，并将并发放宽到 50
				sem := make(chan struct{}, 50) 
				var wg sync.WaitGroup
				for i, n := range AllNodes {
					wg.Add(1)
					go func(idx int, nd protocol.Node, parent *systray.MenuItem) {
						defer wg.Done()
						sem <- struct{}{}        // 获取令牌
						defer func() { <-sem }() // 释放令牌

						select {
						case <-ctx.Done():
							return
						default:
						}

						parent.SetTitle(fmt.Sprintf("[%s] %s - 测速中...", strings.ToUpper(nd.Type), nd.Name))
						latency, err := FastTCPPing(nd)
						if err != nil {
							parent.SetTitle(fmt.Sprintf("[%s] %s - ❌ 失败", strings.ToUpper(nd.Type), nd.Name))
						} else {
							parent.SetTitle(fmt.Sprintf("[%s] %s - ⚡ %dms", strings.ToUpper(nd.Type), nd.Name, latency))
						}
					}(i, n, nodeParents[i])
				}
				wg.Wait()
				MTestAll.SetTitle("⚡ 极速测速所有节点 (TCP)")
				MTestAll.Enable()
				// 强制进行一次垃圾回收并释放系统内存
				runtime.GC()
				debug.FreeOSMemory()
			}
		}
	}(ctx)

	// 自动切换到导入的第一个新节点
	if len(newNodes) > 0 {
		firstNewIndex := len(AllNodes) - len(newNodes)
		if firstNewIndex >= 0 && firstNewIndex < len(nodeParents) {
			nodeParents[firstNewIndex].Check()
			SwitchNode(AllNodes[firstNewIndex])
		}
	}
}

func RefreshSupplierMenu() {
	if MSupplierMenu == nil {
		return
	}

	if supplierMenuCancel != nil {
		supplierMenuCancel()
	}
	var ctx context.Context
	ctx, supplierMenuCancel = context.WithCancel(context.Background())

	for _, mi := range SupplierMenuItems {
		mi.Hide()
	}
	SupplierMenuItems = nil

	links, _ := ReadSubscriptions()
	for _, sub := range links {
		item := MSupplierMenu.AddSubMenuItem(sub.Name, sub.URL)
		SupplierMenuItems = append(SupplierMenuItems, item)

		if sub.FileName == CurrentConfigFile {
			item.Check()
		}

		mSwitch := item.AddSubMenuItem("✅ 切换至此供应商", "")
		mUpdate := item.AddSubMenuItem("🔄 更新此订阅", "")
		mDelete := item.AddSubMenuItem("🗑 删除此供应商", "")

		go func(ctx context.Context, s SubInfo, parent *systray.MenuItem, mSw *systray.MenuItem, mUp *systray.MenuItem, mDel *systray.MenuItem) {
			for {
				select {
				case <-ctx.Done():
					return
				case <-mSw.ClickedCh:
					nodes, err := protocol.ParseNodes(s.FileName)
					if err == nil && len(nodes) > 0 {
						CurrentConfigFile = s.FileName
						AllNodes = nodes

						for _, mi := range SupplierMenuItems {
							mi.Uncheck()
						}
						parent.Check()

						RefreshNodeMenu(nil)
						if len(AllNodes) > 0 {
							SwitchNode(AllNodes[0])
						}
					} else {
						ShowWindowsMsgBox("切换失败", "无法读取该供应商的节点数据，请尝试更新订阅。")
					}
				case <-mUp.ClickedCh:
					parent.SetTitle(s.Name + " (🔄 更新中...)")
					nodes, err := ParseSubscription(s.URL)
					if err == nil && len(nodes) > 0 {
						err = SaveNodesToYAML(s.FileName, nodes)
						if err == nil {
							if CurrentConfigFile == s.FileName {
								AllNodes = nodes
								RefreshNodeMenu(nil) // just refresh, no auto-switch
							}
							parent.SetTitle(s.Name)
							ShowWindowsMsgBox("更新成功", fmt.Sprintf("🎉 成功更新了供应商 %s！\n共获取 %d 个节点。", s.Name, len(nodes)))
						} else {
							parent.SetTitle(s.Name + " (❌ 保存失败)")
							ShowWindowsMsgBox("更新失败", "无法保存节点数据。")
						}
					} else {
						parent.SetTitle(s.Name + " (❌ 失败)")
						ShowWindowsMsgBox("更新失败", "无法从该链接获取有效节点。")
					}
				case <-mDel.ClickedCh:
					DeleteSubscription(s.URL)
					parent.Hide()
					if CurrentConfigFile == s.FileName {
						// 如果删除的是当前正在使用的，则清空当前状态
						AllNodes = nil
						CurrentConfigFile = ""
						if MCurrentNode != nil {
							MCurrentNode.SetTitle("📍 当前节点: [未选择]")
						}
						RefreshNodeMenu(nil)
					}
				}
			}
		}(ctx, sub, item, mSwitch, mUpdate, mDelete)
	}
}

// DeleteSubscription 从配置文件中删除给定的订阅链接
func DeleteSubscription(url string) {
	links, _ := ReadSubscriptions()
	var newLinks []SubInfo
	for _, l := range links {
		if l.URL != url {
			newLinks = append(newLinks, l)
		} else {
			// 删除对应的本地 yaml 文件
			os.Remove(l.FileName)
		}
	}
	data, _ := json.MarshalIndent(newLinks, "", "  ")
	os.WriteFile(SubscriptionsFile, data, 0644)
}

func ParseSubscription(input string) ([]protocol.Node, error) {
	raw, err := protocol.LoadInput(input)
	if err != nil {
		return nil, err
	}
	nodes, err := protocol.ParseSubscriptionRaw(raw)
	if err != nil {
		return nil, err
	}

	if isRemoteSubscription(input) {
		clashRaw, err := protocol.LoadInputWithUserAgent(input, "ClashMeta")
		if err == nil {
			if clashNodes, parseErr := protocol.ParseSubscriptionRaw(clashRaw); parseErr == nil {
				nodes = mergeNodes(nodes, clashNodes)
			}
		}
	}

	return nodes, nil
}

func isRemoteSubscription(input string) bool {
	input = strings.TrimSpace(strings.Trim(input, "“”\"'"))
	return strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
}

func mergeNodes(base []protocol.Node, extra []protocol.Node) []protocol.Node {
	seen := make(map[string]struct{}, len(base)+len(extra))
	merged := make([]protocol.Node, 0, len(base)+len(extra))

	for _, node := range base {
		key := nodeKey(node)
		seen[key] = struct{}{}
		merged = append(merged, node)
	}

	for _, node := range extra {
		key := nodeKey(node)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, node)
	}

	return merged
}

func nodeKey(node protocol.Node) string {
	network := strings.ToLower(strings.TrimSpace(node.Network))
	if network == "tcp" {
		network = ""
	}

	return fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s|%s",
		node.Type,
		node.Server,
		node.Port,
		node.PortRange,
		node.UUID,
		node.Username,
		node.Password,
		node.HashedPassword,
		node.Transport,
		network,
	)
}

func UpdateAllSubscriptions() {
	links, err := ReadSubscriptions()
	if err != nil || len(links) == 0 {
		ShowWindowsMsgBox("更新失败", "没有找到保存的订阅链接。请先从剪贴板导入！")
		return
	}

	totalUpdated := 0
	for _, info := range links {
		nodes, err := ParseSubscription(info.URL)
		if err == nil && len(nodes) > 0 {
			err = SaveNodesToYAML(info.FileName, nodes)
			if err != nil {
				fmt.Printf("⚠️ 写入文件失败: %v\n", err)
			} else {
				totalUpdated += len(nodes)
			}
			if CurrentConfigFile == info.FileName {
				AllNodes = nodes
				RefreshNodeMenu(nodes)
			}
		} else {
			fmt.Printf("⚠️ 链接更新失败或无节点: %s\n", info.URL)
		}
	}

	if totalUpdated == 0 {
		ShowWindowsMsgBox("更新失败", "所有链接均未能获取到有效节点！")
		return
	}

	ShowWindowsMsgBox("更新完成", fmt.Sprintf("🎉 成功从保存的链接中更新了 %d 个节点！", totalUpdated))
}
