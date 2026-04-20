package ins

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/getlantern/systray"
	"high-mae/protocol"

	// 强烈建议使用跨平台剪贴板库，代替 powershell 命令
	// "github.com/atotto/clipboard"
	"os/exec"
)

const SubscriptionsFile = "subscriptions.json"
const ConfigFile = ".yml" // 你的 yaml 配置文件名

// ReadSubscriptions 读取保存的原始链接列表
func ReadSubscriptions() ([]string, error) {
	if _, err := os.Stat(SubscriptionsFile); os.IsNotExist(err) {
		return []string{}, nil // 文件不存在返回空列表
	}

	data, err := os.ReadFile(SubscriptionsFile)
	if err != nil {
		return nil, err
	}

	var links []string
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, fmt.Errorf("解析 JSON 失败: %w", err)
	}
	return links, nil
}

// AppendSubscription 追加新链接到 JSON，并去重
func AppendSubscription(newLink string) error {
	links, _ := ReadSubscriptions()

	// 简单的去重逻辑
	for _, existing := range links {
		if existing == newLink {
			return nil // 已经存在，不用重复添加
		}
	}

	links = append(links, newLink)

	// 格式化输出 JSON (带缩进，方便人眼查看)
	data, err := json.MarshalIndent(links, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(SubscriptionsFile, data, 0644)
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
		inner.WriteString(fmt.Sprintf("    port: %d,\n", n.Port))

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
				inner.WriteString(fmt.Sprintf("    alpn:[%s],\n", strings.Join(n.ALPN, ",")))
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
		} else if n.Type == "http" || n.Type == "https" {
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
	// input 可能是一行（一个分享链接或一个订阅链接），也可能是多行（批量复制的节点文本）。
	// 为了以后方便更新，如果有多行，我们逐行保存；如果是单行订阅，直接保存。
	lines := strings.Split(input, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			err = AppendSubscription(line)
			if err != nil {
				fmt.Printf("⚠️ 警告: 无法将链接保存到 JSON: %v\n", err)
			}
		}
	}

	// 3. 将新节点追加到全局节点列表中
	AllNodes = append(AllNodes, newNodes...)

	// 4. 持久化到 YAML
	err = SaveNodesToYAML(ConfigFile, AllNodes)
	if err != nil {
		ShowWindowsMsgBox("保存失败", "写入 .yml 文件失败: "+err.Error())
		return
	}

	// 5. 重新读取确保同步
	refreshedNodes, err := protocol.ParseNodes(ConfigFile)
	if err == nil {
		AllNodes = refreshedNodes
	}

	// 6. 刷新托盘菜单
	RefreshNodeMenu(newNodes)

	ShowWindowsMsgBox("导入成功", fmt.Sprintf("🎉 成功解析并导入 %d 个节点！\n\n📌 原始链接已保存至 %s，方便日后一键更新。\n节点已保存至 %s 并自动为您切换。", len(newNodes), SubscriptionsFile, ConfigFile))
}

// 辅助函数：刷新菜单逻辑（从你的原代码中抽离，让代码更干净）
func RefreshNodeMenu(newNodes []protocol.Node) {
	for _, mi := range NodeMenuItems {
		mi.Hide()
	}
	NodeMenuItems = nil

	for _, node := range AllNodes {
		itemLabel := fmt.Sprintf("[%s] %s", strings.ToUpper(node.Type), node.Name)
		item := MNodeMenu.AddSubMenuItem(itemLabel, "")
		NodeMenuItems = append(NodeMenuItems, item)

		go func(n protocol.Node, mItem *systray.MenuItem) {
			for range mItem.ClickedCh {
				for _, mi := range NodeMenuItems {
					mi.Uncheck()
				}
				mItem.Check()
				SwitchNode(n)
				ShowWindowsMsgBox("节点已切换", fmt.Sprintf("已成功切换至节点：\n%s", n.Name))
			}
		}(node, item)
	}

	// 自动切换到导入的第一个新节点
	if len(newNodes) > 0 {
		firstNewIndex := len(AllNodes) - len(newNodes)
		if firstNewIndex >= 0 && firstNewIndex < len(NodeMenuItems) {
			NodeMenuItems[firstNewIndex].Check()
			SwitchNode(AllNodes[firstNewIndex])
		}
	}
}

func ParseSubscription(input string) ([]protocol.Node, error) {
	raw, err := protocol.LoadInput(input)
	if err != nil {
		return nil, err
	}
	content, err := protocol.NormalizeSubscription(raw)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(content, "\n")
	var nodes []protocol.Node

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "vmess://"):
			if n, err := protocol.ParseVMess(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "ss://"):
			if n, err := protocol.ParseSS(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "trojan://"):
			if n, err := protocol.ParseTrojan(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "anytls://"):
			if n, err := protocol.ParseAnyTLS(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "tuic://"):
			if n, err := protocol.ParseTUIC(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "vless://"):
			if n, err := protocol.ParseVLESS(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "hy2://") || strings.HasPrefix(line, "hysteria2://"):
			if n, err := protocol.ParseHysteria2(line); err == nil {
				nodes = append(nodes, n)
			}
		case strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://"):
			if n, err := protocol.ParseHTTPLike(line); err == nil {
				nodes = append(nodes, n)
			}
		default:
			// 其他协议或格式暂不支持，直接跳过
			fmt.Printf("⚠️ 跳过不支持的链接格式: %s\n", line)
		}
	}
	return nodes, nil
}

func UpdateAllSubscriptions() {
	links, err := ReadSubscriptions()
	if err != nil || len(links) == 0 {
		ShowWindowsMsgBox("更新失败", "没有找到保存的订阅链接。请先从剪贴板导入！")
		return
	}

	var updatedNodes []protocol.Node

	for _, link := range links {
		// 遍历下载并解析所有保存的链接
		nodes, err := ParseSubscription(link)
		if err == nil && len(nodes) > 0 {
			updatedNodes = append(updatedNodes, nodes...)
		} else {
			fmt.Printf("⚠️ 链接更新失败或无节点: %s\n", link)
		}
	}

	if len(updatedNodes) == 0 {
		ShowWindowsMsgBox("更新失败", "所有链接均未能获取到有效节点！")
		return
	}

	// 覆盖保存，抛弃旧节点
	AllNodes = updatedNodes
	err = SaveNodesToYAML(ConfigFile, AllNodes)
	if err != nil {
		ShowWindowsMsgBox("保存失败", "写入文件失败: "+err.Error())
		return
	}

	RefreshNodeMenu(updatedNodes)
	ShowWindowsMsgBox("更新完成", fmt.Sprintf("🎉 成功从保存的链接中更新了 %d 个节点！", len(updatedNodes)))
}
