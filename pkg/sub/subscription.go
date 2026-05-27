package sub

import (
	"wing/pkg/common"
	"wing/pkg/proxy"
	"wing/pkg/storage"
	"wing/pkg/utils"

	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/getlantern/systray"
	"wing/protocol"

	"gopkg.in/yaml.v3"

	"runtime"
	"runtime/debug"
	"sync"
)

type SubInfo struct {
	Name     string               `json:"name"`
	URL      string               `json:"url"`
	FileName string               `json:"file_name"`
	Traffic  *SubscriptionTraffic `json:"traffic,omitempty"`
}

const SubscriptionsFile = "subscription.json"

var (
	OnSubscriptionNodesUpdated func(fileName string, oldNodes []protocol.Node, newNodes []protocol.Node)
	OnSubscriptionDeleted      func(fileName string, oldNodes []protocol.Node)
)

type SubscriptionTraffic struct {
	Upload                int64  `json:"upload"`
	Download              int64  `json:"download"`
	Used                  int64  `json:"used"`
	Total                 int64  `json:"total"`
	Remaining             int64  `json:"remaining"`
	Expire                int64  `json:"expire,omitempty"`
	ResetAt               int64  `json:"reset_at,omitempty"`
	ResetDay              int64  `json:"reset_day,omitempty"`
	ProfileUpdateInterval int64  `json:"profile_update_interval,omitempty"`
	UpdatedAt             int64  `json:"updated_at"`
	Raw                   string `json:"raw,omitempty"`
}

// ReadSubscriptions 读取保存的订阅信息
func ReadSubscriptions() ([]SubInfo, error) {
	data, err := storage.ReadOrMigrateFile(SubscriptionsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []SubInfo{}, nil
		}
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
	return AppendSubscriptionWithTraffic(newLink, nil)
}

func AppendSubscriptionWithTraffic(newLink string, traffic *SubscriptionTraffic) (string, bool, error) {
	links, _ := ReadSubscriptions()

	for _, existing := range links {
		if existing.URL == newLink {
			if traffic != nil {
				if err := UpdateSubscriptionTraffic(existing.URL, traffic); err != nil {
					return "", true, err
				}
			}
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
		Traffic:  traffic,
	})

	data, err := json.MarshalIndent(links, "", "  ")
	if err != nil {
		return "", false, err
	}

	return fileName, false, storage.Write(SubscriptionsFile, data)
}

func UpdateSubscriptionTraffic(url string, traffic *SubscriptionTraffic) error {
	if traffic == nil {
		return nil
	}
	links, err := ReadSubscriptions()
	if err != nil {
		return err
	}
	changed := false
	for i := range links {
		if links[i].URL == url {
			links[i].Traffic = traffic
			changed = true
			break
		}
	}
	if !changed {
		return nil
	}
	data, err := json.MarshalIndent(links, "", "  ")
	if err != nil {
		return err
	}
	return storage.Write(SubscriptionsFile, data)
}

func SaveNodesToYAML(path string, nodes []protocol.Node) error {
	var sb strings.Builder
	for i, n := range nodes {
		// 确保 TLS 字段一致性
		if n.Tls && !n.TLS {
			n.TLS = true
		}

		data, err := yaml.Marshal(n)
		if err != nil {
			return fmt.Errorf("序列化节点失败: %w", err)
		}
		sb.Write(data)

		// 多节点之间的分隔符
		if i < len(nodes)-1 {
			sb.WriteString("---\n")
		}
	}

	return storage.Write(path, []byte(sb.String()))
}

func NotifySubscriptionNodesUpdated(fileName string, oldNodes []protocol.Node, newNodes []protocol.Node) {
	if OnSubscriptionNodesUpdated != nil {
		OnSubscriptionNodesUpdated(fileName, oldNodes, newNodes)
	}
}

func NotifySubscriptionDeleted(fileName string, oldNodes []protocol.Node) {
	if OnSubscriptionDeleted != nil {
		OnSubscriptionDeleted(fileName, oldNodes)
	}
}

func ImportNodeFromClipboard() {
	// 1. 读取剪贴板内容
	out, err := utils.RunHiddenCommand("powershell", "-NoProfile", "-Command", "Get-Clipboard")
	if err != nil {
		utils.ShowWindowsMsgBox("导入失败", "无法读取剪贴板内容！")
		return
	}

	input := strings.TrimSpace(string(out))
	if input == "" {
		utils.ShowWindowsMsgBox("导入失败", "剪贴板为空！请复制订阅链接或节点内容。")
		return
	}

	// 2. 解析节点 (使用你强大的解析器)
	newNodes, traffic, err := ParseSubscriptionWithInfo(input)
	if err != nil || len(newNodes) == 0 {
		utils.ShowWindowsMsgBox("导入失败", fmt.Sprintf("无法解析剪贴板内的节点或订阅。\n原因: %v", err))
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
			fName, existed, err := AppendSubscriptionWithTraffic(line, traffic)
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
	oldNodes, _ := protocol.ParseNodes(targetFile)
	common.AllNodes = newNodes

	// 4. 持久化到 YAML
	err = SaveNodesToYAML(targetFile, common.AllNodes)
	if err != nil {
		utils.ShowWindowsMsgBox("保存失败", "写入 .yml 文件失败: "+err.Error())
		return
	}
	NotifySubscriptionNodesUpdated(targetFile, oldNodes, common.AllNodes)

	// 更新当前使用的配置文件
	SetActiveConfigFile(targetFile)

	data, err := storage.ReadOrMigrateFile(targetFile)
	if err == nil {
		refreshedNodes, err := protocol.ParseNodesData(data)
		if err == nil {
			common.AllNodes = refreshedNodes
		}
	}

	// 6. 刷新托盘菜单
	RefreshSupplierMenu()
	if isOldLink {
		RefreshNodeMenu(nil)
		utils.ShowWindowsMsgBox("覆盖成功", fmt.Sprintf("🎉 成功更新/覆盖了已存在的订阅！\n共 %d 个节点。\n节点已保存至 %s", len(newNodes), targetFile))
	} else {
		RefreshNodeMenu(newNodes)
		utils.ShowWindowsMsgBox("导入成功", fmt.Sprintf("🎉 成功解析并导入 %d 个新节点！\n\n📌 原始链接已保存，方便日后一键更新。\n节点已保存至 %s 并自动为您切换。", len(newNodes), targetFile))
	}
}

var CurrentConfigFile string = "config.yml"

func SetActiveConfigFile(fileName string) {
	CurrentConfigFile = fileName
	if fileName != "" {
		_ = storage.Write("last_active_config_file", []byte(fileName))
	}
}

func RefreshNodeMenu(newNodes []protocol.Node) {
	if common.NodeMenuCancel != nil {
		common.NodeMenuCancel()
	}
	var ctx context.Context
	ctx, common.NodeMenuCancel = context.WithCancel(context.Background())

	for _, mi := range common.NodeMenuItems {
		mi.Hide()
	}
	common.NodeMenuItems = nil

	var nodeParents []*systray.MenuItem

	if common.MNodeMenu == nil {
		// Web-only mode: systray not initialized, skip tray menu updates
		return
	}

	for _, node := range common.AllNodes {
		itemLabel := fmt.Sprintf("[%s] %s", strings.ToUpper(node.Type), node.Name)
		item := common.MNodeMenu.AddSubMenuItem(itemLabel, "")
		common.NodeMenuItems = append(common.NodeMenuItems, item)
		nodeParents = append(nodeParents, item)

		n := node
		parent := item
		utils.SafeGo("tray node menu", func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-parent.ClickedCh:
					for _, mi := range nodeParents {
						mi.Uncheck()
					}
					parent.Check()
					proxy.SwitchNode(n)
				}
			}
		})
	}

	if common.MTestAll != nil {
		utils.SafeGo("tray test all menu", func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-common.MTestAll.ClickedCh:
					common.MTestAll.SetTitle("⏳ 极速测速中...")
					common.MTestAll.Disable()

					// 🚀 核心优化：改用极低内存消耗的 proxy.FastTCPPing，并将并发放宽到 50
					sem := make(chan struct{}, 50)
					var wg sync.WaitGroup
					for i, n := range common.AllNodes {
						wg.Add(1)
						nd := n
						parent := nodeParents[i]
						utils.SafeGo("tray node tcp ping", func() {
							defer wg.Done()
							sem <- struct{}{}        // 获取令牌
							defer func() { <-sem }() // 释放令牌

							select {
							case <-ctx.Done():
								return
							default:
							}

							parent.SetTitle(fmt.Sprintf("[%s] %s - 测速中...", strings.ToUpper(nd.Type), nd.Name))
							latency, err := proxy.FastTCPPing(nd)
							if err != nil {
								parent.SetTitle(fmt.Sprintf("[%s] %s - ❌ 失败", strings.ToUpper(nd.Type), nd.Name))
							} else {
								parent.SetTitle(fmt.Sprintf("[%s] %s - ⚡ %dms", strings.ToUpper(nd.Type), nd.Name, latency))
							}
						})
					}
					wg.Wait()
					common.MTestAll.SetTitle("⚡ 极速测速所有节点 (TCP)")
					common.MTestAll.Enable()
					// 强制进行一次垃圾回收并释放系统内存
					runtime.GC()
					debug.FreeOSMemory()
				}
			}
		})
	}

	// 自动切换到导入的第一个新节点
	if len(newNodes) > 0 {
		firstNewIndex := len(common.AllNodes) - len(newNodes)
		if firstNewIndex >= 0 && firstNewIndex < len(nodeParents) {
			nodeParents[firstNewIndex].Check()
			proxy.SwitchNode(common.AllNodes[firstNewIndex])
		}
	}
}

func RefreshSupplierMenu() {
	if common.MSupplierMenu == nil {
		return
	}

	if common.SupplierMenuCancel != nil {
		common.SupplierMenuCancel()
	}
	var ctx context.Context
	ctx, common.SupplierMenuCancel = context.WithCancel(context.Background())

	for _, mi := range common.SupplierMenuItems {
		mi.Hide()
	}
	common.SupplierMenuItems = nil

	links, _ := ReadSubscriptions()
	for _, sub := range links {
		item := common.MSupplierMenu.AddSubMenuItem(sub.Name, sub.URL)
		common.SupplierMenuItems = append(common.SupplierMenuItems, item)

		if sub.FileName == CurrentConfigFile {
			item.Check()
		}

		mSwitch := item.AddSubMenuItem("✅ 切换至此供应商", "")
		mUpdate := item.AddSubMenuItem("🔄 更新此订阅", "")
		mDelete := item.AddSubMenuItem("🗑 删除此供应商", "")

		s := sub
		parent := item
		mSw := mSwitch
		mUp := mUpdate
		mDel := mDelete
		utils.SafeGo("tray supplier menu", func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-mSw.ClickedCh:
					nodes, err := protocol.ParseNodes(s.FileName)
					if err == nil && len(nodes) > 0 {
						SetActiveConfigFile(s.FileName)
						common.AllNodes = nodes

						for _, mi := range common.SupplierMenuItems {
							mi.Uncheck()
						}
						parent.Check()

						RefreshNodeMenu(nil)
						if len(common.AllNodes) > 0 {
							proxy.SwitchNode(common.AllNodes[0])
						}
					} else {
						utils.ShowWindowsMsgBox("切换失败", "无法读取该供应商的节点数据，请尝试更新订阅。")
					}
				case <-mUp.ClickedCh:
					parent.SetTitle(s.Name + " (🔄 更新中...)")
					nodes, traffic, err := ParseSubscriptionWithInfo(s.URL)
					if err == nil && len(nodes) > 0 {
						oldNodes, _ := protocol.ParseNodes(s.FileName)
						err = SaveNodesToYAML(s.FileName, nodes)
						if err == nil {
							NotifySubscriptionNodesUpdated(s.FileName, oldNodes, nodes)
							if traffic != nil {
								UpdateSubscriptionTraffic(s.URL, traffic)
							}
							if CurrentConfigFile == s.FileName {
								common.AllNodes = nodes
								RefreshNodeMenu(nil) // just refresh, no auto-switch
							}
							parent.SetTitle(s.Name)
							utils.ShowWindowsMsgBox("更新成功", fmt.Sprintf("🎉 成功更新了供应商 %s！\n共获取 %d 个节点。", s.Name, len(nodes)))
						} else {
							parent.SetTitle(s.Name + " (❌ 保存失败)")
							utils.ShowWindowsMsgBox("更新失败", "无法保存节点数据。")
						}
					} else {
						parent.SetTitle(s.Name + " (❌ 失败)")
						utils.ShowWindowsMsgBox("更新失败", "无法从该链接获取有效节点。")
					}
				case <-mDel.ClickedCh:
					DeleteSubscription(s.URL)
					parent.Hide()
					if CurrentConfigFile == s.FileName {
						// 如果删除的是当前正在使用的，则清空当前状态
						common.AllNodes = nil
						SetActiveConfigFile("")
						if common.MCurrentNode != nil {
							common.MCurrentNode.SetTitle("📍 当前节点: [未选择]")
						}
						RefreshNodeMenu(nil)
					}
				}
			}
		})
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
			oldNodes, _ := protocol.ParseNodes(l.FileName)
			NotifySubscriptionDeleted(l.FileName, oldNodes)
			_ = storage.Delete(l.FileName)
			_ = os.Remove(l.FileName)
		}
	}
	data, _ := json.MarshalIndent(newLinks, "", "  ")
	_ = storage.Write(SubscriptionsFile, data)
}

func ParseSubscriptionTraffic(headers http.Header) *SubscriptionTraffic {
	raw := strings.TrimSpace(headers.Get("subscription-userinfo"))
	if raw == "" {
		raw = strings.TrimSpace(headers.Get("Subscription-Userinfo"))
	}
	if raw == "" {
		return nil
	}

	values := map[string]int64{}
	for _, part := range strings.Split(raw, ";") {
		pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(pair) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(pair[0]))
		value := strings.TrimSpace(pair[1])
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}
		values[key] = n
	}

	total := values["total"]
	upload := values["upload"]
	download := values["download"]
	resetAt := firstNonZero(values, "reset", "reset_at", "next_reset", "next_reset_at", "reset_time")
	resetDay := firstNonZero(values, "reset_day", "resetday")
	updateInterval, _ := strconv.ParseInt(strings.TrimSpace(headers.Get("profile-update-interval")), 10, 64)
	used := upload + download
	remaining := total - used
	if remaining < 0 {
		remaining = 0
	}

	return &SubscriptionTraffic{
		Upload:                upload,
		Download:              download,
		Used:                  used,
		Total:                 total,
		Remaining:             remaining,
		Expire:                values["expire"],
		ResetAt:               resetAt,
		ResetDay:              resetDay,
		ProfileUpdateInterval: updateInterval,
		UpdatedAt:             time.Now().Unix(),
		Raw:                   raw,
	}
}

func firstNonZero(values map[string]int64, keys ...string) int64 {
	for _, key := range keys {
		if values[key] != 0 {
			return values[key]
		}
	}
	return 0
}

func ParseSubscription(input string) ([]protocol.Node, error) {
	nodes, _, err := ParseSubscriptionWithInfo(input)
	return nodes, err
}

func ParseSubscriptionWithInfo(input string) ([]protocol.Node, *SubscriptionTraffic, error) {
	var traffic *SubscriptionTraffic
	if isRemoteSubscription(input) {
		userAgents := []string{
			"wing/1.0",
			"ClashMeta",
			"Clash.Meta",
			"Clash",
			"clash-verge/v2.0",
			"sing-box",
			"Shadowrocket",
			"Karing/2.0.0",
			"Mihomo/1.18.3",
		}
		var bestNodes []protocol.Node
		var bestTraffic *SubscriptionTraffic
		var firstErr error

		for _, userAgent := range userAgents {
			info, infoErr := protocol.LoadInputWithUserAgentInfo(input, userAgent)
			if infoErr != nil {
				if firstErr == nil {
					firstErr = infoErr
				}
				continue
			}

			currentTraffic := ParseSubscriptionTraffic(info.Headers)

			parsed, parseErr := protocol.ParseSubscriptionRaw(info.Body)
			if parseErr != nil {
				if firstErr == nil {
					firstErr = parseErr
				}
				continue
			}

			if len(parsed) > len(bestNodes) {
				bestNodes = parsed
				if currentTraffic != nil {
					bestTraffic = currentTraffic
				}
			}
		}

		if len(bestNodes) == 0 {
			if firstErr != nil {
				return nil, nil, firstErr
			}
			return nil, nil, fmt.Errorf("订阅中未解析到可用节点")
		}
		return bestNodes, bestTraffic, nil
	}

	raw, err := protocol.LoadInput(input)
	if err != nil {
		return nil, nil, err
	}
	nodes, err := protocol.ParseSubscriptionRaw(raw)
	if err != nil {
		return nil, traffic, err
	}
	if len(nodes) == 0 {
		return nil, traffic, fmt.Errorf("订阅中未解析到可用节点")
	}
	return nodes, traffic, nil
}

func isRemoteSubscription(input string) bool {
	input = strings.TrimSpace(strings.Trim(input, "“”\"'"))
	return strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://")
}

func mergeNodes(base []protocol.Node, extra []protocol.Node) []protocol.Node {
	merged := make([]protocol.Node, 0, len(base)+len(extra))
	index := make(map[string]int, len(base)+len(extra))

	for _, node := range base {
		registerNodeIndexes(index, len(merged), node)
		merged = append(merged, node)
	}

	for _, node := range extra {
		matchIdx, exists := findExistingNodeIndex(index, node)
		if exists {
			if nodeScore(node) > nodeScore(merged[matchIdx]) {
				merged[matchIdx] = node
				registerNodeIndexes(index, matchIdx, node)
			}
			continue
		}
		registerNodeIndexes(index, len(merged), node)
		merged = append(merged, node)
	}

	return merged
}

func findExistingNodeIndex(index map[string]int, node protocol.Node) (int, bool) {
	for _, key := range nodeKeys(node) {
		if idx, ok := index[key]; ok {
			return idx, true
		}
	}
	return 0, false
}

func registerNodeIndexes(index map[string]int, idx int, node protocol.Node) {
	for _, key := range nodeKeys(node) {
		index[key] = idx
	}
}

func nodeKeys(node protocol.Node) []string {
	keys := []string{nodeStrictKey(node)}
	if weak := nodeWeakKey(node); weak != "" {
		keys = append(keys, weak)
	}
	return keys
}

func nodeStrictKey(node protocol.Node) string {
	network := strings.ToLower(strings.TrimSpace(node.Network))
	if network == "tcp" {
		network = ""
	}

	return fmt.Sprintf("strict|%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		node.Type,
		node.Server,
		node.Port,
		node.PortRange,
		node.UUID,
		node.Username,
		node.Password,
		node.HashedPassword,
		firstNonEmpty(node.Method, node.Cipher),
		firstNonEmpty(node.SNI, node.ServerName),
		node.Flow,
		firstNonEmpty(node.WSPath, node.WSOpts.Path),
		node.Host,
		node.Obfs,
		node.ObfsPassword,
		node.Transport,
		network,
	)
}

func nodeWeakKey(node protocol.Node) string {
	server := strings.ToLower(strings.TrimSpace(node.Server))
	if server == "" || node.Port == 0 {
		return ""
	}
	identity := firstNonEmpty(node.UUID, node.Password, node.HashedPassword)
	if identity == "" {
		return ""
	}
	return fmt.Sprintf("weak|%s|%s|%d|%s|%s",
		strings.ToLower(strings.TrimSpace(node.Type)),
		server,
		node.Port,
		firstNonEmpty(node.Method, node.Cipher),
		identity,
	)
}

func nodeScore(node protocol.Node) int {
	score := 0
	values := []string{
		node.Name,
		node.Server,
		node.UUID,
		node.Username,
		node.Password,
		node.HashedPassword,
		node.Method,
		node.Cipher,
		node.SNI,
		node.ServerName,
		node.Flow,
		node.WSPath,
		node.WSOpts.Path,
		node.Host,
		node.Obfs,
		node.ObfsPassword,
		node.Transport,
		node.Network,
		node.ClientFingerprint,
	}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			score++
		}
	}
	if node.Port > 0 {
		score++
	}
	if node.TLS || node.Tls {
		score++
	}
	if node.SkipCertVerify || node.Insecure || node.AllowInsecure {
		score++
	}
	if len(node.ALPN) > 0 {
		score++
	}
	return score
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func UpdateAllSubscriptions() {
	links, err := ReadSubscriptions()
	if err != nil || len(links) == 0 {
		utils.ShowWindowsMsgBox("更新失败", "没有找到保存的订阅链接。请先从剪贴板导入！")
		return
	}

	totalUpdated := 0
	for _, info := range links {
		nodes, traffic, err := ParseSubscriptionWithInfo(info.URL)
		if err == nil && len(nodes) > 0 {
			if traffic != nil {
				UpdateSubscriptionTraffic(info.URL, traffic)
			}
			oldNodes, _ := protocol.ParseNodes(info.FileName)
			err = SaveNodesToYAML(info.FileName, nodes)
			if err != nil {
				fmt.Printf("⚠️ 写入文件失败: %v\n", err)
			} else {
				NotifySubscriptionNodesUpdated(info.FileName, oldNodes, nodes)
				totalUpdated += len(nodes)
			}
			if CurrentConfigFile == info.FileName {
				common.AllNodes = nodes
				RefreshNodeMenu(nodes)
			}
		} else {
			fmt.Printf("⚠️ 链接更新失败或无节点: %s\n", info.URL)
		}
	}

	if totalUpdated == 0 {
		utils.ShowWindowsMsgBox("更新失败", "所有链接均未能获取到有效节点！")
		return
	}

	utils.ShowWindowsMsgBox("更新完成", fmt.Sprintf("🎉 成功从保存的链接中更新了 %d 个节点！", totalUpdated))
}

// StartAutoUpdateSubscriptions 启动后台自动更新任务
func StartAutoUpdateSubscriptions() {
	// 每 6 小时更新一次
	ticker := time.NewTicker(6 * time.Hour)
	utils.SafeGo("subscription auto update", func() {
		for range ticker.C {
			fmt.Println("开始执行后台自动更新订阅...")
			UpdateAllSubscriptionsSilently()
		}
	})
}

// UpdateAllSubscriptionsSilently 静默更新，不弹窗
func UpdateAllSubscriptionsSilently() {
	links, err := ReadSubscriptions()
	if err != nil || len(links) == 0 {
		return
	}

	for _, info := range links {
		nodes, traffic, err := ParseSubscriptionWithInfo(info.URL)
		if err == nil && len(nodes) > 0 {
			if traffic != nil {
				UpdateSubscriptionTraffic(info.URL, traffic)
			}
			oldNodes, _ := protocol.ParseNodes(info.FileName)
			if err := SaveNodesToYAML(info.FileName, nodes); err != nil {
				fmt.Printf("⚠️ 写入文件失败: %v\n", err)
				continue
			}
			NotifySubscriptionNodesUpdated(info.FileName, oldNodes, nodes)
			if CurrentConfigFile == info.FileName {
				common.AllNodes = nodes
				RefreshNodeMenu(nodes)
			}
		}
	}
}
