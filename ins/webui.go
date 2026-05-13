package ins

import (
	"encoding/json"
	"fmt"
	"high-mae/protocol"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	uiServer *http.Server
	// Cache latency to avoid re-testing constantly
	latencyCache sync.Map
	// TUN 切换中标记，防止轮询期间闪烁
	tunPending      atomic.Bool
	tunPendingState atomic.Bool
)

type AggregateGroup struct {
	Name     string `json:"name"`
	FileName string `json:"fileName"`
	Active   bool   `json:"active"`
}

const AggregateGroupsFile = "aggregate_groups.json"

func StartWebUI() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", serveHTML)
	mux.HandleFunc("/api/nodes", getNodes)
	mux.HandleFunc("/api/switch", switchNodeHandler)
	mux.HandleFunc("/api/test_single", testSingleHandler)
	mux.HandleFunc("/api/test_all", testAllHandler)
	mux.HandleFunc("/api/speedtest", speedtestHandler)
	mux.HandleFunc("/api/add_node", addNodeHandler)
	mux.HandleFunc("/api/status", getStatusHandler)
	mux.HandleFunc("/api/action", actionHandler)
	mux.HandleFunc("/api/suppliers", getSuppliersHandler)
	mux.HandleFunc("/api/switch_supplier", switchSupplierHandler)
	mux.HandleFunc("/api/update_supplier", updateSupplierHandler)
	mux.HandleFunc("/api/delete_supplier", deleteSupplierHandler)
	mux.HandleFunc("/api/rules", rulesHandler)
	mux.HandleFunc("/api/set_node_group", setNodeGroupHandler)
	mux.HandleFunc("/api/all_nodes_all_subs", getAllNodesAllSubsHandler)
	mux.HandleFunc("/api/create_aggregated_group", createAggregatedGroupHandler)
	mux.HandleFunc("/api/aggregate_groups", aggregateGroupsHandler)
	mux.HandleFunc("/api/switch_aggregate_group", switchAggregateGroupHandler)
	mux.HandleFunc("/api/delete_aggregate_group", deleteAggregateGroupHandler)
	mux.HandleFunc("/api/import_subscription", importSubscriptionHandler)
	mux.HandleFunc("/api/aggregate_group_nodes", aggGroupNodesHandler)
	mux.HandleFunc("/api/aggregate_group_add_nodes", aggGroupAddNodesHandler)
	mux.HandleFunc("/api/aggregate_group_remove_node", aggGroupRemoveNodeHandler)
	mux.HandleFunc("/api/dns", dnsHandler)

	// 默认开启 WebRTC 防泄漏
	IsWebRTCPolicyOn = CheckWebRTCLeakStatus()
	if !IsWebRTCPolicyOn {
		ToggleWebRTCLeak(true)
		IsWebRTCPolicyOn = true
	}

	uiServer = &http.Server{
		Addr:    "127.0.0.1:10809",
		Handler: mux,
	}

	uiServer.ListenAndServe()
}

func getNodes(w http.ResponseWriter, r *http.Request) {
	type NodeInfo struct {
		Index   int    `json:"index"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Latency int64  `json:"latency"`
		Active  bool   `json:"active"`
		Group   string `json:"group"`
	}

	var res []NodeInfo
	for i, n := range AllNodes {
		lat, _ := latencyCache.Load(i)
		latency, _ := lat.(int64)

		res = append(res, NodeInfo{
			Index:   i,
			Name:    n.Name,
			Type:    n.Type,
			Latency: latency,
			Active:  n.Name == ActiveNodeName,
			Group:   n.Group,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func rulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RuleGroups)
		return
	}
	if r.Method == http.MethodPost {
		var groups []RuleGroup
		if err := json.NewDecoder(r.Body).Decode(&groups); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if err := SaveRuleGroups(groups); err != nil {
			http.Error(w, "Save failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func setNodeGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idxStr := r.URL.Query().Get("idx")
	group := r.URL.Query().Get("group")
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 0 || idx >= len(AllNodes) {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	AllNodes[idx].Group = group
	if CurrentConfigFile != "" {
		SaveNodesToYAML(CurrentConfigFile, AllNodes)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func getAllNodesAllSubsHandler(w http.ResponseWriter, r *http.Request) {
	links, _ := ReadSubscriptions()

	type SubGroup struct {
		FileName string          `json:"fileName"`
		SubName  string          `json:"subName"`
		Nodes    []protocol.Node `json:"nodes"`
	}

	var res []SubGroup
	for _, l := range links {
		nodes, err := protocol.ParseNodes(l.FileName)
		if err == nil && len(nodes) > 0 {
			res = append(res, SubGroup{
				FileName: l.FileName,
				SubName:  l.Name,
				Nodes:    nodes,
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func createAggregatedGroupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name  string          `json:"name"`
		Nodes []protocol.Node `json:"nodes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	fileName := "group_" + strconv.FormatInt(time.Now().Unix(), 10) + ".yml"
	SaveNodesToYAML(fileName, req.Nodes)

	groups, _ := ReadAggregateGroups()
	groups = append(groups, AggregateGroup{Name: req.Name, FileName: fileName})
	SaveAggregateGroups(groups)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func ReadAggregateGroups() ([]AggregateGroup, error) {
	if _, err := os.Stat(AggregateGroupsFile); os.IsNotExist(err) {
		return []AggregateGroup{}, nil
	}
	data, err := os.ReadFile(AggregateGroupsFile)
	if err != nil {
		return nil, err
	}
	var groups []AggregateGroup
	if err := json.Unmarshal(data, &groups); err != nil {
		return nil, err
	}
	for i := range groups {
		groups[i].Active = groups[i].FileName == CurrentConfigFile
	}
	return groups, nil
}

func SaveAggregateGroups(groups []AggregateGroup) error {
	for i := range groups {
		groups[i].Active = false
	}
	data, err := json.MarshalIndent(groups, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(AggregateGroupsFile, data, 0644)
}

func aggregateGroupsHandler(w http.ResponseWriter, r *http.Request) {
	groups, _ := ReadAggregateGroups()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(groups)
}

func switchAggregateGroupHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	nodes, err := protocol.ParseNodes(fileName)
	if err == nil && len(nodes) > 0 {
		CurrentConfigFile = fileName
		AllNodes = nodes
		latencyCache = sync.Map{}
		RefreshNodeMenu(nil)
		if len(AllNodes) > 0 {
			SwitchNode(AllNodes[0])
		}
	}
	w.WriteHeader(http.StatusOK)
}

func deleteAggregateGroupHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	groups, _ := ReadAggregateGroups()
	var next []AggregateGroup
	found := false
	for _, group := range groups {
		if group.FileName == fileName {
			found = true
			os.Remove(group.FileName)
			continue
		}
		next = append(next, group)
	}
	if !found {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}
	SaveAggregateGroups(next)
	if CurrentConfigFile == fileName {
		AllNodes = nil
		CurrentConfigFile = ""
		latencyCache = sync.Map{}
		RefreshNodeMenu(nil)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func switchNodeHandler(w http.ResponseWriter, r *http.Request) {
	idxStr := r.URL.Query().Get("idx")
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 0 || idx >= len(AllNodes) {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	node := AllNodes[idx]
	SwitchNode(node)
	w.WriteHeader(http.StatusOK)
}

func testSingleHandler(w http.ResponseWriter, r *http.Request) {
	idxStr := r.URL.Query().Get("idx")
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 0 || idx >= len(AllNodes) {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	node := AllNodes[idx]
	lat, err := FastTCPPing(node)
	if err != nil {
		lat = -1 // Error state
	}
	latencyCache.Store(idx, lat)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"latency": lat})
}

func speedtestHandler(w http.ResponseWriter, r *http.Request) {
	idxStr := r.URL.Query().Get("idx")
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 0 || idx >= len(AllNodes) {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}
	node := AllNodes[idx]

	client, cleanup, err := CreateTempHTTPClient(node)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cleanup != nil {
		defer cleanup()
	}

	// 10MB test payload from Cloudflare
	req, _ := http.NewRequest("GET", "https://speed.cloudflare.com/__down?bytes=10000000", nil)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 限制测速时间最长 10 秒
	var written int64
	buf := make([]byte, 128*1024)
	timer := time.NewTimer(15 * time.Second)
	done := make(chan struct{})

	go func() {
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				written += int64(n)
			}
			if err != nil {
				break
			}
		}
		close(done)
	}()

	select {
	case <-done:
		timer.Stop()
	case <-timer.C:
		resp.Body.Close() // 必须先关 Body，让阻塞的 Read goroutine 返回
		client.CloseIdleConnections()
	}

	duration := time.Since(start).Seconds()
	if duration <= 0 {
		duration = 1
	}

	speed := float64(written) / duration // Bytes per second

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"speed": speed,
	})
}

func addNodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	input := req["input"]
	if input == "" {
		http.Error(w, "Empty input", http.StatusBadRequest)
		return
	}

	newNodes, err := ParseSubscription(input)
	if err != nil || len(newNodes) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": fmt.Sprintf("解析节点失败: %v", err)})
		return
	}

	targetFile := CurrentConfigFile
	if targetFile == "" {
		targetFile = "config.yml"
	}

	// 检查该节点是否已经存在？（按需，这里直接追加）
	AllNodes = append(AllNodes, newNodes...)
	err = SaveNodesToYAML(targetFile, AllNodes)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "保存节点数据失败"})
		return
	}

	CurrentConfigFile = targetFile
	RefreshNodeMenu(newNodes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": fmt.Sprintf("成功添加 %d 个节点", len(newNodes))})
}

func testAllHandler(w http.ResponseWriter, r *http.Request) {
	// Execute FastTCPPing for all nodes
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for i, node := range AllNodes {
		wg.Add(1)
		go func(idx int, n protocol.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			lat, err := FastTCPPing(n)
			if err != nil {
				lat = -1
			}
			latencyCache.Store(idx, lat)
		}(i, node)
	}
	wg.Wait()
	w.WriteHeader(http.StatusOK)
}

func getStatusHandler(w http.ResponseWriter, r *http.Request) {
	tunState := IsTunModeOn
	if tunPending.Load() {
		tunState = tunPendingState.Load()
	}
	status := map[string]interface{}{
		"proxy":    IsSystemProxyOn,
		"mode":     ProxyMode,
		"tun":      tunState,
		"webrtc":   IsWebRTCPolicyOn,
		"speedIn":  CurrentSpeedIn,
		"speedOut": CurrentSpeedOut,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func actionHandler(w http.ResponseWriter, r *http.Request) {
	actionType := r.URL.Query().Get("type")
	w.Header().Set("Content-Type", "application/json")
	switch actionType {
	case "proxy":
		IsSystemProxyOn = !IsSystemProxyOn
		SetSystemProxy(IsSystemProxyOn)
		if MToggleProxy != nil {
			if IsSystemProxyOn {
				MToggleProxy.SetTitle("🟢 系统代理: [已开启]")
			} else {
				MToggleProxy.SetTitle("⚪ 系统代理: [已关闭]")
			}
		}
	case "mode":
		if ProxyMode == "Rule" {
			ProxyMode = "Global"
			if MToggleMode != nil {
				MToggleMode.SetTitle("🌐 路由模式: [全局代理]")
			}
		} else {
			ProxyMode = "Rule"
			if MToggleMode != nil {
				MToggleMode.SetTitle("🔄 路由模式: [规则分流]")
			}
		}
	case "tun":
		if !IsAdmin() {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "开启虚拟网卡(TUN)需要管理员权限！请以管理员身份运行。"})
			return
		}
		// 标记 TUN 正在切换中，防止轮询期间把 checkbox 闪回旧状态
		tunTarget := !IsTunModeOn
		tunPending.Store(true)
		tunPendingState.Store(tunTarget)
		go func() {
			defer tunPending.Store(false)
			msg := ToggleTunMode(MToggleTun)
			if msg != "" {
				// 失败时不需要额外处理，ToggleTunMode 内部不会修改 IsTunModeOn
			}
		}()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
		return
	case "webrtc":
		IsWebRTCPolicyOn = !IsWebRTCPolicyOn
		ToggleWebRTCLeak(IsWebRTCPolicyOn)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":  true,
			"msg": "防 WebRTC 泄露策略已触发！\n\n注意：此功能通过修改 Windows 系统策略(Registry)实现，已向您请求管理员权限。\n如果策略未生效，请前往「chrome://policy」重新加载策略，或重启浏览器。",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func getSuppliersHandler(w http.ResponseWriter, r *http.Request) {
	links, _ := ReadSubscriptions()
	type SupplierInfo struct {
		Name     string               `json:"name"`
		FileName string               `json:"fileName"`
		Active   bool                 `json:"active"`
		Traffic  *SubscriptionTraffic `json:"traffic,omitempty"`
	}
	var list []SupplierInfo
	for _, l := range links {
		list = append(list, SupplierInfo{
			Name:     l.Name,
			FileName: l.FileName,
			Active:   l.FileName == CurrentConfigFile,
			Traffic:  l.Traffic,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func switchSupplierHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	nodes, err := protocol.ParseNodes(fileName)
	if err == nil && len(nodes) > 0 {
		CurrentConfigFile = fileName
		AllNodes = nodes
		latencyCache = sync.Map{} // 清空旧延迟缓存
		RefreshNodeMenu(nil)
		if len(AllNodes) > 0 {
			SwitchNode(AllNodes[0])
		}
	}
	w.WriteHeader(http.StatusOK)
}

func updateSupplierHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	links, _ := ReadSubscriptions()

	var target *SubInfo
	for i := range links {
		if links[i].FileName == fileName {
			target = &links[i]
			break
		}
	}
	if target == nil {
		http.Error(w, "Supplier not found", http.StatusNotFound)
		return
	}

	nodes, traffic, err := ParseSubscriptionWithInfo(target.URL)
	if err != nil || len(nodes) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": fmt.Sprintf("无法从该链接获取有效节点: %v", err)})
		return
	}

	err = SaveNodesToYAML(target.FileName, nodes)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "保存节点数据失败"})
		return
	}

	if CurrentConfigFile == target.FileName {
		AllNodes = nodes
		latencyCache = sync.Map{}
		RefreshNodeMenu(nil)
		runtime.GC()
		debug.FreeOSMemory()
	}
	if traffic != nil {
		target.Traffic = traffic
		data, _ := json.MarshalIndent(links, "", "  ")
		os.WriteFile(SubscriptionsFile, data, 0644)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": fmt.Sprintf("成功更新 %d 个节点", len(nodes)), "traffic": traffic})
}

func deleteSupplierHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	links, _ := ReadSubscriptions()

	found := false
	for _, l := range links {
		if l.FileName == fileName {
			DeleteSubscription(l.URL)
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "Supplier not found", http.StatusNotFound)
		return
	}

	if CurrentConfigFile == fileName {
		AllNodes = nil
		CurrentConfigFile = ""
		latencyCache = sync.Map{}
		RefreshNodeMenu(nil)
	}

	RefreshSupplierMenu()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func importSubscriptionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	respond := func(ok bool, msg string) {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": ok, "msg": msg})
	}

	// 1. 读取剪贴板
	out, err := exec.Command("powershell", "-command", "Get-Clipboard").Output()
	if err != nil {
		respond(false, "无法读取剪贴板内容！")
		return
	}

	input := strings.TrimSpace(string(out))
	if input == "" {
		respond(false, "剪贴板为空！请复制订阅链接或节点内容。")
		return
	}

	// 2. 解析节点
	newNodes, traffic, err := ParseSubscriptionWithInfo(input)
	if err != nil || len(newNodes) == 0 {
		respond(false, fmt.Sprintf("无法解析剪贴板内的节点或订阅: %v", err))
		return
	}

	// 3. 持久化链接到 JSON
	lines := strings.Split(input, "\n")
	targetFile := "config.yml"
	isOldLink := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			fName, existed, saveErr := AppendSubscriptionWithTraffic(line, traffic)
			if saveErr != nil {
				fmt.Printf("⚠️ 警告: 无法将链接保存到 JSON: %v\n", saveErr)
			} else if fName != "" {
				targetFile = fName
				isOldLink = existed
			}
		}
	}

	AllNodes = newNodes
	if err := SaveNodesToYAML(targetFile, AllNodes); err != nil {
		respond(false, "写入 .yml 文件失败: "+err.Error())
		return
	}

	CurrentConfigFile = targetFile
	refreshedNodes, err := protocol.ParseNodes(targetFile)
	if err == nil {
		AllNodes = refreshedNodes
	}

	latencyCache = sync.Map{}
	RefreshSupplierMenu()
	if isOldLink {
		RefreshNodeMenu(nil)
		respond(true, fmt.Sprintf("🎉 成功更新/覆盖了已存在的订阅！共 %d 个节点。", len(newNodes)))
	} else {
		RefreshNodeMenu(newNodes)
		respond(true, fmt.Sprintf("🎉 成功解析并导入 %d 个新节点！原始链接已保存。", len(newNodes)))
	}
}

func aggGroupNodesHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	nodes, err := protocol.ParseNodes(fileName)
	w.Header().Set("Content-Type", "application/json")
	if err != nil || nodes == nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	json.NewEncoder(w).Encode(nodes)
}

func aggGroupAddNodesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		File  string          `json:"file"`
		Nodes []protocol.Node `json:"nodes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	existing, _ := protocol.ParseNodes(req.File)
	existing = append(existing, req.Nodes...)
	if err := SaveNodesToYAML(req.File, existing); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": err.Error()})
		return
	}
	if CurrentConfigFile == req.File {
		AllNodes = existing
		latencyCache = sync.Map{}
		RefreshNodeMenu(nil)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "count": len(existing)})
}

func dnsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GlobalDNSConfig)
		return
	}
	if r.Method == http.MethodPost {
		var config DNSConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		GlobalDNSConfig = config
		if err := SaveDNSConfig(); err != nil {
			http.Error(w, "Save failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func aggGroupRemoveNodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fileName := r.URL.Query().Get("file")
	idxStr := r.URL.Query().Get("idx")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}
	nodes, _ := protocol.ParseNodes(fileName)
	if idx < 0 || idx >= len(nodes) {
		http.Error(w, "Index out of range", http.StatusBadRequest)
		return
	}
	nodes = append(nodes[:idx], nodes[idx+1:]...)
	if err := SaveNodesToYAML(fileName, nodes); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false})
		return
	}
	if CurrentConfigFile == fileName {
		AllNodes = nodes
		latencyCache = sync.Map{}
		RefreshNodeMenu(nil)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}
