package ins

import (
	"encoding/json"
	"fmt"
	"high-mae/protocol"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"time"
)

var (
	uiServer *http.Server
	// Cache latency to avoid re-testing constantly
	latencyCache sync.Map
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
	status := map[string]interface{}{
		"proxy":    IsSystemProxyOn,
		"mode":     ProxyMode,
		"tun":      IsTunModeOn,
		"speedIn":  CurrentSpeedIn,
		"speedOut": CurrentSpeedOut,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func actionHandler(w http.ResponseWriter, r *http.Request) {
	actionType := r.URL.Query().Get("type")
	switch actionType {
	case "import":
		ImportNodeFromClipboard()
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
		ToggleTunMode(MToggleTun, Tun2socksBytes, WintunBytes)
	}
	w.WriteHeader(http.StatusOK)
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
