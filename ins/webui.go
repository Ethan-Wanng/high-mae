package ins

import (
	"encoding/json"
	"fmt"
	"high-mae/protocol"
	"net/http"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
)

var (
	uiServer *http.Server
	// Cache latency to avoid re-testing constantly
	latencyCache sync.Map
)

func StartWebUI() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", serveHTML)
	mux.HandleFunc("/api/nodes", getNodes)
	mux.HandleFunc("/api/switch", switchNodeHandler)
	mux.HandleFunc("/api/test_single", testSingleHandler)
	mux.HandleFunc("/api/test_all", testAllHandler)
	mux.HandleFunc("/api/status", getStatusHandler)
	mux.HandleFunc("/api/action", actionHandler)
	mux.HandleFunc("/api/suppliers", getSuppliersHandler)
	mux.HandleFunc("/api/switch_supplier", switchSupplierHandler)
	mux.HandleFunc("/api/update_supplier", updateSupplierHandler)
	mux.HandleFunc("/api/delete_supplier", deleteSupplierHandler)

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
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
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
		Name     string `json:"name"`
		FileName string `json:"fileName"`
		Active   bool   `json:"active"`
	}
	var list []SupplierInfo
	for _, l := range links {
		list = append(list, SupplierInfo{
			Name:     l.Name,
			FileName: l.FileName,
			Active:   l.FileName == CurrentConfigFile,
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

	nodes, err := ParseSubscription(target.URL)
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": fmt.Sprintf("成功更新 %d 个节点", len(nodes))})
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
