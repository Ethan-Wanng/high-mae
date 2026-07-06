package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wing/pkg/common"
	"wing/pkg/proxy"
	"wing/pkg/routing"
	"wing/pkg/storage"
	"wing/pkg/sub"
	"wing/protocol"
)

func TestQRCodeHandlerReturnsPNG(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/qrcode", strings.NewReader(`{"text":"vless://example"}`))
	rr := httptest.NewRecorder()

	qrCodeHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("qrCodeHandler status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("Content-Type = %q, want image/png", got)
	}
	body := rr.Body.Bytes()
	pngHeader := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	if len(body) < len(pngHeader) || string(body[:len(pngHeader)]) != string(pngHeader) {
		t.Fatalf("QR response is not a PNG")
	}
}

func TestAutoSelectConfigHandlerPersistsJSON(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	payload := `{"enabled":true,"scope":"subscription","subscriptionFiles":["sub_a.yml"],"rules":[]}`
	postReq := httptest.NewRequest(http.MethodPost, "/api/auto_select_config", strings.NewReader(payload))
	postRR := httptest.NewRecorder()

	autoSelectConfigHandler(postRR, postReq)

	if postRR.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d", postRR.Code, http.StatusOK)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/auto_select_config", nil)
	getRR := httptest.NewRecorder()
	autoSelectConfigHandler(getRR, getReq)

	var resp struct {
		OK     bool            `json:"ok"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(getRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GET response JSON error: %v", err)
	}
	if !resp.OK {
		t.Fatalf("GET response ok = false")
	}
	if !strings.Contains(string(resp.Config), "sub_a.yml") {
		t.Fatalf("persisted config = %s, want subscription file", resp.Config)
	}
}

func TestSystemConfigHandlerPersistsBingRedirectGuard(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	oldPort := common.LocalHttpPort
	oldGuard := common.PreventBingCNRedirect
	oldConfig := proxy.GlobalSystemConfig
	defer func() {
		common.LocalHttpPort = oldPort
		common.PreventBingCNRedirect = oldGuard
		proxy.GlobalSystemConfig = oldConfig
	}()

	common.LocalHttpPort = "10808"
	common.PreventBingCNRedirect = false
	proxy.GlobalSystemConfig = proxy.SystemConfig{ProxyPort: "10808"}

	req := httptest.NewRequest(http.MethodPost, "/api/system_config", strings.NewReader(`{"proxyPort":"10808","preventBingCNRedirect":true}`))
	rr := httptest.NewRecorder()
	systemConfigHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if !common.PreventBingCNRedirect {
		t.Fatal("expected runtime Bing redirect guard to be enabled")
	}

	common.PreventBingCNRedirect = false
	proxy.GlobalSystemConfig = proxy.SystemConfig{}
	proxy.LoadSystemConfig()

	if !common.PreventBingCNRedirect {
		t.Fatal("expected persisted Bing redirect guard to reload as enabled")
	}
	if !proxy.GlobalSystemConfig.PreventBingCNRedirect {
		t.Fatal("expected global system config to reload Bing redirect guard as enabled")
	}
}

func TestGetStatusHandlerReportsPendingProxyTarget(t *testing.T) {
	oldProxy := common.GetSystemProxyOn()
	oldMode := common.GetProxyMode()
	oldStartupDone := startupStateDone
	oldProxyPending := proxyPending.Load()
	oldProxyPendingState := proxyPendingState.Load()
	defer func() {
		common.SetSystemProxyOn(oldProxy)
		common.SetProxyMode(oldMode)
		proxyPending.Store(oldProxyPending)
		proxyPendingState.Store(oldProxyPendingState)
		startupStateMu.Lock()
		startupStateDone = oldStartupDone
		startupStateMu.Unlock()
	}()

	startupStateMu.Lock()
	startupStateDone = true
	startupStateMu.Unlock()
	common.SetSystemProxyOn(false)
	common.SetProxyMode("Rule")
	proxyPending.Store(true)
	proxyPendingState.Store(true)

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rr := httptest.NewRecorder()
	getStatusHandler(rr, req)

	var resp struct {
		Proxy        bool `json:"proxy"`
		ProxyPending bool `json:"proxyPending"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("status JSON error: %v", err)
	}
	if !resp.Proxy || !resp.ProxyPending {
		t.Fatalf("status proxy/pending = %v/%v, want true/true", resp.Proxy, resp.ProxyPending)
	}
}

func TestGetStatusHandlerReportsActiveNode(t *testing.T) {
	oldStartupDone := startupStateDone
	oldCurrentConfig := sub.CurrentConfigFile
	oldActiveNode, _ := common.ActiveNodeSnapshot()
	defer func() {
		sub.CurrentConfigFile = oldCurrentConfig
		common.SetActiveNode(oldActiveNode)
		startupStateMu.Lock()
		startupStateDone = oldStartupDone
		startupStateMu.Unlock()
	}()

	startupStateMu.Lock()
	startupStateDone = true
	startupStateMu.Unlock()
	sub.CurrentConfigFile = "sub_active.yml"
	common.SetActiveNode(protocol.Node{Name: "active-node", Type: "hysteria2", Group: "Group A", SourceFile: "source.yml"})

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rr := httptest.NewRecorder()
	getStatusHandler(rr, req)

	var resp struct {
		ActiveNodeName     string `json:"activeNodeName"`
		ActiveNodeType     string `json:"activeNodeType"`
		ActiveNodeGroup    string `json:"activeNodeGroup"`
		ActiveNodeFileName string `json:"activeNodeFileName"`
		ActiveNodeSource   string `json:"activeNodeSource"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("status JSON error: %v", err)
	}
	if resp.ActiveNodeName != "active-node" || resp.ActiveNodeType != "hysteria2" || resp.ActiveNodeGroup != "Group A" || resp.ActiveNodeFileName != "sub_active.yml" || resp.ActiveNodeSource != "source.yml" {
		t.Fatalf("active node status = %+v, want active node fields", resp)
	}
}

func TestResetRulesHandlerRestoresDefaultRulesWithoutBingDirect(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	oldGroups := routing.RuleGroups
	defer func() { routing.RuleGroups = oldGroups }()

	routing.RuleGroups = []routing.RuleGroup{
		{
			ID:     "direct",
			Name:   "Direct",
			Action: "direct",
			Rules: []routing.CustomRule{
				{Type: "domain_suffix", Value: "bing.com"},
				{Type: "domain", Value: "cn.bing.com"},
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/rules/reset_default", nil)
	rr := httptest.NewRecorder()
	resetRulesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp struct {
		OK     bool                `json:"ok"`
		Groups []routing.RuleGroup `json:"groups"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response JSON error: %v", err)
	}
	if !resp.OK {
		t.Fatal("expected ok response")
	}
	for _, group := range resp.Groups {
		for _, rule := range group.Rules {
			if (rule.Type == "domain_suffix" && rule.Value == "bing.com") || (rule.Type == "domain" && rule.Value == "cn.bing.com") {
				t.Fatalf("reset default response still includes legacy Bing direct rule: %+v", rule)
			}
		}
	}
}

func TestApplyRulesHandlerAppliesRoutingAndCmdRulesImmediately(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	oldGroups := routing.GetRuleGroups()
	oldCmdRules := routing.GetCmdRules()
	oldMode := common.GetProxyMode()
	oldSystemProxy := common.GetSystemProxyOn()
	defer func() {
		_ = routing.SaveAllRules(oldGroups, oldCmdRules)
		common.SetProxyMode(oldMode)
		common.SetSystemProxyOn(oldSystemProxy)
	}()

	common.SetProxyMode("Rule")
	common.SetSystemProxyOn(false)
	payload := `{
		"ruleGroups":[
			{"id":"direct","name":"Direct","action":"direct","rules":[{"type":"domain","value":"Example.COM"}]}
		],
		"cmdRules":[
			{"pattern":"curl https://example.com","type":"prefix","action":"direct"}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/rules/apply", strings.NewReader(payload))
	rr := httptest.NewRecorder()

	applyRulesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if got := routing.EvaluateRouting("example.com:443"); got != "direct" {
		t.Fatalf("EvaluateRouting immediately after save = %q, want direct", got)
	}
	action, matched := routing.EvaluateCmdRouting("curl https://example.com/path")
	if !matched || action != "direct" {
		t.Fatalf("EvaluateCmdRouting immediately after save = %q/%v, want direct/true", action, matched)
	}
}

func TestGetNodesMarksOnlyActiveSourceNodeActive(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	oldCurrentConfig := sub.CurrentConfigFile
	oldActiveNode, _ := common.ActiveNodeSnapshot()
	oldAllNodes := common.GetAllNodes()
	oldStartupDone := startupStateDone
	defer func() {
		sub.CurrentConfigFile = oldCurrentConfig
		common.SetActiveNode(oldActiveNode)
		common.SetAllNodes(oldAllNodes)
		startupStateMu.Lock()
		startupStateDone = oldStartupDone
		startupStateMu.Unlock()
		globalNodesMu.Lock()
		globalNodesCache = nil
		globalNodesMu.Unlock()
	}()

	firstFile, _, err := sub.AppendSubscriptionWithTraffic("https://one.example/sub", nil)
	if err != nil {
		t.Fatalf("append first subscription: %v", err)
	}
	secondFile, _, err := sub.AppendSubscriptionWithTraffic("https://two.example/sub", nil)
	if err != nil {
		t.Fatalf("append second subscription: %v", err)
	}
	sameNameNode := protocol.Node{Type: "naive", Name: "same-name", Server: "example.com", Port: 443}
	if err := sub.SaveNodesToYAML(firstFile, []protocol.Node{sameNameNode}); err != nil {
		t.Fatalf("save first nodes: %v", err)
	}
	if err := sub.SaveNodesToYAML(secondFile, []protocol.Node{sameNameNode}); err != nil {
		t.Fatalf("save second nodes: %v", err)
	}

	sub.CurrentConfigFile = secondFile
	common.SetActiveNode(protocol.Node{Name: "same-name"})
	startupStateMu.Lock()
	startupStateDone = true
	startupStateMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	rr := httptest.NewRecorder()
	getNodes(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", rr.Code, http.StatusOK)
	}
	var nodes []GlobalNodeInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("response JSON error: %v", err)
	}
	activeByFile := map[string]bool{}
	for _, node := range nodes {
		if node.Name == "same-name" {
			activeByFile[node.FileName] = node.Active
		}
	}
	if activeByFile[firstFile] {
		t.Fatalf("node from inactive file %s was marked active", firstFile)
	}
	if !activeByFile[secondFile] {
		t.Fatalf("node from current file %s was not marked active", secondFile)
	}
}

func TestSwitchSupplierRejectsUnknownFile(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	req := httptest.NewRequest(http.MethodPost, "/api/switch_supplier?file=../config.yml", nil)
	rr := httptest.NewRecorder()
	switchSupplierHandler(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected unknown supplier file to be rejected, got %d", rr.Code)
	}
}

func TestGetSuppliersHandlerRedactsSubscriptionURL(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	oldStartupDone := startupStateDone
	defer func() {
		startupStateMu.Lock()
		startupStateDone = oldStartupDone
		startupStateMu.Unlock()
	}()
	startupStateMu.Lock()
	startupStateDone = true
	startupStateMu.Unlock()

	secretURL := "https://user:pass@example.com/subscription/token-secret?token=abc123&password=hidden"
	if _, _, err := sub.AppendSubscriptionWithTraffic(secretURL, nil); err != nil {
		t.Fatalf("append subscription: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/suppliers", nil)
	rr := httptest.NewRecorder()
	getSuppliersHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", rr.Code, http.StatusOK)
	}
	var suppliers []struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &suppliers); err != nil {
		t.Fatalf("response JSON error: %v", err)
	}
	var got string
	for _, supplier := range suppliers {
		got = supplier.URL
		break
	}
	if got == "" {
		t.Fatalf("regular supplier not found in %+v", suppliers)
	}
	for _, leaked := range []string{"user", "pass", "token-secret", "abc123", "hidden"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redacted supplier URL %q leaked %q", got, leaked)
		}
	}
	if got != "https://example.com/<redacted>" {
		t.Fatalf("redacted supplier URL = %q, want host-only redaction", got)
	}
}

func TestSupplierURLHandlerReturnsOriginalURLOnPost(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	secretURL := "https://example.com/subscription/token-secret?token=abc123"
	fileName, _, err := sub.AppendSubscriptionWithTraffic(secretURL, nil)
	if err != nil {
		t.Fatalf("append subscription: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/supplier_url?file="+url.QueryEscape(fileName), nil)
	rr := httptest.NewRecorder()
	supplierURLHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp struct {
		OK  bool   `json:"ok"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response JSON error: %v", err)
	}
	if !resp.OK || resp.URL != secretURL {
		t.Fatalf("supplier URL response = %+v, want original URL", resp)
	}
}

func TestEditSupplierRejectsDuplicateURL(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	firstURL := "https://one.example/sub"
	secondURL := "https://two.example/sub"
	firstFile, _, err := sub.AppendSubscriptionWithTraffic(firstURL, nil)
	if err != nil {
		t.Fatalf("append first subscription: %v", err)
	}
	if _, _, err := sub.AppendSubscriptionWithTraffic(secondURL, nil); err != nil {
		t.Fatalf("append second subscription: %v", err)
	}

	payload := `{"url":"` + secondURL + `","updateIntervalMinutes":60}`
	req := httptest.NewRequest(http.MethodPost, "/api/edit_supplier?file="+url.QueryEscape(firstFile), strings.NewReader(payload))
	rr := httptest.NewRecorder()
	editSupplierHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d", rr.Code, http.StatusOK)
	}
	var resp struct {
		OK  bool   `json:"ok"`
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response JSON error: %v", err)
	}
	if resp.OK {
		t.Fatalf("duplicate URL edit succeeded: %+v", resp)
	}

	links, err := sub.ReadSubscriptions()
	if err != nil {
		t.Fatalf("ReadSubscriptions() error = %v", err)
	}
	for _, link := range links {
		if link.FileName == firstFile && link.URL != firstURL {
			t.Fatalf("first subscription URL changed to %q after rejected edit", link.URL)
		}
	}
}

func TestAddNodeStoresInCustomNodesGroup(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	oldCurrentConfig := sub.CurrentConfigFile
	oldAllNodes := common.GetAllNodes()
	oldStartupDone := startupStateDone
	defer func() {
		sub.CurrentConfigFile = oldCurrentConfig
		common.SetAllNodes(oldAllNodes)
		startupStateMu.Lock()
		startupStateDone = oldStartupDone
		startupStateMu.Unlock()
		globalNodesMu.Lock()
		globalNodesCache = nil
		globalNodesMu.Unlock()
	}()
	startupStateMu.Lock()
	startupStateDone = true
	startupStateMu.Unlock()
	sub.SetActiveConfigFile("some_subscription.yml")
	common.SetAllNodes([]protocol.Node{{Type: "ss", Name: "existing-sub-node", Server: "old.example", Port: 443}})

	payload := `{"input":"vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=tls&sni=example.com#custom-node"}`
	req := httptest.NewRequest(http.MethodPost, "/api/add_node", strings.NewReader(payload))
	rr := httptest.NewRecorder()
	addNodeHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("addNodeHandler status = %d, body=%s", rr.Code, rr.Body.String())
	}
	nodes, err := protocol.ParseNodes(CustomNodesFile)
	if err != nil {
		t.Fatalf("ParseNodes(%q) error = %v", CustomNodesFile, err)
	}
	if len(nodes) != 1 || nodes[0].Name != "custom-node" {
		t.Fatalf("custom nodes = %+v, want added node only", nodes)
	}
	if sub.CurrentConfigFile != CustomNodesFile {
		t.Fatalf("CurrentConfigFile = %q, want %q", sub.CurrentConfigFile, CustomNodesFile)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	getRR := httptest.NewRecorder()
	getNodes(getRR, getReq)
	var listed []GlobalNodeInfo
	if err := json.Unmarshal(getRR.Body.Bytes(), &listed); err != nil {
		t.Fatalf("nodes response JSON error: %v", err)
	}
	found := false
	for _, node := range listed {
		if node.FileName == CustomNodesFile && node.Group == CustomNodesName && node.Name == "custom-node" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom node not listed in /api/nodes: %+v", listed)
	}
}

func TestCreateAggregatedGroupUsesUniqueFileNames(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	node := protocol.Node{
		Type:     "ss",
		Name:     "node-a",
		Server:   "example.com",
		Port:     443,
		Method:   "aes-128-gcm",
		Password: "secret",
	}
	var fileNames []string
	for _, name := range []string{"group-a", "group-b"} {
		payload, err := json.Marshal(map[string]interface{}{
			"name":  name,
			"nodes": []protocol.Node{node},
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/create_aggregated_group", strings.NewReader(string(payload)))
		rr := httptest.NewRecorder()
		createAggregatedGroupHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("createAggregatedGroupHandler status = %d, body=%s", rr.Code, rr.Body.String())
		}
		var resp struct {
			OK       bool   `json:"ok"`
			FileName string `json:"fileName"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response JSON error: %v", err)
		}
		if !resp.OK || resp.FileName == "" {
			t.Fatalf("create response = %+v, want ok with fileName", resp)
		}
		if !isManagedAggregateGroupFileName(resp.FileName) {
			t.Fatalf("created aggregate file %q is not a managed group file", resp.FileName)
		}
		fileNames = append(fileNames, resp.FileName)
	}
	if fileNames[0] == fileNames[1] {
		t.Fatalf("aggregate groups reused file name %q", fileNames[0])
	}

	groups, err := ReadAggregateGroups()
	if err != nil {
		t.Fatalf("ReadAggregateGroups() error = %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("ReadAggregateGroups() len = %d, want 2", len(groups))
	}
	for _, fileName := range fileNames {
		nodes, err := protocol.ParseNodes(fileName)
		if err != nil {
			t.Fatalf("ParseNodes(%q) error = %v", fileName, err)
		}
		if len(nodes) != 1 || nodes[0].Name != node.Name {
			t.Fatalf("ParseNodes(%q) = %+v, want one node", fileName, nodes)
		}
	}
}

func TestSwitchAggregateGroupRejectsMissingNodeFile(t *testing.T) {
	_ = storage.Close()
	t.Setenv("WING_DB_PATH", filepath.Join(t.TempDir(), "wing.db"))
	t.Cleanup(func() { _ = storage.Close() })

	if err := SaveAggregateGroups([]AggregateGroup{{Name: "broken", FileName: "group_missing.yml"}}); err != nil {
		t.Fatalf("SaveAggregateGroups() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/switch_aggregate_group?file=group_missing.yml", nil)
	rr := httptest.NewRecorder()
	switchAggregateGroupHandler(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("switchAggregateGroupHandler status = %d, body=%s; want error for missing node file", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK  bool   `json:"ok"`
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response JSON error: %v", err)
	}
	if resp.OK || resp.Msg == "" {
		t.Fatalf("response = %+v, want explicit failure", resp)
	}
}

func TestStateChangingHandlersRejectGet(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		handler http.HandlerFunc
	}{
		{name: "switch supplier", path: "/api/switch_supplier?file=sub_1.yml", handler: switchSupplierHandler},
		{name: "supplier url", path: "/api/supplier_url?file=sub_1.yml", handler: supplierURLHandler},
		{name: "update supplier", path: "/api/update_supplier?file=sub_1.yml", handler: updateSupplierHandler},
		{name: "delete supplier", path: "/api/delete_supplier?file=sub_1.yml", handler: deleteSupplierHandler},
		{name: "switch aggregate group", path: "/api/switch_aggregate_group?file=group_1.yml", handler: switchAggregateGroupHandler},
		{name: "delete aggregate group", path: "/api/delete_aggregate_group?file=group_1.yml", handler: deleteAggregateGroupHandler},
		{name: "set aggregate group nodes", path: "/api/aggregate_group_set_nodes", handler: aggGroupSetNodesHandler},
		{name: "test all", path: "/api/test_all", handler: testAllHandler},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rr := httptest.NewRecorder()
			tt.handler(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

func TestDirectRuleAlreadyCoversSniffDomain(t *testing.T) {
	groups := []routing.RuleGroup{
		{
			ID:     "direct",
			Name:   "直连组",
			Action: "direct",
			Rules: []routing.CustomRule{
				{Type: "domain_suffix", Value: "www.baidu.com"},
				{Type: "domain", Value: "chat.example.com"},
			},
		},
		{
			ID:     "proxy",
			Name:   "代理组",
			Action: "proxy",
			Rules: []routing.CustomRule{
				{Type: "domain_suffix", Value: "qq.com"},
				{Type: "domain", Value: "bilibili.com", Action: "direct"},
			},
		},
		{
			ID:     "override",
			Name:   "覆盖组",
			Action: "direct",
			Rules: []routing.CustomRule{
				{Type: "domain_suffix", Value: "zhihu.com", Action: "proxy"},
			},
		},
	}

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{name: "direct suffix with www variant", domain: "baidu.com", want: true},
		{name: "direct exact", domain: "chat.example.com", want: true},
		{name: "rule action direct overrides proxy group", domain: "bilibili.com", want: true},
		{name: "proxy group does not count", domain: "qq.com", want: false},
		{name: "rule action proxy overrides direct group", domain: "zhihu.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := directRuleAlreadyCoversDomain(groups, tt.domain)
			if got != tt.want {
				t.Fatalf("directRuleAlreadyCoversDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestRunSiteTestsRunsTargetsSequentially(t *testing.T) {
	var active int32
	var maxActive int32
	var mu sync.Mutex
	var paths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&active, 1)
		for {
			max := atomic.LoadInt32(&maxActive)
			if current <= max || atomic.CompareAndSwapInt32(&maxActive, max, current) {
				break
			}
		}
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	targets := []SiteTestTarget{
		{ID: "one", Name: "One", Category: "test", URL: server.URL + "/one"},
		{ID: "two", Name: "Two", Category: "test", URL: server.URL + "/two"},
		{ID: "three", Name: "Three", Category: "test", URL: server.URL + "/three"},
	}

	results := runSiteTests(server.Client(), targets)

	if len(results) != len(targets) {
		t.Fatalf("runSiteTests returned %d results, want %d", len(results), len(targets))
	}
	if maxActive != 1 {
		t.Fatalf("runSiteTests ran %d site requests concurrently, want 1", maxActive)
	}
	wantPaths := []string{"/one", "/two", "/three"}
	if len(paths) != len(wantPaths) {
		t.Fatalf("request count = %d, want %d", len(paths), len(wantPaths))
	}
	for i, want := range wantPaths {
		if paths[i] != want {
			t.Fatalf("request order[%d] = %q, want %q", i, paths[i], want)
		}
	}
}

func TestEvaluateSiteAccessDetectsGeminiRegionUnsupported(t *testing.T) {
	target := SiteTestTarget{
		ID:       "preset_gemini",
		Name:     "Gemini",
		Category: "AI",
		URL:      "https://gemini.google.com/",
		Preset:   true,
	}

	ok, msg := evaluateSiteAccess(target, 200, "Gemini目前不支持你所在的地区。敬请期待！")
	if ok {
		t.Fatalf("expected Gemini region unsupported page to fail, got ok with %q", msg)
	}
	if msg != "地区不支持" {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func TestEvaluateSiteAccessAllowsChatGPTProbeChallenge(t *testing.T) {
	target := SiteTestTarget{
		ID:       "preset_chatgpt",
		Name:     "ChatGPT",
		Category: "AI",
		URL:      "https://chatgpt.com/",
		Preset:   true,
	}

	ok, msg := evaluateSiteAccess(target, 403, "Just a moment...")
	if !ok {
		t.Fatalf("expected ChatGPT challenge response to be treated as reachable, got %q", msg)
	}
}

func TestEvaluateSiteAccessDetectsChatGPTRegionUnsupported(t *testing.T) {
	target := SiteTestTarget{
		ID:       "preset_chatgpt",
		Name:     "ChatGPT",
		Category: "AI",
		URL:      "https://chatgpt.com/",
		Preset:   true,
	}

	ok, msg := evaluateSiteAccess(target, 200, "OpenAI's services are not available in your country.")
	if ok {
		t.Fatalf("expected ChatGPT region unsupported page to fail, got ok with %q", msg)
	}
}

func TestShouldRetryGeminiProbeOnAmbiguousFailure(t *testing.T) {
	target := SiteTestTarget{
		ID:       "preset_gemini",
		Name:     "Gemini",
		Category: "AI",
		URL:      "https://gemini.google.com/",
		Preset:   true,
	}
	result := SiteTestResult{StatusCode: 503, OK: false}

	if !shouldRetryGeminiProbe(target, result, "temporary error", "https://gemini.google.com/_/BardChatUi/") {
		t.Fatal("expected ambiguous Gemini failure to retry fallback probe")
	}
	if shouldRetryGeminiProbe(target, result, "Gemini目前不支持你所在的地区。", "https://gemini.google.com/_/BardChatUi/") {
		t.Fatal("did not expect explicit region unsupported page to retry fallback probe")
	}
}

func TestPresetSiteTargetsDoNotIncludeReuters(t *testing.T) {
	for _, target := range presetSiteTargets {
		if target.ID == "preset_reuters" || target.URL == "https://www.reuters.com/" {
			t.Fatalf("Reuters should not be a preset target: %+v", target)
		}
	}
}
