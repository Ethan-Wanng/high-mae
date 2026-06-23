package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wing/pkg/common"
	"wing/pkg/freeflow"
	"wing/pkg/proxy"
	"wing/pkg/routing"
	"wing/pkg/secure"
	"wing/pkg/stats"
	"wing/pkg/storage"
	"wing/pkg/sub"
	"wing/pkg/utils"
	"wing/protocol"

	"github.com/getlantern/systray"
	"github.com/sagernet/sing/common/metadata"
	"github.com/skip2/go-qrcode"
)

var (
	uiServer   *http.Server
	uiServerMu sync.Mutex
	// Cache latency to avoid re-testing constantly
	latencyCache sync.Map
	speedCache   sync.Map
	// TUN 切换中标记，防止轮询期间闪烁
	tunPending       atomic.Bool
	tunPendingState  atomic.Bool
	nodeSwitching    atomic.Bool
	startupStateMu   sync.Mutex
	startupStateDone bool
)

type AggregateGroup struct {
	Name     string `json:"name"`
	FileName string `json:"fileName"`
	Active   bool   `json:"active"`
}

const AggregateGroupsFile = "aggregate_groups.json"
const SiteTestTargetsFile = "site_test_targets.json"
const AutoSelectConfigFile = "auto_select_config.json"
const siteTestTimeout = 25 * time.Second
const defaultUpdateLatestURL = "https://api.github.com/repos/Ethan-Wanng/high-mae/releases/latest"
const updateCacheTTL = 30 * time.Minute

type SiteTestTarget struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	URL      string `json:"url"`
	Preset   bool   `json:"preset"`
}

type SiteTestResult struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	URL        string `json:"url"`
	OK         bool   `json:"ok"`
	StatusCode int    `json:"statusCode,omitempty"`
	LatencyMS  int64  `json:"latencyMs,omitempty"`
	Message    string `json:"message"`
}

var presetSiteTargets = []SiteTestTarget{
	{ID: "preset_chatgpt", Name: "ChatGPT", Category: "AI", URL: "https://chatgpt.com/", Preset: true},
	{ID: "preset_gemini", Name: "Gemini", Category: "AI", URL: "https://gemini.google.com/", Preset: true},
	{ID: "preset_claude", Name: "Claude", Category: "AI", URL: "https://claude.ai/", Preset: true},
	{ID: "preset_tiktok", Name: "TikTok", Category: "视频", URL: "https://www.tiktok.com/", Preset: true},
	{ID: "preset_youtube", Name: "YouTube", Category: "视频", URL: "https://www.youtube.com/", Preset: true},
	{ID: "preset_netflix", Name: "Netflix", Category: "视频", URL: "https://www.netflix.com/", Preset: true},
	{ID: "preset_bbc", Name: "BBC News", Category: "新闻", URL: "https://www.bbc.com/news", Preset: true},
	{ID: "preset_espn", Name: "ESPN", Category: "体育", URL: "https://www.espn.com/", Preset: true},
}

func init() {
	sub.OnSubscriptionNodesUpdated = syncAggregateGroupsForSubscriptionUpdate
	sub.OnSubscriptionDeleted = removeSubscriptionNodesFromAggregateGroups
}

var (
	globalMux     *http.ServeMux
	globalMuxOnce sync.Once
)

func GetWebUIMux() *http.ServeMux {
	globalMuxOnce.Do(func() {
		globalMux = buildWebUIMux()
	})
	return globalMux
}

func buildWebUIMux() *http.ServeMux {
	mux := http.NewServeMux()
	api := func(pattern string, handler http.HandlerFunc) {
		mux.HandleFunc(pattern, localAPIHandler(handler))
	}

	mux.HandleFunc("/", serveHTML)
	mux.HandleFunc("/style.css", serveCSS)
	mux.HandleFunc("/script.js", serveJS)
	mux.HandleFunc("/logo-mark.png", serveLogoMark)
	mux.HandleFunc("/logo-mark-app.png", func(w http.ResponseWriter, r *http.Request) { servePNGBytes(w, r, logoMarkAppPNG) })
	mux.HandleFunc("/logo-mark-direct-dark.png", func(w http.ResponseWriter, r *http.Request) { servePNGBytes(w, r, logoMarkDirectDarkPNG) })
	mux.HandleFunc("/logo-mark-direct-light.png", func(w http.ResponseWriter, r *http.Request) { servePNGBytes(w, r, logoMarkDirectLightPNG) })
	mux.HandleFunc("/logo-mark-proxy.png", func(w http.ResponseWriter, r *http.Request) { servePNGBytes(w, r, logoMarkProxyPNG) })
	mux.HandleFunc("/logo-mark-tun.png", func(w http.ResponseWriter, r *http.Request) { servePNGBytes(w, r, logoMarkTunPNG) })
	mux.HandleFunc("/logo-mark-proxy-tun.png", func(w http.ResponseWriter, r *http.Request) { servePNGBytes(w, r, logoMarkProxyTunPNG) })
	api("/api/nodes", getNodes)
	api("/api/switch", switchNodeHandler)
	api("/api/direct", directNodeHandler)
	api("/api/node_link", nodeLinkHandler)
	api("/api/qrcode", qrCodeHandler)
	api("/api/delete_node", deleteNodeHandler)
	api("/api/test_single", testSingleHandler)
	api("/api/test_all", testAllHandler)
	api("/api/speedtest", speedtestHandler)
	api("/api/add_node", addNodeHandler)
	api("/api/status", getStatusHandler)
	api("/api/action", actionHandler)
	api("/api/site_targets", siteTargetsHandler)
	api("/api/site_test", siteTestHandler)
	api("/api/auto_select_config", autoSelectConfigHandler)
	api("/api/suppliers", getSuppliersHandler)
	api("/api/switch_supplier", switchSupplierHandler)
	api("/api/update_supplier", updateSupplierHandler)
	api("/api/delete_supplier", deleteSupplierHandler)
	api("/api/rules", rulesHandler)
	api("/api/rules/apply", applyRulesHandler)
	api("/api/rules/reset_default", resetRulesHandler)
	api("/api/sniff_direct_domains", sniffDirectDomainsHandler)
	api("/api/cmd_rules", cmdRulesHandler)
	api("/api/set_node_group", setNodeGroupHandler)
	api("/api/all_nodes_all_subs", getAllNodesAllSubsHandler)
	api("/api/create_aggregated_group", createAggregatedGroupHandler)
	api("/api/aggregate_groups", aggregateGroupsHandler)
	api("/api/switch_aggregate_group", switchAggregateGroupHandler)
	api("/api/delete_aggregate_group", deleteAggregateGroupHandler)
	api("/api/import_subscription", importSubscriptionHandler)
	api("/api/free_traffic", freeTrafficHandler)
	api("/api/set_supplier_update_interval", setSupplierUpdateIntervalHandler)
	api("/api/aggregate_group_nodes", aggGroupNodesHandler)
	api("/api/aggregate_group_add_nodes", aggGroupAddNodesHandler)
	api("/api/aggregate_group_remove_node", aggGroupRemoveNodeHandler)
	api("/api/dns", dnsHandler)
	api("/api/stats", getStatsHandler)
	api("/api/history", historyHandler)
	api("/api/clear_logs", clearLogsHandler)
	api("/api/privacy", privacyToggleHandler)
	api("/api/system_config", systemConfigHandler)
	api("/api/restart", restartHandler)
	api("/api/restart_admin", restartAdminHandler)
	api("/api/app_update", appUpdateHandler)
	api("/api/app_update/open", appUpdateOpenHandler)

	return mux
}

type appUpdateInfo struct {
	OK             bool   `json:"ok"`
	Available      bool   `json:"available"`
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion,omitempty"`
	Name           string `json:"name,omitempty"`
	PageURL        string `json:"pageUrl,omitempty"`
	DownloadURL    string `json:"downloadUrl,omitempty"`
	Message        string `json:"msg,omitempty"`
	Error          string `json:"error,omitempty"`
	CheckedAt      string `json:"checkedAt,omitempty"`
}

type githubReleaseInfo struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

var (
	appUpdateMu        sync.Mutex
	appUpdateCache     appUpdateInfo
	appUpdateCacheTime time.Time
)

const (
	apiRequestHeader      = "X-Wing-Request"
	apiRequestHeaderValue = "webui"
)

func localAPIHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setWebUISecurityHeaders(w)
		if !isTrustedLocalAPIRequest(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func isTrustedLocalAPIRequest(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" && !isTrustedWebUIOrigin(origin) {
		return false
	}
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" && !isTrustedWebUIOrigin(referer) {
		return false
	}
	return r.Header.Get(apiRequestHeader) == apiRequestHeaderValue
}

func isTrustedWebUIOrigin(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return isTrustedWebUIHost(parsed.Hostname())
}

func isTrustedWebUIHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	switch host {
	case "127.0.0.1", "localhost", "::1", "10.0.2.2", "10.0.3.2":
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			ip4[0] == 127 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168) ||
			(ip4[0] == 169 && ip4[1] == 254)
	}
	ip16 := ip.To16()
	return ip16 != nil &&
		(ip.IsLoopback() ||
			(ip16[0]&0xfe) == 0xfc ||
			(ip16[0] == 0xfe && (ip16[1]&0xc0) == 0x80))
}

func StartWebUI() {
	if err := EnsureStartupState(); err != nil {
		fmt.Printf("⚠️ 启动状态加载失败: %v\n", err)
	}
	mux := GetWebUIMux()

	// 默认开启 WebRTC 防泄漏
	common.IsWebRTCPolicyOn = routing.CheckWebRTCLeakStatus()
	if !common.IsWebRTCPolicyOn {
		routing.ToggleWebRTCLeak(true)
		common.IsWebRTCPolicyOn = true
	}

	uiServerMu.Lock()
	if uiServer != nil {
		uiServerMu.Unlock()
		return
	}
	uiServer = &http.Server{
		Addr:    "127.0.0.1:10809",
		Handler: mux,
	}
	server := uiServer
	uiServerMu.Unlock()

	err := server.ListenAndServe()
	uiServerMu.Lock()
	if uiServer == server {
		uiServer = nil
	}
	uiServerMu.Unlock()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("⚠️ Web UI 启动失败: %v\n", err)
	}
}

func EnsureStartupState() error {
	startupStateMu.Lock()
	defer startupStateMu.Unlock()
	if startupStateDone {
		return nil
	}
	if err := loadStartupStateLocked(); err != nil {
		return err
	}
	startupStateDone = true
	return nil
}

func loadStartupStateLocked() error {
	lastConfigFile, err := readOptionalStorageString("last_active_config_file")
	if err != nil {
		return fmt.Errorf("读取上次配置失败: %w", err)
	}
	lastNodeName, err := readOptionalStorageString("last_active_node_name")
	if err != nil {
		return fmt.Errorf("读取上次节点失败: %w", err)
	}

	links, err := sub.ReadSubscriptions()
	if err != nil {
		return fmt.Errorf("读取订阅列表失败: %w", err)
	}
	candidates := startupConfigCandidates(lastConfigFile, links)
	for _, fileName := range candidates {
		nodes, err := protocol.ParseNodes(fileName)
		if err != nil || len(nodes) == 0 {
			continue
		}
		sub.SetActiveConfigFile(fileName)
		common.AllNodes = nodes
		break
	}

	if len(common.AllNodes) == 0 {
		return nil
	}

	targetNode := common.AllNodes[0]
	if lastNodeName != "" {
		for _, node := range common.AllNodes {
			if node.Name == lastNodeName {
				targetNode = node
				break
			}
		}
	}

	common.ClientMu.RLock()
	activeName := common.ActiveNodeName
	activeClient := common.ActiveClient
	common.ClientMu.RUnlock()
	if activeClient == nil || activeName == "" {
		proxy.SwitchNode(targetNode)
	}
	return nil
}

func readOptionalStorageString(key string) (string, error) {
	data, err := storage.Read(key)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func startupConfigCandidates(lastConfigFile string, links []sub.SubInfo) []string {
	seen := make(map[string]struct{}, len(links)+1)
	var candidates []string
	add := func(fileName string) {
		fileName = strings.TrimSpace(fileName)
		if fileName == "" {
			return
		}
		if _, ok := seen[fileName]; ok {
			return
		}
		seen[fileName] = struct{}{}
		candidates = append(candidates, fileName)
	}
	add(lastConfigFile)
	for _, link := range links {
		add(link.FileName)
	}
	return candidates
}

type GlobalNodeInfo struct {
	Index      int    `json:"index"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Latency    int64  `json:"latency"`
	Speed      int64  `json:"speed"`
	Active     bool   `json:"active"`
	Group      string `json:"group"`
	FileName   string `json:"fileName"`
	SubIndex   int    `json:"subIndex"`
	SourceFile string `json:"sourceFile,omitempty"`
	SourceName string `json:"sourceName,omitempty"`
}

var (
	globalNodesCache []GlobalNodeInfo
	globalNodesMu    sync.Mutex
)

func getNodes(w http.ResponseWriter, r *http.Request) {
	EnsureStartupState()

	globalNodesMu.Lock()
	defer globalNodesMu.Unlock()

	var newCache []GlobalNodeInfo
	globalIdx := 0

	// 1. Load subscriptions
	subscriptions, _ := sub.ReadSubscriptions()
	for _, s := range subscriptions {
		nodes, err := protocol.ParseNodes(s.FileName)
		if err == nil {
			for subIdx, n := range nodes {
				lat, _ := latencyCache.Load(globalIdx)
				latency, _ := lat.(int64)
				spd, _ := speedCache.Load(globalIdx)
				speed, _ := spd.(int64)

				newCache = append(newCache, GlobalNodeInfo{
					Index:      globalIdx,
					Name:       n.Name,
					Type:       n.Type,
					Latency:    latency,
					Speed:      speed,
					Active:     n.Name == common.ActiveNodeName,
					Group:      s.Name,
					FileName:   s.FileName,
					SubIndex:   subIdx,
					SourceFile: s.FileName,
					SourceName: n.Name,
				})
				globalIdx++
			}
		}
	}

	// 2. Load aggregate groups
	aggregateGroups, _ := ReadAggregateGroups()
	for _, g := range aggregateGroups {
		nodes, err := protocol.ParseNodes(g.FileName)
		if err == nil {
			for subIdx, n := range nodes {
				lat, _ := latencyCache.Load(globalIdx)
				latency, _ := lat.(int64)
				spd, _ := speedCache.Load(globalIdx)
				speed, _ := spd.(int64)
				sourceName := n.SourceName
				if sourceName == "" {
					sourceName = n.Name
				}

				newCache = append(newCache, GlobalNodeInfo{
					Index:      globalIdx,
					Name:       n.Name,
					Type:       n.Type,
					Latency:    latency,
					Speed:      speed,
					Active:     n.Name == common.ActiveNodeName,
					Group:      g.Name,
					FileName:   g.FileName,
					SubIndex:   subIdx,
					SourceFile: n.SourceFile,
					SourceName: sourceName,
				})
				globalIdx++
			}
		}
	}

	globalNodesCache = newCache

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalNodesCache)
}

func resetNodeMetricCaches() {
	latencyCache = sync.Map{}
	speedCache = sync.Map{}
}

func rulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(routing.GetRuleGroups())
		return
	}
	if r.Method == http.MethodPost {
		var groups []routing.RuleGroup
		if err := json.NewDecoder(r.Body).Decode(&groups); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if err := routing.SaveRuleGroups(groups); err != nil {
			http.Error(w, "Save failed", http.StatusInternalServerError)
			return
		}
		if err := proxy.ApplyRoutingRulesChanged(); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "规则已保存，但重新应用系统代理失败: " + err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func applyRulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RuleGroups []routing.RuleGroup `json:"ruleGroups"`
		CmdRules   []routing.CmdRule   `json:"cmdRules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if err := routing.SaveAllRules(req.RuleGroups, req.CmdRules); err != nil {
		http.Error(w, "Save failed", http.StatusInternalServerError)
		return
	}
	if err := proxy.ApplyRoutingRulesChanged(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "规则已保存，但重新应用系统代理失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":         true,
		"msg":        "规则已保存并立即应用",
		"ruleGroups": routing.GetRuleGroups(),
		"cmdRules":   routing.GetCmdRules(),
	})
}

func resetRulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	groups := routing.DefaultRuleGroups()
	if err := routing.SaveRuleGroups(groups); err != nil {
		http.Error(w, "Save failed", http.StatusInternalServerError)
		return
	}
	if err := proxy.ApplyRoutingRulesChanged(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "规则已恢复，但重新应用系统代理失败: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "groups": routing.GetRuleGroups()})
}

func sniffDirectDomainsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	candidates := directSniffCandidates()
	added := make([]string, 0, len(candidates))
	groups := routing.GetRuleGroups()
	sniffIdx := -1
	for i := range groups {
		if groups[i].ID == "direct_sniff" || groups[i].Name == "嗅探到规则" {
			sniffIdx = i
			break
		}
	}
	if sniffIdx < 0 {
		groups = append(groups, routing.RuleGroup{ID: "direct_sniff", Name: "嗅探到规则", Action: "direct"})
		sniffIdx = len(groups) - 1
	}
	groups[sniffIdx].ID = "direct_sniff"
	groups[sniffIdx].Name = "嗅探到规则"
	groups[sniffIdx].Action = "direct"

	for _, domain := range candidates {
		domain = normalizeSniffDomain(domain)
		if domain == "" || directRuleAlreadyCoversDomain(groups, domain) || !looksMainlandDirectDomain(domain) {
			continue
		}
		if !probeDirectDomain(domain, 2400*time.Millisecond) {
			continue
		}
		groups[sniffIdx].Rules = append(groups[sniffIdx].Rules, routing.CustomRule{
			Type:  "domain_suffix",
			Value: domain,
		})
		added = append(added, domain)
	}

	if err := routing.SaveRuleGroups(groups); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "保存嗅探规则失败"})
		return
	}
	if err := proxy.ApplyRoutingRulesChanged(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "嗅探规则已保存，但重新应用系统代理失败: " + err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     true,
		"added":  added,
		"groups": routing.GetRuleGroups(),
	})
}

func directSniffCandidates() []string {
	ordered := []string{
		"baidu.com",
		"qq.com",
		"bilibili.com",
		"zhihu.com",
		"weibo.com",
		"jd.com",
		"taobao.com",
		"tmall.com",
		"aliyun.com",
		"mi.com",
		"163.com",
		"360.cn",
		"gov.cn",
		"china.com.cn",
	}
	for _, target := range readSiteTestTargets() {
		parsed, err := url.Parse(target.URL)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if host != "" {
			ordered = append(ordered, host)
		}
	}
	unique := make([]string, 0, len(ordered))
	seen := map[string]bool{}
	for _, domain := range ordered {
		domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "www.")
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		unique = append(unique, domain)
	}
	return unique
}

func directRuleAlreadyCoversDomain(groups []routing.RuleGroup, domain string) bool {
	domain = normalizeSniffDomain(domain)
	if domain == "" {
		return false
	}
	for _, group := range groups {
		groupAction := strings.ToLower(strings.TrimSpace(group.Action))
		for _, rule := range group.Rules {
			action := groupAction
			if strings.TrimSpace(rule.Action) != "" {
				action = strings.ToLower(strings.TrimSpace(rule.Action))
			}
			if action != "direct" {
				continue
			}
			if sniffRuleMatchesDomain(rule, domain) {
				return true
			}
		}
	}
	return false
}

func sniffRuleMatchesDomain(rule routing.CustomRule, domain string) bool {
	domain = normalizeSniffDomain(domain)
	value := normalizeSniffDomain(rule.Value)
	if domain == "" || value == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(rule.Type)) {
	case "domain", "exact":
		return domain == value
	case "domain_keyword", "keyword":
		return strings.Contains(domain, value)
	default:
		return domain == value || strings.HasSuffix(domain, "."+value)
	}
}

func normalizeSniffDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.Trim(domain, ".")
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}

func looksMainlandDirectDomain(domain string) bool {
	if strings.HasSuffix(domain, ".cn") {
		return true
	}
	known := []string{
		"baidu.com", "qq.com", "bilibili.com", "zhihu.com", "weibo.com", "jd.com",
		"taobao.com", "tmall.com", "aliyun.com", "mi.com", "163.com",
	}
	for _, suffix := range known {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

func probeDirectDomain(domain string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "80"))
	}
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func cmdRulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(routing.GetCmdRules())
		return
	}
	if r.Method == http.MethodPost {
		var rules []routing.CmdRule
		if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if err := routing.SaveCmdRules(rules); err != nil {
			http.Error(w, "Save failed", http.StatusInternalServerError)
			return
		}
		if err := proxy.ApplyRoutingRulesChanged(); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "命令行规则已保存，但重新应用系统代理失败: " + err.Error()})
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
	if err != nil || idx < 0 || idx >= len(common.AllNodes) {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	common.AllNodes[idx].Group = group
	if sub.CurrentConfigFile != "" {
		sub.SaveNodesToYAML(sub.CurrentConfigFile, common.AllNodes)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func getAllNodesAllSubsHandler(w http.ResponseWriter, r *http.Request) {
	links, _ := sub.ReadSubscriptions()

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
				Nodes:    withAggregateSource(l.FileName, nodes),
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
	sub.SaveNodesToYAML(fileName, normalizeAggregateSources(req.Nodes))

	groups, _ := ReadAggregateGroups()
	groups = append(groups, AggregateGroup{Name: req.Name, FileName: fileName})
	SaveAggregateGroups(groups)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func ReadAggregateGroups() ([]AggregateGroup, error) {
	data, err := secure.SecureReadFile(AggregateGroupsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []AggregateGroup{}, nil
		}
		return nil, err
	}
	var groups []AggregateGroup
	if err := json.Unmarshal(data, &groups); err != nil {
		return nil, err
	}
	for i := range groups {
		groups[i].Active = groups[i].FileName == sub.CurrentConfigFile
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
	return secure.SecureWriteFile(AggregateGroupsFile, data)
}

func aggregateGroupByFile(fileName string) (AggregateGroup, bool) {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		return AggregateGroup{}, false
	}
	groups, err := ReadAggregateGroups()
	if err != nil {
		return AggregateGroup{}, false
	}
	for _, group := range groups {
		if group.FileName == fileName {
			return group, true
		}
	}
	return AggregateGroup{}, false
}

func isManagedAggregateGroupFileName(fileName string) bool {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" || strings.ContainsAny(fileName, `/\`) || !strings.HasSuffix(fileName, ".yml") {
		return false
	}
	return strings.HasPrefix(fileName, "group_") || strings.HasPrefix(fileName, "agg_")
}

func withAggregateSource(sourceFile string, nodes []protocol.Node) []protocol.Node {
	out := make([]protocol.Node, len(nodes))
	for i, node := range nodes {
		node.SourceFile = sourceFile
		node.SourceKey = aggregateNodeKey(node)
		node.SourceName = node.Name
		out[i] = node
	}
	return out
}

func normalizeAggregateSources(nodes []protocol.Node) []protocol.Node {
	out := make([]protocol.Node, len(nodes))
	for i, node := range nodes {
		if node.SourceName == "" {
			node.SourceName = node.Name
		}
		if node.SourceKey == "" {
			node.SourceKey = aggregateNodeKey(node)
		}
		out[i] = node
	}
	return out
}

func aggregateNodeKey(node protocol.Node) string {
	network := strings.ToLower(strings.TrimSpace(node.Network))
	if network == "tcp" {
		network = ""
	}
	return fmt.Sprintf("%s|%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		node.Type,
		node.Name,
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

func aggregateNameTypeKey(node protocol.Node) string {
	return strings.ToLower(strings.TrimSpace(node.Type)) + "|" + strings.ToLower(strings.TrimSpace(node.Name))
}

func buildAggregateLookup(nodes []protocol.Node) (map[string]protocol.Node, map[string]protocol.Node) {
	byKey := make(map[string]protocol.Node, len(nodes))
	byNameType := make(map[string]protocol.Node, len(nodes))
	for _, node := range nodes {
		byKey[aggregateNodeKey(node)] = node
		if node.SourceKey != "" {
			byKey[node.SourceKey] = node
		}
		nameType := aggregateNameTypeKey(node)
		if _, exists := byNameType[nameType]; !exists {
			byNameType[nameType] = node
		}
	}
	return byKey, byNameType
}

func buildAggregateKeySet(nodes []protocol.Node) map[string]struct{} {
	keys := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		keys[aggregateNodeKey(node)] = struct{}{}
		if node.SourceKey != "" {
			keys[node.SourceKey] = struct{}{}
		}
	}
	return keys
}

func aggregateNodeBelongsToSource(node protocol.Node, sourceFile string, oldKeys map[string]struct{}) bool {
	if node.SourceFile == sourceFile {
		return true
	}
	if node.SourceFile != "" {
		return false
	}
	_, ok := oldKeys[aggregateNodeKey(node)]
	return ok
}

func replacementAggregateNode(node protocol.Node, sourceFile string, newByKey map[string]protocol.Node, newByNameType map[string]protocol.Node) (protocol.Node, bool) {
	keys := []string{node.SourceKey, aggregateNodeKey(node)}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if replacement, ok := newByKey[key]; ok {
			return withAggregateSource(sourceFile, []protocol.Node{replacement})[0], true
		}
	}
	if node.SourceName != "" {
		nameType := strings.ToLower(strings.TrimSpace(node.Type)) + "|" + strings.ToLower(strings.TrimSpace(node.SourceName))
		if replacement, ok := newByNameType[nameType]; ok {
			return withAggregateSource(sourceFile, []protocol.Node{replacement})[0], true
		}
	}
	if replacement, ok := newByNameType[aggregateNameTypeKey(node)]; ok {
		return withAggregateSource(sourceFile, []protocol.Node{replacement})[0], true
	}
	return protocol.Node{}, false
}

func syncAggregateGroupsForSubscriptionUpdate(sourceFile string, oldNodes []protocol.Node, newNodes []protocol.Node) {
	groups, err := ReadAggregateGroups()
	if err != nil || len(groups) == 0 {
		return
	}
	oldKeys := buildAggregateKeySet(oldNodes)
	newByKey, newByNameType := buildAggregateLookup(newNodes)

	for _, group := range groups {
		nodes, err := protocol.ParseNodes(group.FileName)
		if err != nil || len(nodes) == 0 {
			continue
		}
		next := make([]protocol.Node, 0, len(nodes))
		changed := false
		for _, node := range nodes {
			if !aggregateNodeBelongsToSource(node, sourceFile, oldKeys) {
				next = append(next, node)
				continue
			}
			replacement, ok := replacementAggregateNode(node, sourceFile, newByKey, newByNameType)
			if ok {
				next = append(next, replacement)
			}
			changed = true
		}
		if changed {
			_ = sub.SaveNodesToYAML(group.FileName, next)
			if sub.CurrentConfigFile == group.FileName {
				common.AllNodes = next
				resetNodeMetricCaches()
				sub.RefreshNodeMenu(nil)
			}
		}
	}
}

func removeSubscriptionNodesFromAggregateGroups(sourceFile string, oldNodes []protocol.Node) {
	groups, err := ReadAggregateGroups()
	if err != nil || len(groups) == 0 {
		return
	}
	oldKeys := buildAggregateKeySet(oldNodes)
	for _, group := range groups {
		nodes, err := protocol.ParseNodes(group.FileName)
		if err != nil || len(nodes) == 0 {
			continue
		}
		next := make([]protocol.Node, 0, len(nodes))
		changed := false
		for _, node := range nodes {
			if aggregateNodeBelongsToSource(node, sourceFile, oldKeys) {
				changed = true
				continue
			}
			next = append(next, node)
		}
		if changed {
			_ = sub.SaveNodesToYAML(group.FileName, next)
			if sub.CurrentConfigFile == group.FileName {
				common.AllNodes = next
				resetNodeMetricCaches()
				sub.RefreshNodeMenu(nil)
			}
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func aggregateGroupsHandler(w http.ResponseWriter, r *http.Request) {
	EnsureStartupState()
	groups, _ := ReadAggregateGroups()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(groups)
}

func switchAggregateGroupHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	group, ok := aggregateGroupByFile(fileName)
	if !ok {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}
	fileName = group.FileName
	nodes, err := protocol.ParseNodes(fileName)
	if err == nil && len(nodes) > 0 {
		sub.SetActiveConfigFile(fileName)
		common.AllNodes = nodes
		resetNodeMetricCaches()
		sub.RefreshNodeMenu(nil)
		if len(common.AllNodes) > 0 {
			proxy.SwitchNode(common.AllNodes[0])
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
			_ = storage.Delete(group.FileName)
			if isManagedAggregateGroupFileName(group.FileName) {
				_ = os.Remove(group.FileName)
			}
			continue
		}
		next = append(next, group)
	}
	if !found {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}
	SaveAggregateGroups(next)
	if sub.CurrentConfigFile == fileName {
		common.AllNodes = nil
		sub.SetActiveConfigFile("")
		resetNodeMetricCaches()
		sub.RefreshNodeMenu(nil)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func switchNodeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	idxStr := r.URL.Query().Get("idx")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	globalNodesMu.Lock()
	if idx < 0 || idx >= len(globalNodesCache) {
		globalNodesMu.Unlock()
		http.Error(w, "Index out of bounds", http.StatusBadRequest)
		return
	}
	node := globalNodesCache[idx]
	globalNodesMu.Unlock()
	if !nodeSwitching.CompareAndSwap(false, true) {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "节点正在切换中，请稍候。"})
		return
	}

	utils.SafeGo("webui switch node", func() {
		defer nodeSwitching.Store(false)

		// Switch config file if needed
		if sub.CurrentConfigFile != node.FileName {
			nodes, err := protocol.ParseNodes(node.FileName)
			if err == nil {
				sub.SetActiveConfigFile(node.FileName)
				common.AllNodes = nodes
				sub.RefreshNodeMenu(nil)
			}
		}

		// Double check to make sure index is valid in common.AllNodes
		if node.SubIndex >= 0 && node.SubIndex < len(common.AllNodes) {
			targetNode := common.AllNodes[node.SubIndex]
			proxy.SwitchNode(targetNode)
		}
	})

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "pending": true, "msg": "正在切换节点..."})
}

func directNodeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	common.ClientMu.Lock()
	common.ActiveClient = nil
	common.ActiveNode = protocol.Node{}
	common.ActiveNodeName = ""
	common.GlobalNodeServer = ""
	common.GlobalNodeIP = ""
	common.ClientMu.Unlock()
	if common.MCurrentNode != nil {
		common.MCurrentNode.SetTitle("当前节点: 直连")
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "已不选择节点，当前为直连"})
}

func nodeLinkHandler(w http.ResponseWriter, r *http.Request) {
	_, targetNode, ok := getGlobalNodeFromRequest(w, r)
	if !ok {
		return
	}

	link, err := protocol.ExportNodeLink(targetNode)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "link": link})
}

func qrCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	text := strings.TrimSpace(req.Text)
	if text == "" {
		http.Error(w, "Empty QR content", http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(text, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Generate QR failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

func deleteNodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodeInfo, targetNode, ok := getGlobalNodeFromRequest(w, r)
	if !ok {
		return
	}

	nodes, err := protocol.ParseNodes(nodeInfo.FileName)
	if err != nil {
		http.Error(w, "Read node file failed", http.StatusInternalServerError)
		return
	}
	if nodeInfo.SubIndex < 0 || nodeInfo.SubIndex >= len(nodes) {
		http.Error(w, "Node index mismatch", http.StatusBadRequest)
		return
	}

	nodes = append(nodes[:nodeInfo.SubIndex], nodes[nodeInfo.SubIndex+1:]...)
	if err := sub.SaveNodesToYAML(nodeInfo.FileName, nodes); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "保存节点数据失败"})
		return
	}

	if sub.CurrentConfigFile == nodeInfo.FileName {
		common.AllNodes = nodes
		resetNodeMetricCaches()
		sub.RefreshNodeMenu(nil)
		if targetNode.Name == common.ActiveNodeName {
			if len(nodes) > 0 {
				proxy.SwitchNode(nodes[0])
			} else {
				common.ActiveNodeName = ""
				if common.MCurrentNode != nil {
					common.MCurrentNode.SetTitle("📍 当前节点: [未选择]")
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func getGlobalNodeFromRequest(w http.ResponseWriter, r *http.Request) (GlobalNodeInfo, protocol.Node, bool) {
	idxStr := r.URL.Query().Get("idx")
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return GlobalNodeInfo{}, protocol.Node{}, false
	}

	globalNodesMu.Lock()
	if idx < 0 || idx >= len(globalNodesCache) {
		globalNodesMu.Unlock()
		http.Error(w, "Index out of bounds", http.StatusBadRequest)
		return GlobalNodeInfo{}, protocol.Node{}, false
	}
	nodeInfo := globalNodesCache[idx]
	globalNodesMu.Unlock()

	nodes, err := protocol.ParseNodes(nodeInfo.FileName)
	if err != nil || nodeInfo.SubIndex < 0 || nodeInfo.SubIndex >= len(nodes) {
		http.Error(w, "Node index mismatch", http.StatusBadRequest)
		return GlobalNodeInfo{}, protocol.Node{}, false
	}
	return nodeInfo, nodes[nodeInfo.SubIndex], true
}

func testSingleHandler(w http.ResponseWriter, r *http.Request) {
	nodeInfo, targetNode, ok := getGlobalNodeFromRequest(w, r)
	if !ok {
		return
	}

	var lat int64
	var err error
	if r.URL.Query().Get("current") == "1" && isCurrentActiveNode(targetNode) {
		lat, err = testActiveProxyLatency(8 * time.Second)
	} else {
		lat, err = proxy.FastTCPPing(targetNode)
	}
	if err != nil {
		lat = -1
	}
	latencyCache.Store(nodeInfo.Index, lat)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"latency": lat})
}

var speedtestSem = make(chan struct{}, 2)

var bandwidthTestTargets = []string{
	"https://speed.cloudflare.com/__down?bytes=10000000",
	"http://speed.cloudflare.com/__down?bytes=10000000",
	"http://cachefly.cachefly.net/10mb.test",
}

type bandwidthSample struct {
	bytes    int64
	duration float64
}

func speedtestHandler(w http.ResponseWriter, r *http.Request) {
	select {
	case speedtestSem <- struct{}{}:
		atomic.AddInt32(&common.ActiveSpeedtests, 1)
		defer func() {
			<-speedtestSem
			atomic.AddInt32(&common.ActiveSpeedtests, -1)
		}()
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "已有带宽测速正在进行，请稍后再试",
			"stage": "queued",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	nodeInfo, node, ok := getGlobalNodeFromRequest(w, r)
	if !ok {
		return
	}

	var client *http.Client
	var cleanup func()
	var err error
	if r.URL.Query().Get("current") == "1" && isCurrentActiveNode(node) {
		client, err = activeProxyHTTPClient()
	} else {
		client, cleanup, err = proxy.CreateTempHTTPClient(node)
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "stage": "create_client", "error": err.Error()})
		return
	}
	if cleanup != nil {
		defer cleanup()
	}
	client.Timeout = 0

	var sample bandwidthSample
	var lastErr error
	var lastTarget string
	for _, target := range bandwidthTestTargets {
		sample, err = runBandwidthSample(client, target, 12*time.Second)
		if err == nil {
			lastErr = nil
			lastTarget = target
			break
		}
		lastErr = err
		lastTarget = target
		client.CloseIdleConnections()
	}
	if lastErr != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":     false,
			"stage":  "request",
			"target": lastTarget,
			"error":  "所有测速源均不可用，最后错误: " + lastErr.Error(),
		})
		return
	}

	speed := float64(sample.bytes) / sample.duration // Bytes per second
	speedInt := int64(speed)
	speedCache.Store(nodeInfo.Index, speedInt)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       true,
		"speed":    speedInt,
		"bytes":    sample.bytes,
		"duration": sample.duration,
		"target":   lastTarget,
	})
}

func isCurrentActiveNode(node protocol.Node) bool {
	common.ClientMu.RLock()
	defer common.ClientMu.RUnlock()
	return common.ActiveClient != nil && common.ActiveNodeName != "" && common.ActiveNodeName == node.Name
}

func activeProxyHTTPClient() (*http.Client, error) {
	common.ClientMu.RLock()
	client := common.ActiveClient
	common.ClientMu.RUnlock()
	if client == nil {
		return nil, errors.New("当前没有正在工作的节点连接")
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return client.CreateProxy(ctx, metadata.ParseSocksaddr(addr))
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Transport: transport}, nil
}

func testActiveProxyLatency(timeout time.Duration) (int64, error) {
	common.ClientMu.RLock()
	client := common.ActiveClient
	common.ClientMu.RUnlock()
	if client == nil {
		return -1, errors.New("当前没有正在工作的节点连接")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	conn, err := client.CreateProxy(ctx, metadata.ParseSocksaddr("www.gstatic.com:80"))
	if err != nil {
		return -1, err
	}
	_ = conn.Close()
	return time.Since(start).Milliseconds(), nil
}

func runBandwidthSample(client *http.Client, targetURL string, timeout time.Duration) (bandwidthSample, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	req.Header.Set("User-Agent", "wing-speedtest/1.0")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return bandwidthSample{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return bandwidthSample{}, fmt.Errorf("测速服务器返回 HTTP %d", resp.StatusCode)
	}

	var written atomic.Int64
	buf := make([]byte, 256*1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				written.Add(int64(n))
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
		resp.Body.Close()
		<-done
	}

	duration := time.Since(start).Seconds()
	if duration <= 0 {
		duration = 1
	}

	totalWritten := written.Load()
	if totalWritten == 0 {
		if ctx.Err() != nil {
			return bandwidthSample{}, ctx.Err()
		}
		return bandwidthSample{}, fmt.Errorf("未下载到任何数据")
	}
	return bandwidthSample{bytes: totalWritten, duration: duration}, nil
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

	newNodes, err := sub.ParseSubscription(input)
	if err != nil || len(newNodes) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": fmt.Sprintf("解析节点失败: %v", err)})
		return
	}

	targetFile := sub.CurrentConfigFile
	if targetFile == "" {
		targetFile = "config.yml"
	}

	// 检查该节点是否已经存在？（按需，这里直接追加）
	common.AllNodes = append(common.AllNodes, newNodes...)
	err = sub.SaveNodesToYAML(targetFile, common.AllNodes)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "保存节点数据失败"})
		return
	}

	sub.SetActiveConfigFile(targetFile)
	sub.RefreshNodeMenu(newNodes)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": fmt.Sprintf("成功添加 %d 个节点", len(newNodes))})
}

func testAllHandler(w http.ResponseWriter, r *http.Request) {
	globalNodesMu.Lock()
	nodesToTest := make([]GlobalNodeInfo, len(globalNodesCache))
	copy(nodesToTest, globalNodesCache)
	globalNodesMu.Unlock()

	// Pre-parse each unique subscription/aggregate group file exactly once
	parsedFiles := make(map[string][]protocol.Node)
	for _, gNode := range nodesToTest {
		if _, exists := parsedFiles[gNode.FileName]; !exists {
			nodes, err := protocol.ParseNodes(gNode.FileName)
			if err == nil {
				parsedFiles[gNode.FileName] = nodes
			}
		}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, gNode := range nodesToTest {
		wg.Add(1)
		go func(gGlobalIdx int, fileName string, subIdx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			nodes := parsedFiles[fileName]
			if subIdx >= 0 && subIdx < len(nodes) {
				lat, err := proxy.FastTCPPing(nodes[subIdx])
				if err != nil {
					lat = -1
				}
				latencyCache.Store(gGlobalIdx, lat)
			}
		}(gNode.Index, gNode.FileName, gNode.SubIndex)
	}
	wg.Wait()
	w.WriteHeader(http.StatusOK)
}

func getStatusHandler(w http.ResponseWriter, r *http.Request) {
	EnsureStartupState()

	tunState := common.IsTunModeOn
	if tunPending.Load() {
		tunState = tunPendingState.Load()
	}
	speedIn, speedOut := stats.GetCurrentSpeeds()
	status := map[string]interface{}{
		"proxy":       common.IsSystemProxyOn,
		"mode":        common.ProxyMode,
		"tun":         tunState,
		"tunnel":      tunState,
		"webrtc":      common.IsWebRTCPolicyOn,
		"speedIn":     speedIn,
		"speedOut":    speedOut,
		"freeTraffic": freeflow.Snapshot(freeflow.IsNodeName(common.ActiveNodeName)),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func freeTrafficHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"traffic": freeflow.Snapshot(freeflow.IsNodeName(common.ActiveNodeName)),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := freeflow.Snapshot(false)
	if state.Remaining <= 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "本周免费流量已用完，下周自动恢复。", "traffic": state})
		return
	}

	node, err := freeflow.Node()
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "免费流量暂时不可用。"})
		return
	}
	proxy.SwitchNode(node)
	if !common.IsSystemProxyOn {
		if err := proxy.SetSystemProxyEnabled(true); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "免费流量已切换，但开启系统代理失败: " + err.Error()})
			return
		}
	}
	if common.MCurrentNode != nil {
		common.MCurrentNode.SetTitle("📍 当前节点: [免费流量]")
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"msg":     "免费流量已启用。",
		"traffic": freeflow.Snapshot(true),
	})
}

func autoSelectConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		data, err := secure.SecureReadFile(AutoSelectConfigFile)
		if err != nil || len(strings.TrimSpace(string(data))) == 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "config": nil})
			return
		}
		var raw json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil || !json.Valid(raw) {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "config": nil})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "config": raw})
	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 128*1024))
		if err != nil || len(body) == 0 || !json.Valid(body) {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "自动选择配置格式错误"})
			return
		}
		var obj map[string]interface{}
		if err := json.Unmarshal(body, &obj); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "自动选择配置必须是 JSON 对象"})
			return
		}
		pretty, err := json.MarshalIndent(obj, "", "  ")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "自动选择配置序列化失败"})
			return
		}
		if err := secure.SecureWriteFile(AutoSelectConfigFile, pretty); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "自动选择配置保存失败"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func siteTargetsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(readSiteTestTargets())
	case http.MethodPost:
		var target SiteTestTarget
		if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "请求格式错误"})
			return
		}
		target.Name = strings.TrimSpace(target.Name)
		target.Category = strings.TrimSpace(target.Category)
		target.URL = strings.TrimSpace(target.URL)
		if target.Name == "" || target.URL == "" {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "请输入名称和网址"})
			return
		}
		if target.Category == "" {
			target.Category = "自定义"
		}
		parsed, err := url.Parse(target.URL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "请输入 http 或 https 开头的网址"})
			return
		}
		target.ID = fmt.Sprintf("custom_%d", time.Now().UnixNano())
		target.Preset = false
		custom := readCustomSiteTestTargets()
		custom = append(custom, target)
		if err := saveCustomSiteTestTargets(custom); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "保存测试网站失败"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "target": target})
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if isPresetSiteTarget(id) {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "预设测试网站不能删除"})
			return
		}
		custom := readCustomSiteTestTargets()
		next := custom[:0]
		found := false
		for _, target := range custom {
			if target.ID == id {
				found = true
				continue
			}
			next = append(next, target)
		}
		if !found {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "测试网站不存在"})
			return
		}
		if err := saveCustomSiteTestTargets(next); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "删除测试网站失败"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func siteTestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	common.ClientMu.RLock()
	activeNode := common.ActiveNode
	activeName := common.ActiveNodeName
	common.ClientMu.RUnlock()
	if strings.TrimSpace(activeName) == "" || strings.TrimSpace(activeNode.Type) == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "请先选择一个节点"})
		return
	}

	targets := readSiteTestTargets()
	targetID := strings.TrimSpace(r.URL.Query().Get("id"))
	if targetID != "" {
		filtered := targets[:0]
		for _, target := range targets {
			if target.ID == targetID {
				filtered = append(filtered, target)
				break
			}
		}
		if len(filtered) == 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "测试网站不存在"})
			return
		}
		targets = filtered
	}
	client, cleanup, err := proxy.CreateTempHTTPClient(activeNode)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "当前节点初始化失败: " + err.Error()})
		return
	}
	defer cleanup()
	client.Timeout = siteTestTimeout

	proxyReady, proxyMsg := verifySiteTestProxy(client)
	if !proxyReady {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":         false,
			"node":       activeName,
			"proxyReady": false,
			"msg":        proxyMsg,
		})
		return
	}

	results := runSiteTests(client, targets)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":         true,
		"node":       activeName,
		"proxyReady": true,
		"results":    results,
	})
}

func verifySiteTestProxy(client *http.Client) (bool, string) {
	probes := []string{
		"https://www.gstatic.com/generate_204",
		"https://cp.cloudflare.com/generate_204",
		"https://www.apple.com/library/test/success.html",
	}
	var lastErr string
	for _, probeURL := range probes {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "wing-sitecheck/1.0")
		start := time.Now()
		resp, err := client.Do(req)
		latency := time.Since(start).Milliseconds()
		cancel()
		if err != nil {
			lastErr = friendlySiteTestError(err)
			continue
		}
		_, _ = io.CopyN(io.Discard, resp.Body, 512)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			return true, fmt.Sprintf("代理链已生效，基础探测 %dms", latency)
		}
		lastErr = fmt.Sprintf("基础探测返回 HTTP %d", resp.StatusCode)
	}
	if lastErr == "" {
		lastErr = "基础连通性探测失败"
	}
	return false, "当前选择的节点代理未生效或不可用：" + lastErr
}

func readSiteTestTargets() []SiteTestTarget {
	targets := make([]SiteTestTarget, 0, len(presetSiteTargets))
	targets = append(targets, presetSiteTargets...)
	targets = append(targets, readCustomSiteTestTargets()...)
	return targets
}

func readCustomSiteTestTargets() []SiteTestTarget {
	data, err := storage.ReadOrMigrateFile(SiteTestTargetsFile)
	if err != nil || len(data) == 0 {
		return nil
	}
	var targets []SiteTestTarget
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil
	}
	out := make([]SiteTestTarget, 0, len(targets))
	for _, target := range targets {
		if target.ID == "" || target.URL == "" || target.Name == "" || target.Preset {
			continue
		}
		if target.Category == "" {
			target.Category = "自定义"
		}
		out = append(out, target)
	}
	return out
}

func saveCustomSiteTestTargets(targets []SiteTestTarget) error {
	for i := range targets {
		targets[i].Preset = false
	}
	data, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return err
	}
	return storage.Write(SiteTestTargetsFile, data)
}

func isPresetSiteTarget(id string) bool {
	for _, target := range presetSiteTargets {
		if target.ID == id {
			return true
		}
	}
	return false
}

func runSiteTests(client *http.Client, targets []SiteTestTarget) []SiteTestResult {
	results := make([]SiteTestResult, len(targets))
	for i, target := range targets {
		results[i] = testSiteTarget(client, target)
	}
	return results
}

func testSiteTarget(client *http.Client, target SiteTestTarget) SiteTestResult {
	result := SiteTestResult{
		ID:       target.ID,
		Name:     target.Name,
		Category: target.Category,
		URL:      target.URL,
	}
	ctx, cancel := context.WithTimeout(context.Background(), siteTestTimeout)
	defer cancel()

	probe := siteProbe{URL: target.URL}
	if isGeminiTarget(target) {
		probe.FallbackURL = "https://gemini.google.com/_/BardChatUi/"
	}
	result = runSiteProbe(ctx, client, target, result, probe)
	return result
}

type siteProbe struct {
	URL         string
	FallbackURL string
}

func runSiteProbe(ctx context.Context, client *http.Client, target SiteTestTarget, result SiteTestResult, probe siteProbe) SiteTestResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.URL, nil)
	if err != nil {
		result.Message = "网址无效"
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	start := time.Now()
	resp, err := client.Do(req)
	result.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Message = friendlySiteTestError(err)
		return result
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	result.StatusCode = resp.StatusCode
	result.OK, result.Message = evaluateSiteAccess(target, resp.StatusCode, string(body))
	if shouldRetryGeminiProbe(target, result, string(body), probe.FallbackURL) {
		fallbackResult := result
		fallbackResult.URL = probe.FallbackURL
		fallbackResult.StatusCode = 0
		fallbackResult.LatencyMS = 0
		fallbackResult.OK = false
		fallbackResult.Message = ""
		return runSiteProbe(ctx, client, target, fallbackResult, siteProbe{URL: probe.FallbackURL})
	}
	return result
}

func shouldRetryGeminiProbe(target SiteTestTarget, result SiteTestResult, body string, fallbackURL string) bool {
	return isGeminiTarget(target) &&
		fallbackURL != "" &&
		!hasRegionUnsupportedSignal(target, body) &&
		(!result.OK || result.StatusCode >= 400)
}

func evaluateSiteAccess(target SiteTestTarget, status int, body string) (bool, string) {
	if hasRegionUnsupportedSignal(target, body) {
		return false, "地区不支持"
	}
	if status == http.StatusUnavailableForLegalReasons {
		return false, "地区或合规限制"
	}
	if isAIProbeTarget(target) && status < 500 {
		if status >= 400 {
			return true, "可访问，探测遇到登录或风控页"
		}
		return true, siteStatusMessage(status)
	}
	return status >= 200 && status < 400, siteStatusMessage(status)
}

func isAIProbeTarget(target SiteTestTarget) bool {
	category := strings.ToLower(strings.TrimSpace(target.Category))
	id := strings.ToLower(strings.TrimSpace(target.ID))
	host := ""
	if parsed, err := url.Parse(target.URL); err == nil {
		host = strings.ToLower(parsed.Host)
	}
	return category == "ai" ||
		strings.Contains(id, "chatgpt") ||
		strings.Contains(id, "gemini") ||
		strings.Contains(id, "claude") ||
		strings.Contains(host, "chatgpt.com") ||
		strings.Contains(host, "gemini.google.com") ||
		strings.Contains(host, "claude.ai")
}

func isGeminiTarget(target SiteTestTarget) bool {
	id := strings.ToLower(strings.TrimSpace(target.ID))
	host := ""
	if parsed, err := url.Parse(target.URL); err == nil {
		host = strings.ToLower(parsed.Host)
	}
	return strings.Contains(id, "gemini") || strings.Contains(host, "gemini.google.com")
}

func hasRegionUnsupportedSignal(target SiteTestTarget, body string) bool {
	text := strings.ToLower(body)
	host := ""
	if parsed, err := url.Parse(target.URL); err == nil {
		host = strings.ToLower(parsed.Host)
	}
	commonPatterns := []string{
		"not available in your country",
		"not available in your region",
		"not currently supported in your country",
		"not currently supported in your region",
		"not supported in your country",
		"not supported in your region",
		"your country is not supported",
		"unsupported_country",
		"unsupported country",
		"地区不支持",
		"不支持你所在的地区",
		"不支持您所在的地区",
		"暂不支持你所在",
		"暂不支持您所在",
		"所在的地区。敬请期待",
	}
	for _, pattern := range commonPatterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	if strings.Contains(host, "gemini.google.com") {
		geminiPatterns := []string{
			"gemini isn’t currently supported",
			"gemini isn't currently supported",
			"gemini is not currently supported",
			"gemini目前不支持",
			"gemini 目前不支持",
		}
		for _, pattern := range geminiPatterns {
			if strings.Contains(text, pattern) {
				return true
			}
		}
	}
	if strings.Contains(host, "chatgpt.com") {
		openAIPatterns := []string{
			"openai's services are not available",
			"openai services are not available",
			"chatgpt is not available",
			"chatgpt isn't available",
		}
		for _, pattern := range openAIPatterns {
			if strings.Contains(text, pattern) {
				return true
			}
		}
	}
	return false
}

func siteStatusMessage(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "可访问"
	case status >= 300 && status < 400:
		return "可访问，发生跳转"
	case status == http.StatusForbidden:
		return "访问受限"
	case status == http.StatusTooManyRequests:
		return "请求被限流"
	case status == http.StatusUnavailableForLegalReasons:
		return "地区或合规限制"
	case status >= 500:
		return "目标站点或线路异常"
	default:
		return fmt.Sprintf("HTTP %d", status)
	}
}

func friendlySiteTestError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "连接超时"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host"):
		return "DNS 解析失败"
	case strings.Contains(msg, "handshake"):
		return "TLS 握手失败"
	case strings.Contains(msg, "connection refused"):
		return "连接被拒绝"
	case strings.Contains(msg, "connection reset"):
		return "连接被重置"
	default:
		return "无法访问"
	}
}

func actionHandler(w http.ResponseWriter, r *http.Request) {
	actionType := r.URL.Query().Get("type")
	w.Header().Set("Content-Type", "application/json")
	switch actionType {
	case "proxy":
		target := requestedBool(r, !common.IsSystemProxyOn)
		if err := proxy.SetSystemProxyEnabled(target); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "系统代理切换失败: " + err.Error(), "proxy": common.IsSystemProxyOn})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "proxy": common.IsSystemProxyOn})
		return
	case "mode":
		targetGlobal := requestedBool(r, common.ProxyMode != "Global")
		proxy.SetProxyModeGlobal(targetGlobal)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "mode": common.ProxyMode})
		return
	case "tun", "tunnel":
		tunTarget := requestedBool(r, !common.IsTunModeOn)
		if tunPending.Load() {
			if tunPendingState.Load() == tunTarget {
				json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "pending": true, "tun": tunTarget})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "TUN 正在切换中，请稍候。"})
			return
		}
		if common.IsTunModeOn == tunTarget {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "tun": common.IsTunModeOn})
			return
		}
		if tunTarget && !utils.IsAdmin() {
			if proxy.GlobalSystemConfig.AutoRestartAsAdmin {
				if err := utils.RestartAsAdmin(); err != nil {
					json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "requiresAdmin": true, "msg": "自动请求管理员权限失败: " + err.Error()})
					return
				}
				scheduleExitAfterAdminRestart("auto admin restart")
				json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "restarting": true, "msg": "正在请求管理员权限并重启 wing..."})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "requiresAdmin": true, "msg": "开启隧道连接需要管理员权限！可在系统设置里开启“需要管理员权限时自动重启”。"})
			return
		}
		// 标记 TUN 正在切换中，防止轮询期间把 checkbox 闪回旧状态
		if !tunPending.CompareAndSwap(false, true) {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "TUN 正在切换中，请稍候。"})
			return
		}
		tunPendingState.Store(tunTarget)
		utils.SafeGo("webui tun toggle", func() {
			defer tunPending.Store(false)
			msg := proxy.SetTunMode(tunTarget)
			if msg != "" {
				// 失败时不需要额外处理，proxy.SetTunMode 内部不会修改 common.IsTunModeOn
				return
			}
			stats.SyncTrafficSession(common.IsSystemProxyOn, common.IsTunModeOn)
		})
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
		return
	case "webrtc":
		common.IsWebRTCPolicyOn = requestedBool(r, !common.IsWebRTCPolicyOn)
		routing.ToggleWebRTCLeak(common.IsWebRTCPolicyOn)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":  true,
			"msg": "防 WebRTC 泄露策略已触发！\n\n注意：此功能通过修改 Windows 系统策略(Registry)实现，已向您请求管理员权限。\n如果策略未生效，请前往「chrome://policy」重新加载策略，或重启浏览器。",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func requestedBool(r *http.Request, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("enable")))
	switch raw {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return fallback
	}
}

func restartHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	wasAdmin := utils.IsAdmin()
	if err := utils.RestartApp(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "重启失败: " + err.Error()})
		return
	}
	scheduleExitAfterRestart("manual app restart")
	msg := "正在重启 wing..."
	if wasAdmin {
		msg = "正在以当前管理员权限重启 wing..."
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "restarting": true, "admin": wasAdmin, "msg": msg})
}

func restartAdminHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if utils.IsAdmin() {
		if err := utils.RestartApp(); err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "重启失败: " + err.Error()})
			return
		}
		scheduleExitAfterRestart("admin app restart")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "restarting": true, "msg": "正在以当前管理员权限重启 wing..."})
		return
	}
	if err := utils.RestartAsAdmin(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "请求管理员权限失败: " + err.Error()})
		return
	}
	scheduleExitAfterAdminRestart("manual admin restart")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "restarting": true, "msg": "正在请求管理员权限并重启 wing..."})
}

func scheduleExitAfterAdminRestart(name string) {
	scheduleExitAfterRestart(name)
}

func scheduleExitAfterRestart(name string) {
	utils.SafeGo(name, func() {
		time.Sleep(500 * time.Millisecond)
		systray.Quit()
	})
}

func getSuppliersHandler(w http.ResponseWriter, r *http.Request) {
	EnsureStartupState()

	links, _ := sub.ReadSubscriptions()
	type SupplierInfo struct {
		Name                  string                   `json:"name"`
		FileName              string                   `json:"fileName"`
		URL                   string                   `json:"url"`
		Active                bool                     `json:"active"`
		Traffic               *sub.SubscriptionTraffic `json:"traffic,omitempty"`
		UpdateIntervalMinutes int64                    `json:"updateIntervalMinutes"`
		LastUpdatedAt         int64                    `json:"lastUpdatedAt,omitempty"`
	}
	var list []SupplierInfo
	for _, l := range links {
		list = append(list, SupplierInfo{
			Name:                  l.Name,
			FileName:              l.FileName,
			URL:                   l.URL,
			Active:                l.FileName == sub.CurrentConfigFile,
			Traffic:               l.Traffic,
			UpdateIntervalMinutes: l.UpdateIntervalMinutes,
			LastUpdatedAt:         l.LastUpdatedAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func switchSupplierHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	nodes, err := protocol.ParseNodes(fileName)
	if err == nil && len(nodes) > 0 {
		sub.SetActiveConfigFile(fileName)
		common.AllNodes = nodes
		resetNodeMetricCaches()
		sub.RefreshNodeMenu(nil)
		if len(common.AllNodes) > 0 {
			proxy.SwitchNode(common.AllNodes[0])
		}
	}
	w.WriteHeader(http.StatusOK)
}

func updateSupplierHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	links, _ := sub.ReadSubscriptions()

	var target *sub.SubInfo
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

	nodes, traffic, err := sub.ParseSubscriptionWithInfo(target.URL)
	if err != nil || len(nodes) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": fmt.Sprintf("无法从该链接获取有效节点: %v", err)})
		return
	}

	oldNodes, _ := protocol.ParseNodes(target.FileName)
	err = sub.SaveNodesToYAML(target.FileName, nodes)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "保存节点数据失败"})
		return
	}
	sub.NotifySubscriptionNodesUpdated(target.FileName, oldNodes, nodes)

	if sub.CurrentConfigFile == target.FileName {
		common.AllNodes = nodes
		resetNodeMetricCaches()
		sub.RefreshNodeMenu(nil)
		runtime.GC()
		debug.FreeOSMemory()
	}
	_ = sub.MarkSubscriptionUpdated(target.URL, traffic)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": fmt.Sprintf("成功更新 %d 个节点", len(nodes)), "traffic": traffic})
}

func setSupplierUpdateIntervalHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fileName := r.URL.Query().Get("file")
	minutes, err := strconv.ParseInt(r.URL.Query().Get("minutes"), 10, 64)
	if err != nil || minutes <= 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "请输入有效的分钟数"})
		return
	}
	if err := sub.SetSubscriptionUpdateInterval(fileName, minutes); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "自动更新间隔已保存"})
}

func deleteSupplierHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	links, _ := sub.ReadSubscriptions()

	found := false
	for _, l := range links {
		if l.FileName == fileName {
			sub.DeleteSubscription(l.URL)
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "Supplier not found", http.StatusNotFound)
		return
	}

	if sub.CurrentConfigFile == fileName {
		common.AllNodes = nil
		sub.SetActiveConfigFile("")
		resetNodeMetricCaches()
		sub.RefreshNodeMenu(nil)
	}

	sub.RefreshSupplierMenu()
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
	out, err := utils.RunHiddenCommand("powershell", "-NoProfile", "-Command", "Get-Clipboard")
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
	newNodes, traffic, err := sub.ParseSubscriptionWithInfo(input)
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
			fName, existed, saveErr := sub.AppendSubscriptionWithTraffic(line, traffic)
			if saveErr != nil {
				fmt.Printf("⚠️ 警告: 无法将链接保存到 JSON: %v\n", saveErr)
			} else if fName != "" {
				targetFile = fName
				isOldLink = existed
			}
		}
	}

	oldNodes, _ := protocol.ParseNodes(targetFile)
	common.AllNodes = newNodes
	if err := sub.SaveNodesToYAML(targetFile, common.AllNodes); err != nil {
		respond(false, "写入 .yml 文件失败: "+err.Error())
		return
	}
	sub.NotifySubscriptionNodesUpdated(targetFile, oldNodes, common.AllNodes)

	sub.SetActiveConfigFile(targetFile)
	refreshedNodes, err := protocol.ParseNodes(targetFile)
	if err == nil {
		common.AllNodes = refreshedNodes
	}

	resetNodeMetricCaches()
	sub.RefreshSupplierMenu()
	if isOldLink {
		sub.RefreshNodeMenu(nil)
		respond(true, fmt.Sprintf("🎉 成功更新/覆盖了已存在的订阅！共 %d 个节点。", len(newNodes)))
	} else {
		sub.RefreshNodeMenu(newNodes)
		respond(true, fmt.Sprintf("🎉 成功解析并导入 %d 个新节点！原始链接已保存。", len(newNodes)))
	}
}

func aggGroupNodesHandler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	group, ok := aggregateGroupByFile(fileName)
	if !ok {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}
	fileName = group.FileName
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
	group, ok := aggregateGroupByFile(req.File)
	if !ok {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}
	fileName := group.FileName
	existing, _ := protocol.ParseNodes(fileName)
	existing = append(existing, normalizeAggregateSources(req.Nodes)...)
	if err := sub.SaveNodesToYAML(fileName, existing); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": err.Error()})
		return
	}
	if sub.CurrentConfigFile == fileName {
		common.AllNodes = existing
		resetNodeMetricCaches()
		sub.RefreshNodeMenu(nil)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "count": len(existing)})
}

func dnsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxy.GlobalDNSConfig)
		return
	}
	if r.Method == http.MethodPost {
		var config proxy.DNSConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		proxy.GlobalDNSConfig = config
		if err := proxy.SaveDNSConfig(); err != nil {
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
	group, ok := aggregateGroupByFile(fileName)
	if !ok {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}
	fileName = group.FileName
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
	if err := sub.SaveNodesToYAML(fileName, nodes); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false})
		return
	}
	if sub.CurrentConfigFile == fileName {
		common.AllNodes = nodes
		resetNodeMetricCaches()
		sub.RefreshNodeMenu(nil)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

var startTime = time.Now()

func getStatsHandler(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	speedIn, speedOut := stats.GetCurrentSpeeds()

	stats := map[string]interface{}{
		"memAlloc":         m.Alloc,
		"memSys":           m.Sys,
		"heapInuse":        m.HeapInuse,
		"heapReleased":     m.HeapReleased,
		"goroutines":       runtime.NumGoroutine(),
		"speedIn":          speedIn,
		"speedOut":         speedOut,
		"activeNodes":      1,
		"uptime":           time.Since(startTime).Seconds(),
		"connections":      atomic.LoadInt32(&stats.ActiveConnections),
		"activeSpeedtests": atomic.LoadInt32(&common.ActiveSpeedtests),
		"activeDNSQueries": atomic.LoadInt32(&common.ActiveDNSQueries),
		"logs":             stats.GetRecentConnLogs(200),
		"totalIn":          atomic.LoadUint64(&common.GlobalProxyIn),
		"totalOut":         atomic.LoadUint64(&common.GlobalProxyOut),
		"trafficSessions":  stats.GetTrafficSessions(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func clearLogsHandler(w http.ResponseWriter, r *http.Request) {
	stats.ClearConnLogs()
	w.WriteHeader(http.StatusOK)
}

func privacyToggleHandler(w http.ResponseWriter, r *http.Request) {
	common.PrivacyMode = !common.PrivacyMode
	if common.PrivacyMode {
		stats.ClearConnLogs()
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"enabled": common.PrivacyMode})
}

func appUpdateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	info := cachedAppUpdateInfo()
	json.NewEncoder(w).Encode(info)
}

func cachedAppUpdateInfo() appUpdateInfo {
	appUpdateMu.Lock()
	defer appUpdateMu.Unlock()

	if !appUpdateCacheTime.IsZero() && time.Since(appUpdateCacheTime) < updateCacheTTL {
		return appUpdateCache
	}

	info := fetchAppUpdateInfo()
	appUpdateCache = info
	appUpdateCacheTime = time.Now()
	return info
}

func fetchAppUpdateInfo() appUpdateInfo {
	info := appUpdateInfo{
		CurrentVersion: common.AppVersion,
		CheckedAt:      time.Now().Format(time.RFC3339),
	}

	latestURL := strings.TrimSpace(os.Getenv("WING_UPDATE_LATEST_URL"))
	if latestURL == "" {
		latestURL = defaultUpdateLatestURL
	}

	req, err := http.NewRequest(http.MethodGet, latestURL, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wing/"+common.AppVersion)

	client := &http.Client{Timeout: 8 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		info.Error = fmt.Sprintf("GitHub releases returned %s", res.Status)
		return info
	}

	var release githubReleaseInfo
	if err := json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&release); err != nil {
		info.Error = err.Error()
		return info
	}

	latestVersion := normalizeVersionLabel(release.TagName)
	if latestVersion == "" {
		latestVersion = normalizeVersionLabel(release.Name)
	}
	if latestVersion == "" {
		info.Error = "latest release has no version tag"
		return info
	}

	info.OK = true
	info.LatestVersion = latestVersion
	info.Name = release.Name
	info.PageURL = release.HTMLURL
	info.DownloadURL = selectUpdateDownloadURL(release)
	if overrideURL := strings.TrimSpace(os.Getenv("WING_UPDATE_DOWNLOAD_URL")); overrideURL != "" {
		info.DownloadURL = overrideURL
	}
	info.Available = compareVersionLabel(latestVersion, common.AppVersion) > 0
	if !info.Available {
		info.Message = "当前已是最新版本"
	}
	return info
}

func appUpdateOpenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL string `json:"url"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req)
	target := strings.TrimSpace(req.URL)
	if target == "" {
		info := cachedAppUpdateInfo()
		target = firstNonEmptyString(info.DownloadURL, info.PageURL)
	}
	if !isAllowedUpdateURL(target) {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "更新下载链接无效"})
		return
	}
	if err := openExternalUpdateURL(target); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "打开更新下载页失败: " + err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func selectUpdateDownloadURL(release githubReleaseInfo) string {
	if len(release.Assets) == 0 {
		return release.HTMLURL
	}

	osName := runtime.GOOS
	archName := runtime.GOARCH
	bestScore := -1
	bestURL := ""
	for _, asset := range release.Assets {
		name := strings.ToLower(asset.Name)
		if asset.BrowserDownloadURL == "" {
			continue
		}
		score := 0
		if strings.Contains(name, osName) {
			score += 20
		}
		if osName == "windows" && strings.Contains(name, "win") {
			score += 14
		}
		if archMatchesAssetName(archName, name) {
			score += 10
		}
		if strings.Contains(name, "setup") || strings.Contains(name, "installer") || strings.HasSuffix(name, ".exe") || strings.HasSuffix(name, ".msi") {
			score += 4
		}
		if strings.HasSuffix(name, ".zip") || strings.HasSuffix(name, ".pkg") || strings.HasSuffix(name, ".run") || strings.HasSuffix(name, ".apk") || strings.HasSuffix(name, ".ipa") {
			score += 2
		}
		if score > bestScore {
			bestScore = score
			bestURL = asset.BrowserDownloadURL
		}
	}
	if bestURL != "" {
		return bestURL
	}
	return release.HTMLURL
}

func archMatchesAssetName(arch, name string) bool {
	switch arch {
	case "amd64":
		return strings.Contains(name, "x64") || strings.Contains(name, "amd64")
	case "arm64":
		return strings.Contains(name, "arm64") || strings.Contains(name, "aarch64")
	default:
		return strings.Contains(name, arch)
	}
}

func normalizeVersionLabel(value string) string {
	value = strings.TrimSpace(strings.TrimLeft(value, "vV"))
	if value == "" {
		return ""
	}
	parts := versionNumberParts(value)
	if len(parts) == 0 {
		return ""
	}
	labels := make([]string, 0, len(parts))
	for _, part := range parts {
		labels = append(labels, strconv.Itoa(part))
	}
	return strings.Join(labels, ".")
}

func compareVersionLabel(a, b string) int {
	left := versionNumberParts(a)
	right := versionNumberParts(b)
	maxLen := len(left)
	if len(right) > maxLen {
		maxLen = len(right)
	}
	for i := 0; i < maxLen; i++ {
		var lv, rv int
		if i < len(left) {
			lv = left[i]
		}
		if i < len(right) {
			rv = right[i]
		}
		if lv > rv {
			return 1
		}
		if lv < rv {
			return -1
		}
	}
	return 0
}

func versionNumberParts(value string) []int {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r < '0' || r > '9'
	})
	parts := make([]int, 0, len(fields))
	for _, field := range fields {
		if field == "" {
			continue
		}
		part, err := strconv.Atoi(field)
		if err != nil {
			continue
		}
		parts = append(parts, part)
		if len(parts) >= 4 {
			break
		}
	}
	return parts
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func isAllowedUpdateURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "github.com" ||
		host == "objects.githubusercontent.com" ||
		host == "github-releases.githubusercontent.com"
}

func openExternalUpdateURL(target string) error {
	switch runtime.GOOS {
	case "windows":
		_, err := utils.RunHiddenCommand("rundll32", "url.dll,FileProtocolHandler", target)
		return err
	case "darwin":
		_, err := utils.RunHiddenCommand("open", target)
		return err
	default:
		_, err := utils.RunHiddenCommand("xdg-open", target)
		return err
	}
}

func historyHandler(w http.ResponseWriter, r *http.Request) {
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	var startVal, endVal time.Time

	if startStr != "" {
		if val, err := strconv.ParseInt(startStr, 10, 64); err == nil {
			if val > 9999999999 {
				startVal = time.UnixMilli(val)
			} else {
				startVal = time.Unix(val, 0)
			}
		} else if parsed, err := time.Parse(time.RFC3339, startStr); err == nil {
			startVal = parsed
		}
	}
	if startVal.IsZero() {
		startVal = time.Now().Add(-24 * time.Hour)
	}

	if endStr != "" {
		if val, err := strconv.ParseInt(endStr, 10, 64); err == nil {
			if val > 9999999999 {
				endVal = time.UnixMilli(val)
			} else {
				endVal = time.Unix(val, 0)
			}
		} else if parsed, err := time.Parse(time.RFC3339, endStr); err == nil {
			endVal = parsed
		}
	}
	if endVal.IsZero() {
		endVal = time.Now()
	}

	res := stats.GetHistory(startVal, endVal)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
