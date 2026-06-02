package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
