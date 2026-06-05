package webui

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"wing/pkg/common"
	"wing/pkg/proxy"
	"wing/pkg/utils"
)

func systemConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		proxy.GlobalSystemConfig.StartupEnabled = utils.IsStartupEnabled()
		if proxy.GlobalSystemConfig.ThemeMode == "" {
			proxy.GlobalSystemConfig.ThemeMode = "system"
		}
		json.NewEncoder(w).Encode(proxy.GlobalSystemConfig)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			ProxyPort             string `json:"proxyPort"`
			PreventBingCNRedirect *bool  `json:"preventBingCNRedirect"`
			PreferIPv6            *bool  `json:"preferIPv6"`
			AutoRestartAsAdmin    *bool  `json:"autoRestartAsAdmin"`
			StartupEnabled        *bool  `json:"startupEnabled"`
			ThemeMode             string `json:"themeMode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		portStr := strings.TrimSpace(req.ProxyPort)
		if portStr == "" {
			portStr = common.LocalHttpPort
		}
		if portStr == "" {
			portStr = proxy.GlobalSystemConfig.ProxyPort
		}
		if portStr == "" {
			portStr = "10808"
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			http.Error(w, "Invalid port number", http.StatusBadRequest)
			return
		}

		// Save old port to check if it actually changed
		oldPort := common.LocalHttpPort

		// Update global config
		proxy.GlobalSystemConfig.ProxyPort = portStr
		common.LocalHttpPort = portStr
		if req.PreventBingCNRedirect != nil {
			proxy.GlobalSystemConfig.PreventBingCNRedirect = *req.PreventBingCNRedirect
			common.PreventBingCNRedirect = *req.PreventBingCNRedirect
		}
		if req.PreferIPv6 != nil {
			proxy.GlobalSystemConfig.PreferIPv6 = *req.PreferIPv6
		}
		if req.AutoRestartAsAdmin != nil {
			proxy.GlobalSystemConfig.AutoRestartAsAdmin = *req.AutoRestartAsAdmin
		}
		if req.StartupEnabled != nil {
			if err := utils.SetStartupEnabled(*req.StartupEnabled); err != nil {
				json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "开机自启动设置失败: " + err.Error()})
				return
			}
			proxy.GlobalSystemConfig.StartupEnabled = *req.StartupEnabled
		}
		themeMode := strings.TrimSpace(req.ThemeMode)
		if themeMode != "" {
			if themeMode != "light" && themeMode != "dark" && themeMode != "system" {
				http.Error(w, "Invalid theme mode", http.StatusBadRequest)
				return
			}
			proxy.GlobalSystemConfig.ThemeMode = themeMode
		}
		if err := proxy.SaveSystemConfig(); err != nil {
			http.Error(w, "Save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Apply port change if changed
		if oldPort != portStr {
			if err := proxy.RestartLocalHTTPProxyServer(); err != nil {
				// We don't rollback port here to keep it simple, just report error
				json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "msg": "代理端口已保存，但重启本地 HTTP 服务失败: " + err.Error()})
				return
			}
			if common.IsSystemProxyOn {
				utils.SetSystemProxy(true)
			}
			if common.IsTunModeOn {
				proxy.RestartTun(common.GlobalNodeServer, common.GlobalNodeIP)
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "msg": "系统设置已保存生效"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
