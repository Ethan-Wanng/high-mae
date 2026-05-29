package webui

import (
	"encoding/json"
	"net/http"
	"wing/pkg/common"
	"wing/pkg/proxy"
	"wing/pkg/utils"
	"strconv"
)

func systemConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxy.GlobalSystemConfig)
		return
	}

	if r.Method == http.MethodPost {
		var req proxy.SystemConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		portStr := req.ProxyPort
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
