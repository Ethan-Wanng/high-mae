package proxy

import (
	"encoding/json"
	"wing/pkg/common"
	"wing/pkg/storage"
)

type SystemConfig struct {
	ProxyPort             string `json:"proxyPort"`
	PreventBingCNRedirect bool   `json:"preventBingCNRedirect"`
	PreferIPv6            bool   `json:"preferIPv6"`
	AutoRestartAsAdmin    bool   `json:"autoRestartAsAdmin"`
	StartupEnabled        bool   `json:"startupEnabled"`
	ThemeMode             string `json:"themeMode"`
}

var GlobalSystemConfig SystemConfig

const SystemConfigFile = "system_config.json"

func LoadSystemConfig() {
	data, err := storage.ReadOrMigrateFile(SystemConfigFile)
	if err == nil {
		_ = json.Unmarshal(data, &GlobalSystemConfig)
	}
	if GlobalSystemConfig.ProxyPort == "" {
		GlobalSystemConfig.ProxyPort = "10808"
	}
	if GlobalSystemConfig.ThemeMode == "" {
		GlobalSystemConfig.ThemeMode = "system"
	}
	common.LocalHttpPort = GlobalSystemConfig.ProxyPort
	common.PreventBingCNRedirect = GlobalSystemConfig.PreventBingCNRedirect
}

func SaveSystemConfig() error {
	GlobalSystemConfig.ProxyPort = common.LocalHttpPort
	GlobalSystemConfig.PreventBingCNRedirect = common.PreventBingCNRedirect
	data, err := json.MarshalIndent(GlobalSystemConfig, "", "  ")
	if err != nil {
		return err
	}
	return storage.Write(SystemConfigFile, data)
}
