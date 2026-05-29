package proxy

import (
	"encoding/json"
	"wing/pkg/common"
	"wing/pkg/storage"
)

type SystemConfig struct {
	ProxyPort string `json:"proxyPort"`
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
	common.LocalHttpPort = GlobalSystemConfig.ProxyPort
}

func SaveSystemConfig() error {
	GlobalSystemConfig.ProxyPort = common.LocalHttpPort
	data, err := json.MarshalIndent(GlobalSystemConfig, "", "  ")
	if err != nil {
		return err
	}
	return storage.Write(SystemConfigFile, data)
}
