package proxy

import (
	"wing/pkg/common"
	"wing/pkg/stats"
	"wing/pkg/utils"
)

func SetSystemProxyEnabled(enabled bool) error {
	var err error
	RunNetworkTransition(func() {
		err = setSystemProxyEnabledLocked(enabled)
	})
	return err
}

func setSystemProxyEnabledLocked(enabled bool) error {
	if common.GetSystemProxyOn() == enabled {
		if enabled {
			if err := utils.SetSystemProxy(true); err != nil {
				return err
			}
		}
		updateSystemProxyMenu()
		if common.RefreshTrayIcon != nil {
			common.RefreshTrayIcon()
		}
		return nil
	}

	if err := utils.SetSystemProxy(enabled); err != nil {
		return err
	}
	common.SetSystemProxyOn(enabled)
	proxyOn, tunOn, _ := common.GetNetworkState()
	stats.SyncTrafficSession(proxyOn, tunOn)
	_ = SaveLastNetworkMode(proxyOn, tunOn)
	updateSystemProxyMenu()
	if common.RefreshTrayIcon != nil {
		common.RefreshTrayIcon()
	}
	return nil
}

func ToggleSystemProxy() error {
	var err error
	RunNetworkTransition(func() {
		err = setSystemProxyEnabledLocked(!common.GetSystemProxyOn())
	})
	return err
}

func SetProxyModeGlobal(global bool) {
	RunNetworkTransition(func() {
		if global {
			common.SetProxyMode("Global")
		} else {
			common.SetProxyMode("Rule")
		}
		updateProxyModeMenu()
	})
}

func ToggleProxyMode() {
	RunNetworkTransition(func() {
		common.SetProxyMode(nextProxyMode(common.GetProxyMode()))
		updateProxyModeMenu()
	})
}

func ApplyRoutingRulesChanged() error {
	var err error
	RunNetworkTransition(func() {
		ClearNodeClientsCache()
		if common.GetSystemProxyOn() {
			err = utils.SetSystemProxy(true)
		}
	})
	return err
}

func nextProxyMode(mode string) string {
	if mode == "Rule" {
		return "Global"
	}
	return "Rule"
}

func updateSystemProxyMenu() {
	if common.MToggleProxy == nil {
		return
	}
	if common.GetSystemProxyOn() {
		common.MToggleProxy.SetTitle("🟢 系统代理: [已开启]")
	} else {
		common.MToggleProxy.SetTitle("⚪ 系统代理: [已关闭]")
	}
}

func updateProxyModeMenu() {
	if common.MToggleMode == nil {
		return
	}
	if common.GetProxyMode() == "Global" {
		common.MToggleMode.SetTitle("🌐 路由模式: [全局代理]")
	} else {
		common.MToggleMode.SetTitle("🔄 路由模式: [规则分流]")
	}
}
