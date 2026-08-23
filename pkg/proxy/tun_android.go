//go:build android

package proxy

func ToggleTunMode() string {
	return "Android 平台暂不支持内置 TUN 模式（需要使用 VpnService 重新实现）"
}

func SetTunMode(enabled bool) string {
	if !enabled {
		return ""
	}
	return "Android 平台暂不支持内置 TUN 模式"
}

func RestartTun(nodeServer, nodeIP string) error {
	return nil
}

func StopTun() {}

func prepareNodeBypassRouteForSwitch(nodeIP string) func() {
	return func() {}
}
