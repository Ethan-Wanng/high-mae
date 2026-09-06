//go:build android

package systray

// Android uses Flutter and VpnService instead of a desktop notification-area
// menu. These no-op hooks keep shared proxy state portable without linking the
// GTK/AppIndicator C implementation into the Android executable.

func registerSystray() {
	if systrayReady != nil {
		systrayReady()
	}
}

func nativeLoop() {}

func quit() {
	if systrayExit != nil {
		systrayExit()
	}
}

func SetIcon([]byte) {}

func SetTemplateIcon([]byte, []byte) {}

func SetTitle(string) {}

func SetTooltip(string) {}

func addOrUpdateMenuItem(*MenuItem) {}

func addSeparator(uint32) {}

func hideMenuItem(*MenuItem) {}

func showMenuItem(*MenuItem) {}

func (*MenuItem) SetIcon([]byte) {}

func (*MenuItem) SetTemplateIcon([]byte, []byte) {}
