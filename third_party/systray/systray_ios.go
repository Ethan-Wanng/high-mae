//go:build ios

package systray

// iOS uses Flutter and NetworkExtension; desktop tray calls are no-ops.
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
func SetIcon([]byte)                             {}
func SetTemplateIcon([]byte, []byte)             {}
func SetTitle(string)                            {}
func SetTooltip(string)                          {}
func addOrUpdateMenuItem(*MenuItem)              {}
func addSeparator(uint32)                        {}
func hideMenuItem(*MenuItem)                     {}
func showMenuItem(*MenuItem)                     {}
func (*MenuItem) SetIcon([]byte)                 {}
func (*MenuItem) SetTemplateIcon([]byte, []byte) {}
