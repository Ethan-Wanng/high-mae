//go:build android

package systray

func registerSystray() {}

func nativeLoop() {
	// block forever
	select {}
}

func quit() {}

func SetIcon(iconBytes []byte) {}
func SetTitle(title string) {}
func SetTooltip(tooltip string) {}
func addSeparator(id uint32) {}
func hideMenuItem(item *MenuItem) {}
func showMenuItem(item *MenuItem) {}
func addOrUpdateMenuItem(item *MenuItem) {}
