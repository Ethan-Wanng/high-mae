//go:build !android

package webui

import "github.com/getlantern/systray"

func quitApplication() {
	systray.Quit()
}
