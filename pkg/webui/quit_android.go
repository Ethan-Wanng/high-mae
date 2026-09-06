//go:build android

package webui

// Android owns the application lifecycle through Flutter and VpnService.
// Desktop-only restart endpoints must not pull the systray CGO dependency
// into the bundled mobile proxy core.
func quitApplication() {}
