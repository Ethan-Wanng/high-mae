//go:build linux && !android && !legacy_appindicator
// +build linux,!android,!legacy_appindicator

package systray

/*
#cgo linux pkg-config: ayatana-appindicator3-0.1

#include "systray.h"
*/
import "C"
