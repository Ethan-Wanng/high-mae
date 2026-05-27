package main

import (
	"context"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var (
	globalApp  *App
	isQuitting bool
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called at application startup
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	globalApp = a
}

// domReady is called after front-end resources have been loaded
func (a *App) domReady(ctx context.Context) {
}

// beforeClose is called when the application is about to quit.
// Returning true prevents the window from closing and hides it to the system tray instead.
func (a *App) beforeClose(ctx context.Context) (prevent bool) {
	if isQuitting {
		return false
	}
	runtime.WindowHide(ctx)
	return true
}

// shutdown is called at application termination
func (a *App) shutdown(ctx context.Context) {
}

// ShowWailsWindow exposes a global function to restore the Wails window
func ShowWailsWindow() {
	if globalApp != nil && globalApp.ctx != nil {
		runtime.WindowShow(globalApp.ctx)
	}
}

// QuitWailsApp exposes a global function to securely quit the Wails process
func QuitWailsApp() {
	isQuitting = true
	if globalApp != nil && globalApp.ctx != nil {
		runtime.Quit(globalApp.ctx)
	}
}
