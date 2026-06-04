package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"wing/pkg/utils"
)

const webUIURL = "http://127.0.0.1:10809/"

var (
	isQuitting atomic.Bool

	flutterUIMu       sync.Mutex
	flutterUICmd      *exec.Cmd
	flutterUIStarting bool
	flutterUIPending  bool
)

func ShowFlutterWindow() {
	startFlutterWindow(true)
}

func PreloadFlutterWindow() {
	startFlutterWindow(false)
}

func startFlutterWindow(show bool) {
	flutterUIMu.Lock()
	if flutterUICmd != nil && flutterUICmd.Process != nil && flutterUICmd.ProcessState == nil {
		cmd := flutterUICmd
		flutterUIMu.Unlock()
		if show {
			go waitAndFocusFlutterWindow(cmd)
		}
		return
	}
	if flutterUIStarting {
		if show {
			flutterUIPending = true
		}
		flutterUIMu.Unlock()
		return
	}
	flutterUIStarting = true
	flutterUIPending = show
	flutterUIMu.Unlock()

	exePath, err := findFlutterUIExecutable()
	if err != nil {
		flutterUIMu.Lock()
		flutterUIStarting = false
		flutterUIPending = false
		flutterUIMu.Unlock()
		if show {
			openExternalURL(webUIURL)
			utils.ShowWindowsMsgBox("wing", "未找到 Flutter 控制面板，已改用浏览器打开。\n\n"+err.Error())
		}
		return
	}

	args := []string{"--wing-url=" + webUIURL}
	if !show {
		args = append(args, "--startup-hidden")
	}
	cmd := exec.Command(exePath, args...)
	cmd.Dir = filepath.Dir(exePath)

	if err := cmd.Start(); err != nil {
		flutterUIMu.Lock()
		flutterUIStarting = false
		flutterUIPending = false
		flutterUIMu.Unlock()
		if show {
			openExternalURL(webUIURL)
			utils.ShowWindowsMsgBox("wing", "无法启动 Flutter 控制面板，已改用浏览器打开。\n\n"+err.Error())
		}
		return
	}

	flutterUIMu.Lock()
	flutterUICmd = cmd
	shouldFocus := flutterUIPending
	flutterUIStarting = false
	flutterUIPending = false
	flutterUIMu.Unlock()

	if shouldFocus {
		go waitAndFocusFlutterWindow(cmd)
	}

	go func() {
		_ = cmd.Wait()
		flutterUIMu.Lock()
		if flutterUICmd == cmd {
			flutterUICmd = nil
		}
		flutterUIMu.Unlock()
	}()
}

func waitAndFocusFlutterWindow(cmd *exec.Cmd) {
	for i := 0; i < 30; i++ {
		if focusFlutterWindow(cmd) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func QuitFlutterApp() {
	isQuitting.Store(true)

	flutterUIMu.Lock()
	cmd := flutterUICmd
	flutterUICmd = nil
	flutterUIStarting = false
	flutterUIMu.Unlock()

	if cmd != nil && cmd.Process != nil && cmd.ProcessState == nil {
		_ = cmd.Process.Kill()
	}
}

func findFlutterUIExecutable() (string, error) {
	var candidates []string
	if configured := os.Getenv("WING_FLUTTER_UI_EXE"); configured != "" {
		candidates = append(candidates, configured)
	}

	if currentExe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(currentExe)
		candidates = append(candidates, flutterUICandidates(exeDir)...)
	}

	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, flutterUICandidates(cwd)...)
		candidates = append(candidates,
			filepath.Join(cwd, "flutter_ui", "build", "windows", "x64", "runner", "Release", "wing_ui.exe"),
			filepath.Join(cwd, "flutter_ui", "build", "linux", "x64", "release", "bundle", "wing_ui"),
			filepath.Join(cwd, "flutter_ui", "build", "macos", "Build", "Products", "Release", "wing_ui.app", "Contents", "MacOS", "wing_ui"),
		)
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", errors.New("请先运行 .\\scripts\\mk.ps1 build 构建 Flutter UI")
}

func flutterUICandidates(root string) []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			filepath.Join(root, "wing_ui.exe"),
			filepath.Join(root, "flutter_ui", "wing_ui.exe"),
		}
	case "darwin":
		return []string{
			filepath.Join(root, "wing_ui.app", "Contents", "MacOS", "wing_ui"),
			filepath.Join(root, "flutter_ui", "wing_ui.app", "Contents", "MacOS", "wing_ui"),
		}
	default:
		return []string{
			filepath.Join(root, "wing_ui"),
			filepath.Join(root, "flutter_ui", "wing_ui"),
		}
	}
}

func openExternalURL(url string) {
	switch runtime.GOOS {
	case "windows":
		_, _ = utils.RunHiddenCommand("cmd", "/c", "start", url)
	case "darwin":
		_, _ = utils.RunHiddenCommand("open", url)
	default:
		_, _ = utils.RunHiddenCommand("xdg-open", url)
	}
}

func flutterUIStatus() string {
	if exePath, err := findFlutterUIExecutable(); err == nil {
		return fmt.Sprintf("Flutter UI: %s", exePath)
	}
	return "Flutter UI: 未构建"
}
