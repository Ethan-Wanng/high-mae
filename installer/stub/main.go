package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

//go:embed wing-payload.zip
var payloadZip []byte

const (
	appName        = "wing"
	defaultFolder  = "Programs\\wing"
	createNoWindow = 0x08000000

	mbOK        = 0x00000000
	mbOKCancel  = 0x00000001
	mbYesNo     = 0x00000004
	mbIconInfo  = 0x00000040
	mbIconError = 0x00000010
	idOK        = 1
	idYes       = 6
)

func main() {
	if err := run(); err != nil {
		messageBox("wing installer", "安装失败:\n\n"+err.Error(), mbOK|mbIconError)
		os.Exit(1)
	}
}

func run() error {
	options := parseOptions(os.Args[1:])
	installDir := options.installDir
	if installDir == "" {
		defaultDir := defaultInstallDir()
		selectedDir, err := chooseInstallDir(defaultDir)
		if err != nil {
			if errors.Is(err, errCanceled) {
				return nil
			}
			return err
		}
		installDir = selectedDir
	}
	installDir = strings.TrimSpace(installDir)
	if installDir == "" {
		return nil
	}
	var err error
	installDir, err = filepath.Abs(installDir)
	if err != nil {
		return err
	}

	if !options.silent {
		confirm := messageBox(
			"wing installer",
			fmt.Sprintf("wing 将安装到:\n\n%s\n\n如果该目录已存在旧版本文件，将会被覆盖；如果旧版本正在运行，会先自动关闭。", installDir),
			mbOKCancel|mbIconInfo,
		)
		if confirm != idOK {
			return nil
		}
	}

	if err := installPayload(installDir); err != nil {
		return err
	}
	exePath := filepath.Join(installDir, "wing.exe")
	if !options.noShortcuts {
		if err := createShortcuts(installDir, exePath); err != nil {
			if options.silent {
				return err
			}
			messageBox("wing installer", "安装完成，但创建快捷方式失败:\n\n"+err.Error(), mbOK|mbIconInfo)
		}
	}

	if options.silent || options.noLaunch {
		return nil
	}

	launch := messageBox("wing installer", "wing 已安装完成。\n\n是否现在启动？", mbYesNo|mbIconInfo)
	if launch == idYes {
		cmd := exec.Command(exePath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
		_ = cmd.Start()
	}
	return nil
}

type installOptions struct {
	installDir  string
	silent      bool
	noLaunch    bool
	noShortcuts bool
}

func parseOptions(args []string) installOptions {
	var options installOptions
	for _, arg := range args {
		lower := strings.ToLower(arg)
		switch {
		case lower == "--silent":
			options.silent = true
		case lower == "--no-launch":
			options.noLaunch = true
		case lower == "--no-shortcuts":
			options.noShortcuts = true
		case strings.HasPrefix(lower, "--dir="):
			options.installDir = strings.TrimSpace(arg[len("--dir="):])
		}
	}
	if options.silent {
		options.noLaunch = true
	}
	return options
}

var errCanceled = errors.New("canceled")

func defaultInstallDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.Getenv("USERPROFILE")
	}
	if base == "" {
		base = "."
	}
	return filepath.Join(base, defaultFolder)
}

func chooseInstallDir(defaultDir string) (string, error) {
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
$default = %s
New-Item -ItemType Directory -Path $default -Force | Out-Null
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = '选择 wing 安装目录'
$dialog.SelectedPath = $default
$dialog.ShowNewFolderButton = $true
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
  Write-Output $dialog.SelectedPath
  exit 0
}
exit 2
`, powershellString(defaultDir))

	cmd := exec.Command("powershell", "-STA", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			return "", errCanceled
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func installPayload(installDir string) error {
	root, err := filepath.Abs(installDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	_ = stopInstalledProcesses(root)

	for _, name := range []string{"flutter_ui"} {
		path := filepath.Join(root, name)
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("清理旧文件失败 %s: %w", path, err)
		}
	}
	for _, name := range []string{"wing.exe", "libcronet.dll"} {
		path := filepath.Join(root, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("清理旧文件失败 %s: %w", path, err)
		}
	}

	reader, err := zip.NewReader(bytes.NewReader(payloadZip), int64(len(payloadZip)))
	if err != nil {
		return err
	}

	for _, file := range reader.File {
		target := filepath.Join(root, file.Name)
		if !isPathInside(root, target) {
			return fmt.Errorf("安装包包含非法路径: %s", file.Name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := extractFile(file, target); err != nil {
			return err
		}
	}
	return nil
}

func stopInstalledProcesses(installDir string) error {
	root, err := filepath.Abs(installDir)
	if err != nil {
		return err
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'SilentlyContinue'
$root = [System.IO.Path]::GetFullPath(%s).TrimEnd('\') + '\'
Get-Process -Name 'wing','wing_ui' -ErrorAction SilentlyContinue | Where-Object {
    $processPath = $null
    try { $processPath = $_.Path } catch { $processPath = $null }
    if ($processPath) {
        $fullProcessPath = [System.IO.Path]::GetFullPath($processPath)
        $fullProcessPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)
    } else {
        $false
    }
} | ForEach-Object {
    $targetId = $_.Id
    Stop-Process -Id $targetId -Force -ErrorAction SilentlyContinue
    try { Wait-Process -Id $targetId -Timeout 10 -ErrorAction SilentlyContinue } catch {}
}
`, powershellString(root))

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd.Run()
}

func extractFile(file *zip.File, target string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, file.Mode())
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func createShortcuts(installDir, exePath string) error {
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$shell = New-Object -ComObject WScript.Shell
$exe = %s
$workDir = %s
$icon = Join-Path $workDir 'icon.ico'
if (-not (Test-Path -LiteralPath $icon)) {
    $icon = $exe
}
$desktop = [Environment]::GetFolderPath('DesktopDirectory')
$shortcut = $shell.CreateShortcut((Join-Path $desktop 'wing.lnk'))
$shortcut.TargetPath = $exe
$shortcut.WorkingDirectory = $workDir
$shortcut.IconLocation = $icon
$shortcut.Save()
$programs = [Environment]::GetFolderPath('Programs')
$startMenuDir = Join-Path $programs 'wing'
New-Item -ItemType Directory -Path $startMenuDir -Force | Out-Null
$shortcut = $shell.CreateShortcut((Join-Path $startMenuDir 'wing.lnk'))
$shortcut.TargetPath = $exe
$shortcut.WorkingDirectory = $workDir
$shortcut.IconLocation = $icon
$shortcut.Save()
`, powershellString(exePath), powershellString(installDir))

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func powershellString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func isPathInside(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func messageBox(title, text string, flags uint32) int {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBoxW := user32.NewProc("MessageBoxW")
	ret, _, _ := messageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(text))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
		uintptr(flags),
	)
	return int(ret)
}
