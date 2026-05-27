//go:build windows
package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// EnsureCronetDll 自动定位并拷贝 libcronet.dll
func EnsureCronetDll() {
	// 检查当前目录下是否已存在 libcronet.dll
	if _, err := os.Stat("libcronet.dll"); err == nil {
		return
	}

	// 从环境变量获取 GOPATH，默认为用户目录下的 go 文件夹
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			gopath = filepath.Join(home, "go")
		}
	}
	if gopath == "" {
		return
	}

	// 匹配 github.com/sagernet/cronet-go/lib/windows_amd64@* 路径
	cronetLibDir := filepath.Join(gopath, "pkg", "mod", "github.com", "sagernet", "cronet-go", "lib")
	files, err := os.ReadDir(cronetLibDir)
	if err != nil {
		return
	}

	var bestDir string
	for _, file := range files {
		if file.IsDir() && strings.HasPrefix(file.Name(), "windows_amd64@") {
			bestDir = filepath.Join(cronetLibDir, file.Name())
		}
	}

	if bestDir == "" {
		return
	}

	srcPath := filepath.Join(bestDir, "libcronet.dll")
	if _, err := os.Stat(srcPath); err != nil {
		return
	}

	// 拷贝文件到当前工作目录
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return
	}
	defer srcFile.Close()

	destFile, err := os.Create("libcronet.dll")
	if err != nil {
		return
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, srcFile); err == nil {
		fmt.Println("✅ 自动从 Go 模块缓存拷贝 libcronet.dll 至当前工作目录")
	}
}
