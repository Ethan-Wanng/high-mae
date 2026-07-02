//go:build windows

package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	cronetDLLName             = "libcronet.dll"
	cronetWindowsAMD64Version = "v0.0.0-20260309101654-0cbdcfddded9"
)

var expectedCronetDLLSHA256 = "8ef1f8bbde77f954af1ae47bee1819ac8dc2354bb0e1d4baba3dad9e58d7a6f7"

// EnsureCronetDll 自动定位并拷贝 libcronet.dll
func EnsureCronetDll() {
	// 检查当前目录下是否已存在 libcronet.dll
	if _, err := os.Stat(cronetDLLName); err == nil {
		if err := verifyCronetDLLHash(cronetDLLName); err != nil {
			fmt.Printf("⚠️ 已存在的 %s 未通过完整性校验: %v\n", cronetDLLName, err)
		}
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

	srcPath := cronetModuleDLLPath(gopath)
	if _, err := os.Stat(srcPath); err != nil {
		return
	}
	if err := verifyCronetDLLHash(srcPath); err != nil {
		fmt.Printf("⚠️ 跳过拷贝 %s: %v\n", srcPath, err)
		return
	}

	// 拷贝文件到当前工作目录
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return
	}
	defer srcFile.Close()

	destFile, err := os.OpenFile(cronetDLLName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return
	}

	if _, err := io.Copy(destFile, srcFile); err != nil {
		_ = destFile.Close()
		_ = os.Remove(cronetDLLName)
		return
	}
	if err := destFile.Close(); err != nil {
		_ = os.Remove(cronetDLLName)
		return
	}
	if err := verifyCronetDLLHash(cronetDLLName); err != nil {
		_ = os.Remove(cronetDLLName)
		fmt.Printf("⚠️ 拷贝后的 %s 未通过完整性校验: %v\n", cronetDLLName, err)
		return
	}
	fmt.Println("✅ 自动从 Go 模块缓存拷贝 libcronet.dll 至当前工作目录")
}

func cronetModuleDLLPath(gopath string) string {
	return filepath.Join(
		gopath,
		"pkg", "mod", "github.com", "sagernet", "cronet-go", "lib",
		"windows_amd64@"+cronetWindowsAMD64Version,
		cronetDLLName,
	)
}

func verifyCronetDLLHash(path string) error {
	got, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, expectedCronetDLLSHA256) {
		return fmt.Errorf("sha256=%s, want %s", got, expectedCronetDLLSHA256)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
