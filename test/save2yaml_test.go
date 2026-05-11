package test

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"high-mae/ins"
	"high-mae/protocol"
)

// go test -v -run TestImportAndSaveRealFile -args "订阅链接或节点"
func TestImportAndSaveRealFile(t *testing.T) {
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		t.Fatal("❌ 请通过 -args 传入订阅链接或节点字符串")
	}

	input := args[0]
	t.Logf("📥 输入:\n%s", input)

	// 1. 解析
	nodes, err := ins.ParseSubscription(input)
	if err != nil {
		t.Fatalf("❌ 解析失败: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("❌ 没有解析出节点")
	}

	t.Logf("✅ 解析出 %d 个节点", len(nodes))

	// 2. 写入真实文件（当前目录）
	outPath := filepath.Join(".", "output.yml")

	// 删除旧文件（防止残留）
	_ = os.Remove(outPath)

	err = ins.SaveNodesToYAML(outPath, nodes)
	if err != nil {
		t.Fatalf("❌ 写入失败: %v", err)
	}

	absPath, _ := filepath.Abs(outPath)
	t.Logf("💾 已写入文件: %s", absPath)

	// 3. 回读验证（可选但建议保留）
	readNodes, err := protocol.ParseNodes(outPath)
	if err != nil {
		t.Fatalf("❌ 回读失败: %v", err)
	}
	t.Logf("📦 回读节点数: %d", len(readNodes))

	// 4. 自动打开文件（方便你肉眼检查）
	openFile(absPath)

	t.Log("🎉 测试完成，请直接查看 output.yml")
}

// 自动打开文件（跨平台）
func openFile(path string) {
	switch runtime.GOOS {
	case "windows":
		exec.Command("cmd", "/c", "start", path).Start()
	case "darwin":
		exec.Command("open", path).Start()
	case "linux":
		exec.Command("xdg-open", path).Start()
	}
}
