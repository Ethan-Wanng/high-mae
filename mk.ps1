# High-Mae 构建脚本
# 使用方法: .\mk.ps1 build

# 核心插件标签
$tags = "with_quic,with_utls"
# 链接器参数: -s -w 去除调试信息, -H windowsgui 隐藏控制台窗口
$ldflags = "-s -w -H windowsgui"

switch ($args[0]) {
    "build" {
        Write-Host "🚀 正在进行隐私保护构建..." -ForegroundColor Cyan
        go build -tags $tags -trimpath -ldflags "$ldflags" -o HighMae.exe .
        Write-Host "✅ 构建完成: HighMae.exe" -ForegroundColor Green
    }
    "test" {
        go test -tags $tags -v ./...
    }
    "run" {
        go run -tags $tags .
    }
    default {
        Write-Host "用法: .\mk.ps1 [build|test|run]"
        Write-Host "  build  - 隐私保护 & 隐藏窗口构建"
        Write-Host "  test   - 运行测试"
        Write-Host "  run    - 直接运行"
    }
}
