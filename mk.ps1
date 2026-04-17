# High-Mae 构建脚本
# 使用方法: .\mk.ps1 [build|test|run]

$tags = "with_quic"

switch ($args[0]) {
    "build" {
        go build -tags $tags -o high-mae.exe .
    }
    "test" {
        go test -tags $tags -v ./...
    }
    "run" {
        go run -tags $tags .
    }
    default {
        Write-Host "用法: .\mk.ps1 [build|test|run]"
        Write-Host "  build  - 构建可执行文件 high-mae.exe"
        Write-Host "  test   - 运行所有测试"
        Write-Host "  run    - 直接运行"
    }
}
