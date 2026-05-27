# wing 构建脚本
# 使用方法: .\mk.ps1 build

# 核心插件标签
$tags = "with_quic,with_utls,with_gvisor,with_naive_outbound,with_purego"
# 链接器参数: -s -w 去除调试信息, -H windowsgui 隐藏控制台窗口
$ldflags = "-s -w -H windowsgui"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$goCache = Join-Path $repoRoot ".gocache"
$legacyGoModCache = Join-Path $repoRoot "gomodcache2"

function Protect-LegacyGoModCache {
    if (Test-Path $legacyGoModCache) {
        $legacyGoMod = Join-Path $legacyGoModCache "go.mod"
        if (-not (Test-Path $legacyGoMod)) {
            @"
module wing/gomodcache2

go 1.25.0
"@ | Set-Content -LiteralPath $legacyGoMod -Encoding ASCII
        }
    }
}

function Invoke-WithProjectGoCache {
    param([scriptblock]$Action)

    $oldGoCache = $env:GOCACHE

    try {
        New-Item -ItemType Directory -Path $goCache -Force | Out-Null
        Protect-LegacyGoModCache
        $env:GOCACHE = $goCache

        & $Action
    }
    finally {
        $env:GOCACHE = $oldGoCache
    }
}

function Copy-CronetDll {
    Write-Host "🔍 检查并定位 libcronet.dll..." -ForegroundColor Cyan
    $destRoot = Join-Path $repoRoot "libcronet.dll"
    $destBuild = Join-Path $repoRoot "build\bin\libcronet.dll"

    if ((Test-Path $destRoot) -and (Test-Path $destBuild)) {
        Write-Host "✅ libcronet.dll 已存在于合适的位置。" -ForegroundColor Green
        return
    }

    # 定位 GOPATH
    $goPath = $env:GOPATH
    if (-not $goPath) {
        $goPath = Join-Path $env:USERPROFILE "go"
    }

    $modPath = Join-Path $goPath "pkg\mod\github.com\sagernet\cronet-go\lib\windows_amd64@*\libcronet.dll"
    $dlls = Get-ChildItem -Path $modPath -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($dlls) {
        $srcPath = $dlls.FullName
        Write-Host "📍 找到缓存的 libcronet.dll: $srcPath" -ForegroundColor Green
        Copy-Item $srcPath -Destination $destRoot -Force
        Copy-Item $srcPath -Destination $destBuild -Force
        Write-Host "✅ 成功拷贝 libcronet.dll 到项目根目录及 build/bin/" -ForegroundColor Green
    } else {
        Write-Warning "⚠️ 未能在 Go 模块缓存中找到 libcronet.dll，如果运行或测速 QUIC (Naive) 协议节点，可能需要手动放置该 DLL 到当前目录。"
    }
}

switch ($args[0]) {
    "build" {
        Copy-CronetDll
        Write-Host "🚀 正在进行 Wails 桌面应用隐私保护构建..." -ForegroundColor Cyan
        $outputExe = Join-Path $repoRoot "build\bin\wing.exe"

        Invoke-WithProjectGoCache {
            wails build -tags $tags -ldflags "-s -w"
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Wails 构建失败，退出码: $LASTEXITCODE"
        }
        if (Test-Path $outputExe) {
            Copy-Item $outputExe -Destination (Join-Path $repoRoot "wing.exe") -Force
            Write-Host "✅ Wails 桌面应用构建完成: wing.exe" -ForegroundColor Green
        } else {
            throw "编译失败: 未能在 build\bin 中找到 wing.exe"
        }
    }
    "test" {
        Invoke-WithProjectGoCache {
            go test -tags $tags -v . ./pkg/... ./protocol ./test
        }
        if ($LASTEXITCODE -ne 0) {
            throw "测试失败，退出码: $LASTEXITCODE"
        }
    }
    "run" {
        Copy-CronetDll
        Invoke-WithProjectGoCache {
            go run -tags $tags .
        }
        if ($LASTEXITCODE -ne 0) {
            throw "运行失败，退出码: $LASTEXITCODE"
        }
    }
    default {
        Write-Host "用法: .\mk.ps1 [build|test|run]"
        Write-Host "  build  - 隐私保护 & 隐藏窗口构建"
        Write-Host "  test   - 运行测试"
        Write-Host "  run    - 直接运行"
    }
}
