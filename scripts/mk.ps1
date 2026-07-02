# wing 构建脚本
# 使用方法: .\mk.ps1 build

$ErrorActionPreference = "Stop"

# 核心插件标签
$tags = "with_quic,with_utls,with_gvisor,with_naive_outbound,with_purego"
# 链接器参数: -s -w 去除调试信息, -H windowsgui 隐藏控制台窗口
$ldflags = "-s -w -H windowsgui"
if (-not [string]::IsNullOrWhiteSpace($env:WING_FREE_FLOW_NODE_LINK)) {
    $ldflags += " -X wing/pkg/freeflow.packagedNodeLink=$($env:WING_FREE_FLOW_NODE_LINK)"
}
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$goCache = Join-Path $repoRoot ".gocache"
$legacyGoModCache = Join-Path $repoRoot "gomodcache2"
$flutterProject = Join-Path $repoRoot "flutter_ui"
$flutterRelease = Join-Path $flutterProject "build\windows\x64\runner\Release"
$flutterDist = Join-Path $repoRoot "build\bin\flutter_ui"
$backendExe = Join-Path $repoRoot "build\bin\wing.exe"
$portablePackageScript = Join-Path $repoRoot "scripts\package-portable.ps1"
$innoPackageScript = Join-Path $repoRoot "scripts\package.ps1"
$cronetWindowsAMD64Version = "v0.0.0-20260309101654-0cbdcfddded9"
$cronetDllSha256 = "8ef1f8bbde77f954af1ae47bee1819ac8dc2354bb0e1d4baba3dad9e58d7a6f7"

function Stop-BuildOutputProcesses {
    param([string[]]$TargetRoots)

    $fullRoots = @($TargetRoots | ForEach-Object {
        if ($_ -and (Test-Path $_)) {
            [System.IO.Path]::GetFullPath($_).TrimEnd('\')
        }
    })
    if ($fullRoots.Count -eq 0) {
        return
    }

    $processes = Get-Process -Name "wing", "wing_ui" -ErrorAction SilentlyContinue | Where-Object {
        $processPath = $null
        try {
            $processPath = $_.Path
        }
        catch {
            $processPath = $null
        }
        if (-not $processPath) {
            return $false
        }
        $fullProcessPath = [System.IO.Path]::GetFullPath($processPath)
        foreach ($root in $fullRoots) {
            if ($fullProcessPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        return $false
    }

    foreach ($process in $processes) {
        Write-Host "🛑 正在停止旧构建进程 $($process.ProcessName) (PID $($process.Id))..." -ForegroundColor Yellow
        Stop-Process -Id $process.Id -Force
        Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
}

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

function Assert-CronetDllHash {
    param([string]$Path)

    if (-not (Test-Path $Path -PathType Leaf)) {
        throw "未找到 libcronet.dll: $Path"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -ne $cronetDllSha256) {
        throw "libcronet.dll 完整性校验失败: $Path sha256=$actual, want=$cronetDllSha256"
    }
}

function Copy-CronetDll {
    Write-Host "🔍 检查并定位 libcronet.dll..." -ForegroundColor Cyan
    $destRoot = Join-Path $repoRoot "libcronet.dll"
    $destBuild = Join-Path $repoRoot "build\bin\libcronet.dll"
    New-Item -ItemType Directory -Path (Split-Path -Parent $destBuild) -Force | Out-Null

    if ((Test-Path $destRoot) -and (Test-Path $destBuild)) {
        Assert-CronetDllHash $destRoot
        Assert-CronetDllHash $destBuild
        Write-Host "✅ libcronet.dll 已存在于合适的位置。" -ForegroundColor Green
        return
    }

    # 定位 GOPATH
    $goPath = $env:GOPATH
    if (-not $goPath) {
        $goPath = Join-Path $env:USERPROFILE "go"
    }

    $modPath = Join-Path $goPath "pkg\mod\github.com\sagernet\cronet-go\lib\windows_amd64@$cronetWindowsAMD64Version\libcronet.dll"
    $dlls = Get-Item -LiteralPath $modPath -ErrorAction SilentlyContinue

    if ($dlls) {
        $srcPath = $dlls.FullName
        Write-Host "📍 找到缓存的 libcronet.dll: $srcPath" -ForegroundColor Green
        Assert-CronetDllHash $srcPath
        Copy-Item $srcPath -Destination $destRoot -Force
        Copy-Item $srcPath -Destination $destBuild -Force
        Assert-CronetDllHash $destRoot
        Assert-CronetDllHash $destBuild
        Write-Host "✅ 成功拷贝 libcronet.dll 到项目根目录及 build/bin/" -ForegroundColor Green
    } else {
        Write-Warning "⚠️ 未能在 Go 模块缓存中找到 libcronet.dll，如果运行或测速 QUIC (Naive) 协议节点，可能需要手动放置该 DLL 到当前目录。"
    }
}

function Download-CronetDllModule {
    Write-Host "⬇️ 正在准备 libcronet.dll 模块..." -ForegroundColor Cyan
    Invoke-WithProjectGoCache {
        go mod download github.com/sagernet/cronet-go/lib/windows_amd64
    }
    if ($LASTEXITCODE -ne 0) {
        throw "下载 libcronet.dll 模块失败，退出码: $LASTEXITCODE"
    }
}

function Reset-ProjectDirectory {
    param([string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($repoRoot)
    if (-not $fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "拒绝清理项目目录之外的路径: $fullPath"
    }

    if (Test-Path $fullPath) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
    New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
}

function Build-FlutterUI {
    if (-not (Test-Path $flutterProject)) {
        throw "未找到 Flutter 项目目录: $flutterProject"
    }

    Write-Host "🦋 正在构建 Flutter 桌面控制面板..." -ForegroundColor Cyan
    Push-Location $flutterProject
    try {
        flutter pub get
        if ($LASTEXITCODE -ne 0) {
            throw "Flutter 依赖安装失败，退出码: $LASTEXITCODE"
        }

        flutter build windows --release -t lib/main_windows.dart
        if ($LASTEXITCODE -ne 0) {
            throw "Flutter Windows 构建失败，退出码: $LASTEXITCODE。请确认已安装 Visual Studio 2022 Build Tools 的 Desktop development with C++ 工作负载。"
        }
    }
    finally {
        Pop-Location
    }

    $flutterExe = Join-Path $flutterRelease "wing_ui.exe"
    if (-not (Test-Path $flutterExe)) {
        throw "Flutter 构建失败: 未能找到 $flutterExe"
    }

    Stop-BuildOutputProcesses @($flutterDist)
    Reset-ProjectDirectory $flutterDist
    Copy-Item -Path (Join-Path $flutterRelease "*") -Destination $flutterDist -Recurse -Force
    Write-Host "✅ Flutter 控制面板已输出到 build\bin\flutter_ui" -ForegroundColor Green
}

function Build-GoBackend {
    Download-CronetDllModule
    Copy-CronetDll
    Write-Host "🚀 正在构建 Go 后端与系统托盘..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path (Split-Path -Parent $backendExe) -Force | Out-Null
    Stop-BuildOutputProcesses @((Split-Path -Parent $backendExe))

    Invoke-WithProjectGoCache {
        go build -tags $tags -ldflags $ldflags -o $backendExe .
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Go 后端构建失败，退出码: $LASTEXITCODE"
    }

    Copy-Item $backendExe -Destination (Join-Path $repoRoot "wing.exe") -Force
    Copy-Item (Join-Path $repoRoot "assets\icon.ico") -Destination (Join-Path $repoRoot "build\bin\icon.ico") -Force
    Write-Host "✅ Go 后端构建完成: wing.exe" -ForegroundColor Green
}

function Invoke-InnoPackage {
    $packageArgs = @()
    if ($args.Count -gt 1) {
        $packageArgs = $args[1..($args.Count - 1)]
    }

    & $innoPackageScript @packageArgs
    if ($LASTEXITCODE -ne 0) {
        throw "安装包生成失败，退出码: $LASTEXITCODE"
    }
}

switch ($args[0]) {
    "build" {
        Build-FlutterUI
        Build-GoBackend
        Write-Host "🎉 Flutter + Go 桌面应用构建完成。" -ForegroundColor Green
    }
    "package" {
        Build-FlutterUI
        Build-GoBackend
        Invoke-InnoPackage @args
    }
    "installer" {
        Build-FlutterUI
        Build-GoBackend
        Invoke-InnoPackage @args
    }
    "portable" {
        Build-FlutterUI
        Build-GoBackend
        & $portablePackageScript
        if ($LASTEXITCODE -ne 0) {
            throw "安装包生成失败，退出码: $LASTEXITCODE"
        }
    }
    "inno" {
        Build-FlutterUI
        Build-GoBackend
        Invoke-InnoPackage @args
    }
    "backend" {
        Build-GoBackend
    }
    "test" {
        Invoke-WithProjectGoCache {
            go test -tags $tags -v . ./pkg/... ./protocol
        }
        if ($LASTEXITCODE -ne 0) {
            throw "测试失败，退出码: $LASTEXITCODE"
        }
    }
    "run" {
        Build-FlutterUI
        Copy-CronetDll
        $oldFlutterUIExe = $env:WING_FLUTTER_UI_EXE
        try {
            $env:WING_FLUTTER_UI_EXE = Join-Path $flutterRelease "wing_ui.exe"
            Invoke-WithProjectGoCache {
                go run -tags $tags .
            }
        }
        finally {
            $env:WING_FLUTTER_UI_EXE = $oldFlutterUIExe
        }
        if ($LASTEXITCODE -ne 0) {
            throw "运行失败，退出码: $LASTEXITCODE"
        }
    }
    "ui" {
        Build-FlutterUI
    }
    default {
        Write-Host "用法: .\mk.ps1 [build|package|installer|portable|backend|test|run|ui|inno]"
        Write-Host "  build  - 构建 Flutter 控制面板与 Go 后端"
        Write-Host "  package - 构建并生成 dist\wing-1.0.5.2-windows-x64-setup.exe 标准安装包"
        Write-Host "  installer - 同 package，生成标准 Windows 安装包"
        Write-Host "  portable - 生成旧版自解压单文件安装包，可能更容易被安全软件误报"
        Write-Host "  backend - 仅构建 Go 后端"
        Write-Host "  test   - 运行测试"
        Write-Host "  run    - 构建 Flutter 控制面板后直接运行 Go 后端"
        Write-Host "  ui     - 仅构建 Flutter 控制面板"
        Write-Host "  inno   - 使用 Inno Setup 生成 dist\wing-setup.exe"
    }
}
