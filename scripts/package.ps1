# wing installer packaging script
# Usage: .\scripts\package.ps1

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$issFile = Join-Path $repoRoot "installer\wing.iss"
$setupExe = Join-Path $repoRoot "dist\wing-setup.exe"

function Find-InnoCompiler {
    $cmd = Get-Command iscc -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 5\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 5\ISCC.exe"
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    return $null
}

if (-not (Test-Path $issFile)) {
    throw "未找到 Inno Setup 配置文件: $issFile"
}

$requiredFiles = @(
    (Join-Path $repoRoot "build\bin\wing.exe"),
    (Join-Path $repoRoot "build\bin\libcronet.dll"),
    (Join-Path $repoRoot "build\bin\flutter_ui\wing_ui.exe")
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        throw "缺少打包输入文件: $file。请先运行 .\scripts\mk.ps1 build"
    }
}

$iscc = Find-InnoCompiler
if (-not $iscc) {
    throw "未找到 Inno Setup 编译器 ISCC.exe。请安装 Inno Setup 6，或把 ISCC.exe 加入 PATH。下载地址: https://jrsoftware.org/isdl.php"
}

New-Item -ItemType Directory -Path (Join-Path $repoRoot "dist") -Force | Out-Null

Write-Host "📦 正在生成单文件安装包..." -ForegroundColor Cyan
& $iscc $issFile
if ($LASTEXITCODE -ne 0) {
    throw "安装包生成失败，退出码: $LASTEXITCODE"
}

if (-not (Test-Path $setupExe)) {
    throw "安装包生成失败: 未找到 $setupExe"
}

Write-Host "✅ 安装包已生成: $setupExe" -ForegroundColor Green
