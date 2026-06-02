# wing single-file installer packaging script.
# Builds a Go installer stub with the compiled app payload embedded in the exe.

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$binDir = Join-Path $repoRoot "build\bin"
$distDir = Join-Path $repoRoot "dist"
$stubDir = Join-Path $repoRoot "installer\stub"
$stubPayload = Join-Path $stubDir "wing-payload.zip"
$installerExe = Join-Path $distDir "wing-installer.exe"

$requiredFiles = @(
    (Join-Path $binDir "wing.exe"),
    (Join-Path $binDir "libcronet.dll"),
    (Join-Path $binDir "flutter_ui\wing_ui.exe"),
    (Join-Path $stubDir "main.go")
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        throw "缺少打包输入文件: $file。请先运行 .\scripts\mk.ps1 build"
    }
}

New-Item -ItemType Directory -Path $distDir -Force | Out-Null

Write-Host "🗜️ 正在压缩安装 payload..." -ForegroundColor Cyan
if (Test-Path $stubPayload) {
    Remove-Item -LiteralPath $stubPayload -Force
}
Compress-Archive -Path (Join-Path $binDir "*") -DestinationPath $stubPayload -CompressionLevel Optimal -Force

Write-Host "📦 正在生成单文件安装器..." -ForegroundColor Cyan
Push-Location $repoRoot
try {
    go build -ldflags "-s -w -H windowsgui" -o $installerExe .\installer\stub
    if ($LASTEXITCODE -ne 0) {
        throw "Go 安装器构建失败，退出码: $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

if (-not (Test-Path $installerExe)) {
    throw "安装器生成失败: 未找到 $installerExe"
}

Write-Host "✅ 单文件安装器已生成: $installerExe" -ForegroundColor Green
