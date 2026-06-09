# wing installer packaging script
# Usage: .\scripts\package.ps1 [-ISCCPath C:\Path\To\ISCC.exe]

param(
    [string]$ISCCPath
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$issFile = Join-Path $repoRoot "installer\wing.iss"
$setupExe = Join-Path $repoRoot "dist\wing-1.0.2-windows-x64-setup.exe"

function Resolve-InnoCompilerCandidate {
    param([string]$Path)

    if (-not $Path) {
        return $null
    }

    $candidate = [Environment]::ExpandEnvironmentVariables($Path.Trim('"'))
    if (-not $candidate) {
        return $null
    }

    if ((Test-Path $candidate -PathType Container)) {
        $candidate = Join-Path $candidate "ISCC.exe"
    }

    if (Test-Path $candidate -PathType Leaf) {
        return (Resolve-Path $candidate).Path
    }

    return $null
}

function Find-InnoCompiler {
    $explicit = Resolve-InnoCompilerCandidate $ISCCPath
    if ($explicit) {
        return $explicit
    }

    $envCandidates = @(
        $env:ISCC_EXE,
        $env:ISCC,
        $env:INNO_SETUP_COMPILER,
        $env:INNO_SETUP_DIR
    )
    foreach ($candidate in $envCandidates) {
        $resolved = Resolve-InnoCompilerCandidate $candidate
        if ($resolved) {
            return $resolved
        }
    }

    $cmd = Get-Command iscc.exe, iscc -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) {
        return $cmd.Source
    }

    $registryRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($item in Get-ItemProperty $registryRoots -ErrorAction SilentlyContinue) {
        if ($item.DisplayName -notlike "Inno Setup*") {
            continue
        }
        $resolved = Resolve-InnoCompilerCandidate $item.InstallLocation
        if ($resolved) {
            return $resolved
        }

        if ($item.UninstallString -match '^"([^"]+)"') {
            $resolved = Resolve-InnoCompilerCandidate (Split-Path -Parent $matches[1])
            if ($resolved) {
                return $resolved
            }
        }
    }

    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 5\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 5\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 5\ISCC.exe"
    )

    foreach ($candidate in $candidates) {
        $resolved = Resolve-InnoCompilerCandidate $candidate
        if ($resolved) {
            return $resolved
        }
    }

    return $null
}

function Get-InnoMissingMessage {
    @"
未找到 Inno Setup 编译器 ISCC.exe，标准安装包未生成。

可选处理方式:
1. 安装 Inno Setup 6 后重试:
   winget install --id JRSoftware.InnoSetup -e
   或从 https://jrsoftware.org/isdl.php 下载安装
2. 如果已安装在自定义目录，显式指定:
   .\scripts\mk.ps1 package -ISCCPath "C:\Path\To\ISCC.exe"
   或设置环境变量 ISCC_EXE / INNO_SETUP_DIR
3. 只需要一个可分发单文件时，可先用:
   .\scripts\mk.ps1 portable
"@
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
    throw (Get-InnoMissingMessage)
}

New-Item -ItemType Directory -Path (Join-Path $repoRoot "dist") -Force | Out-Null

Write-Host "📦 正在生成标准 Windows 安装包..." -ForegroundColor Cyan
& $iscc $issFile
if ($LASTEXITCODE -ne 0) {
    throw "安装包生成失败，退出码: $LASTEXITCODE"
}

if (-not (Test-Path $setupExe)) {
    throw "安装包生成失败: 未找到 $setupExe"
}

Write-Host "✅ 安装包已生成: $setupExe" -ForegroundColor Green
