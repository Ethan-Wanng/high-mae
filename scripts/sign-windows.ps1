param(
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
    [string[]]$Path
)

$ErrorActionPreference = "Stop"

function Find-SignTool {
    $cmd = Get-Command signtool -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (-not (Test-Path $kitsRoot)) {
        return $null
    }

    $candidate = Get-ChildItem -Path $kitsRoot -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($candidate) {
        return $candidate.FullName
    }
    return $null
}

function Get-CertificatePath {
    if ($env:WINDOWS_CERTIFICATE_PATH -and (Test-Path $env:WINDOWS_CERTIFICATE_PATH)) {
        return $env:WINDOWS_CERTIFICATE_PATH
    }

    if (-not $env:WINDOWS_CERTIFICATE_BASE64) {
        return $null
    }

    $certPath = Join-Path $env:RUNNER_TEMP "wing-signing-cert.pfx"
    try {
        [IO.File]::WriteAllBytes($certPath, [Convert]::FromBase64String(($env:WINDOWS_CERTIFICATE_BASE64 -replace '\s','')))
        return $certPath
    } catch {
        Write-Warning "Failed to parse WINDOWS_CERTIFICATE_BASE64: $_"
        return $null
    }
}

$signTool = Find-SignTool
if (-not $signTool) {
    Write-Host "signtool not found; skipping Windows code signing."
    return
}

$certPath = Get-CertificatePath
$thumbprint = $env:WINDOWS_CERTIFICATE_THUMBPRINT
if (-not $certPath -and -not $thumbprint) {
    Write-Host "No Windows signing certificate configured; skipping Windows code signing."
    return
}

$timestampURL = if ($env:WINDOWS_TIMESTAMP_URL) { $env:WINDOWS_TIMESTAMP_URL } else { "http://timestamp.digicert.com" }

foreach ($item in $Path) {
    if (-not (Test-Path $item)) {
        throw "Cannot sign missing file: $item"
    }

    if ($certPath) {
        & $signTool sign /fd SHA256 /td SHA256 /tr $timestampURL /f $certPath /p $env:WINDOWS_CERTIFICATE_PASSWORD $item
    } else {
        & $signTool sign /fd SHA256 /td SHA256 /tr $timestampURL /sha1 $thumbprint $item
    }

    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed for $item with exit code $LASTEXITCODE"
    }
}
