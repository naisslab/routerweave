param(
    [ValidateSet("recover")][string]$Action = "recover",
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Udid,
    [ValidateRange(1,65535)][int]$Port = 8100
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$StateDir = Join-Path $RepoRoot ".go-ios"
function Ensure-StateDir {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
}

function Get-IosExe {
    $cmd = Get-Command ios.exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "ios.exe not found. Install go-ios or make sure it is on PATH."
    }
    return $cmd.Source
}

function Repair-Wda {
    Ensure-StateDir
    $ios = Get-IosExe
    $deviceToken = '(?i)(?:^|\s)--udid\s+"?' + [regex]::Escape($Udid) + '"?(?:\s|$)'
    $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'ios.exe'" |
        Where-Object { $_.CommandLine -match $deviceToken })
    $forwardToken = '(?i)(?:^|\s)forward\s+' + $Port + '\s+8100(?:\s|$)'
    $forwards = @($processes | Where-Object { $_.CommandLine -match $forwardToken })
    $runs = @($processes | Where-Object { $_.CommandLine -match '(?i)(?:^|\s)runwda(?:\s|$)' })
    $stamp = [guid]::NewGuid().ToString('N')
    foreach ($item in $forwards) {
        $current = Get-CimInstance Win32_Process -Filter "ProcessId = $($item.ProcessId)"
        if ($current -and $current.CommandLine -eq $item.CommandLine -and $current.CreationDate -eq $item.CreationDate) {
            Stop-Process -Id $item.ProcessId -Force
        }
    }
    Start-Process -FilePath $ios -ArgumentList @('forward', "$Port", '8100', '--udid', $Udid) `
        -RedirectStandardOutput (Join-Path $StateDir "wda-recovery-$stamp-forward.out.log") `
        -RedirectStandardError (Join-Path $StateDir "wda-recovery-$stamp-forward.err.log") -WindowStyle Hidden | Out-Null
    Start-Sleep -Seconds 2
    try {
        $status = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/status" -TimeoutSec 5
        if ($status.value.ready) { return }
    } catch {}
    foreach ($item in $runs) {
        $current = Get-CimInstance Win32_Process -Filter "ProcessId = $($item.ProcessId)"
        if ($current -and $current.CommandLine -eq $item.CommandLine -and $current.CreationDate -eq $item.CreationDate) {
            Stop-Process -Id $item.ProcessId -Force
        }
    }
    Start-Process -FilePath $ios -ArgumentList @('runwda', '--udid', $Udid) `
        -RedirectStandardOutput (Join-Path $StateDir "wda-recovery-$stamp-run.out.log") `
        -RedirectStandardError (Join-Path $StateDir "wda-recovery-$stamp-run.err.log") -WindowStyle Hidden | Out-Null
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        Start-Sleep -Seconds 3
        try {
            $status = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/status" -TimeoutSec 3
            if ($status.value.ready) { return }
        } catch {}
    }
    throw 'Selected-phone WDA recovery did not become ready within its bounded wait'
}

Repair-Wda
