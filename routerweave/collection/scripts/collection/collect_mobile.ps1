param(
    [switch]$ManualGroundTruth,
    [switch]$EventMarkerOnly,
    [string]$PythonExecutable = "python",
    [string]$Task = "",
    [string]$AppName = "",
    [switch]$Preview,
    [ValidateSet("human", "agent")]
    [string]$EnvironmentOperator = "human",
    [string]$ResumeEnvironmentFrom = "",
    [string]$ContinueEnvironmentFrom = "",
    [ValidateSet("", "home_screen_idle", "idle_screen_off")]
    [string]$BackgroundScenario = "",
    [double]$DurationSeconds = 0,
    [Parameter(Mandatory = $true)]
    [string]$RootOut,
    [Parameter(Mandatory = $true)]
    [string]$CollectionTaskId,
    [string]$PhoneIp = "",
    [string]$Serial = "",
    [string]$IosUdid = "",
    [string]$WdaUrl = "http://127.0.0.1:8100",
    [string]$RouterHost = $env:ROUTERWEAVE_ROUTER_HOST,
    [string]$RouterUser = "root",
    [string]$RouterInterface = "br-lan",
    [ValidateSet("app", "none")]
    [string]$AttributionMode = "app",
    [string]$RouterIdentity = $env:ROUTERWEAVE_SSH_KEY
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo
$env:PYTHONPATH = (Join-Path $repo "src") + [IO.Path]::PathSeparator + $repo
if ($EventMarkerOnly -and -not $ManualGroundTruth) {
    throw "EventMarkerOnly requires ManualGroundTruth."
}

if (([int][bool]$Task + [int][bool]$AppName + [int][bool]$BackgroundScenario + [int][bool]$ManualGroundTruth) -ne 1) {
    throw "Provide exactly one of -Task, -AppName, -BackgroundScenario, or -ManualGroundTruth."
}
if ($Preview -and ($ManualGroundTruth -or $BackgroundScenario)) { throw "Preview requires Task or AppName." }
if ($ResumeEnvironmentFrom -and ($ManualGroundTruth -or $BackgroundScenario)) { throw "ResumeEnvironmentFrom requires Task or AppName." }
if ($ContinueEnvironmentFrom -and ($ManualGroundTruth -or $BackgroundScenario -or $ResumeEnvironmentFrom)) { throw "ContinueEnvironmentFrom requires Task or AppName, without ResumeEnvironmentFrom." }
if ($ManualGroundTruth) {
    if ($Serial -or $IosUdid -or $DurationSeconds -or $PSBoundParameters.ContainsKey('AttributionMode')) {
        throw "Manual ground truth uses operator labels and device IP traffic; omit Serial, IosUdid, DurationSeconds and AttributionMode."
    }
    $command = @(
        "-m", "collection.runtime.mobile_control", "manual",
        "--out", $RootOut,
        "--router-user", $RouterUser,
        "--router-interface", $RouterInterface,
        "--collection-task-id", $CollectionTaskId
    )
    if ($EventMarkerOnly) { $command += '--marker-only' }
} elseif ($BackgroundScenario) {
    if ($DurationSeconds -le 0) {
        throw "Background scenario collection requires positive -DurationSeconds."
    }
    if (-not $IosUdid) {
        throw "Background scenario collection requires -IosUdid."
    }
    $command = @(
        "-m", "collection.runtime.mobile_control", "collect-background",
        "--scenario", $BackgroundScenario,
        "--duration-seconds", [string]$DurationSeconds,
        "--out", $RootOut,
        "--wda-url", $WdaUrl,
        "--router-user", $RouterUser,
        "--router-interface", $RouterInterface,
        "--collection-task-id", $CollectionTaskId
    )
} else {
    $sourceArguments = @()
    if ($Task) {
    $resolvedTask = (Resolve-Path -LiteralPath $Task).Path
    $taskPayload = Get-Content -LiteralPath $resolvedTask -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$taskPayload.platform -notin @("android", "ios")) {
        throw "Task platform must be 'android' or 'ios'."
    }
    if (-not [string]$taskPayload.app_name) {
        throw "Task must declare app_name."
    }
    if ([string]$taskPayload.platform -eq "android" -and -not $Serial -and -not $Preview) {
        throw "Android task collection requires -Serial."
    }
    $sourceArguments = @("--task", $resolvedTask)
    } else {
        $sourceArguments = @("--app-name", $AppName)
    }
    $command = @(
        "-m", "collection.runtime.mobile_control", "collect",
        "--out", $RootOut,
        "--wda-url", $WdaUrl,
        "--router-user", $RouterUser,
        "--router-interface", $RouterInterface,
        "--attribution-mode", $AttributionMode,
        "--collection-task-id", $CollectionTaskId
    ) + $sourceArguments
    $command += @("--environment-operator", $EnvironmentOperator)
    if ($Preview) { $command += "--preview" }
    if ($ResumeEnvironmentFrom) { $command += @("--resume-environment-from", (Resolve-Path -LiteralPath $ResumeEnvironmentFrom).Path) }
    if ($ContinueEnvironmentFrom) { $command += @("--continue-environment-from", (Resolve-Path -LiteralPath $ContinueEnvironmentFrom).Path) }
}
if ($RouterHost) { $command += @("--router-host", $RouterHost) }
if ($RouterIdentity) { $command += @("--router-identity", $RouterIdentity) }
if ($PhoneIp) {
    $command += @("--phone-ip", $PhoneIp)
}
if ($Serial) {
    $command += @("--serial", $Serial)
}
if ($IosUdid) {
    $command += @("--udid", $IosUdid)
}

& $PythonExecutable @command
if ($LASTEXITCODE -ne 0) {
    throw "Unified mobile collection failed with exit code $LASTEXITCODE"
}
