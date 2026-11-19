param(
    [Parameter(Mandatory = $true)]
    [string]$CollectionTaskId,
    [string]$Plan = "configs\plans\windows_behavior.json",
    [double]$DurationSeconds = 0,
    [int]$SampleIntervalMs = 1000,
    [int]$Seed = -1,
    [string]$CategoryId = "",
    [string]$TargetName = "",
    [string]$ResumeEnvironmentFrom = "",
    [string]$ContinueEnvironmentFrom = "",
    [ValidateSet("human", "agent")][string]$EnvironmentOperator = "human",
    [string]$ExistingEdgeProfile = "",
    [switch]$UseExistingEdge,
    [switch]$BackgroundControlOnly,
    [switch]$TolerateForegroundInterruptions,
    [switch]$AllowBrowsingArticleRedirects,
    [string]$ExistingEdgeTabId = "",
    [string]$BrowserControlDir = "",
    [string]$NativeControlDir = "",
    [ValidateSet("", "desktop_idle", "locked_session")][string]$BackgroundScenario = "",
    [double]$SessionSeconds = 0,
    [double]$MinimumAcceptedSeconds = 0,
    [switch]$SingleSession,
    [switch]$RequireMediaProbe,
    [double]$MediaPollSeconds = 0,
    [string]$RootOut = "",
    [switch]$NoAutomation,
    [Alias("Preview")][switch]$DryRun,
    [switch]$EnableRouterCapture,
    [switch]$ProcessAttribution,
    [string]$RouterHost = $env:ROUTERWEAVE_ROUTER_HOST,
    [int]$RouterPort = 22,
    [string]$RouterUser = "root",
    [string]$RouterInterface = "br-lan",
    [string]$RouterIdentity = $env:ROUTERWEAVE_SSH_KEY,
    [string]$DeviceIp = "",
    [string]$BpfFilter = "",
    [int]$SnaplenBytes = 262144,
    [int]$RotationSizeMb = 256
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo
$env:PYTHONPATH = (Join-Path $repo "src") + [IO.Path]::PathSeparator + $repo

$arguments = @(
    "-m", "collection.runtime.windows.capture",
    "--plan", $Plan,
    "--sample-interval-ms", [string]$SampleIntervalMs,
    "--router-port", [string]$RouterPort,
    "--router-user", $RouterUser,
    "--router-interface", $RouterInterface,
    "--snaplen-bytes", [string]$SnaplenBytes,
    "--rotation-size-mb", [string]$RotationSizeMb,
    "--collection-task-id", $CollectionTaskId
)
$arguments += @("--environment-operator", $EnvironmentOperator)
if ($RouterHost) { $arguments += @("--router-host", $RouterHost) }
if ($RouterIdentity) { $arguments += @("--router-identity", $RouterIdentity) }
if ($DurationSeconds -gt 0) { $arguments += @("--duration-seconds", [string]$DurationSeconds) }
if ($Seed -ge 0) { $arguments += @("--seed", [string]$Seed) }
if ($CategoryId) { $arguments += @("--category-id", $CategoryId) }
if ($TargetName) { $arguments += @("--target-name", $TargetName) }
if ($ResumeEnvironmentFrom) { $arguments += @("--resume-environment-from", $ResumeEnvironmentFrom) }
if ($ContinueEnvironmentFrom -and $ResumeEnvironmentFrom) { throw "Recovery and continuation cannot be combined." }
if ($ContinueEnvironmentFrom) { $arguments += @("--continue-environment-from", $ContinueEnvironmentFrom) }
if ($ExistingEdgeProfile) { $arguments += @("--existing-edge-profile", $ExistingEdgeProfile) }
if ($UseExistingEdge) { $arguments += "--use-existing-edge" }
if ($BackgroundControlOnly) { $arguments += "--background-control-only" }
if ($TolerateForegroundInterruptions) { $arguments += "--tolerate-foreground-interruptions" }
if ($AllowBrowsingArticleRedirects) { $arguments += "--allow-browsing-article-redirects" }
if ($ExistingEdgeTabId) { $arguments += @("--existing-edge-tab-id", $ExistingEdgeTabId) }
if ($BrowserControlDir) { $arguments += @("--browser-control-dir", $BrowserControlDir) }
if ($NativeControlDir) { $arguments += @("--native-control-dir", $NativeControlDir) }
if ($BackgroundScenario) { $arguments += @("--background-scenario", $BackgroundScenario) }
if ($SessionSeconds -gt 0) { $arguments += @("--session-seconds", [string]$SessionSeconds) }
if ($MinimumAcceptedSeconds -gt 0) { $arguments += @("--minimum-accepted-seconds", [string]$MinimumAcceptedSeconds) }
if ($SingleSession) { $arguments += "--single-session" }
if ($RequireMediaProbe) { $arguments += "--require-media-probe" }
if ($MediaPollSeconds -gt 0) { $arguments += @("--media-poll-seconds", [string]$MediaPollSeconds) }
if ($RootOut) { $arguments += @("--out", $RootOut) }
if ($DeviceIp) { $arguments += @("--device-ip", $DeviceIp) }
if ($BpfFilter) { $arguments += @("--bpf-filter", $BpfFilter) }
if ($NoAutomation) { $arguments += "--no-automation" }
if ($DryRun) { $arguments += "--dry-run" }
if ($EnableRouterCapture) { $arguments += "--enable-router-capture" }
if ($ProcessAttribution) { $arguments += "--process-attribution" }

& python @arguments
exit $LASTEXITCODE
