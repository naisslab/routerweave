param(
    [Parameter(Mandatory = $true)]
    [string]$CollectionTaskId,
    [Parameter(Mandatory = $true)]
    [string]$RunRoot,
    [Parameter(Mandatory = $true)]
    [string]$PythonModule,
    [ValidateSet("iot", "generic")]
    [string]$Kind = "iot",
    [string]$Platform = "generic",
    [int]$SuccessUnits = 0,
    [ValidateSet("", "validation", "formal", "review")]
    [string]$ArtifactPurpose = "",
    [string[]]$CollectorArguments = @()
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $repo
$env:PYTHONPATH = (Join-Path $repo "src") + [IO.Path]::PathSeparator + $repo

$arguments = @(
    "-m", "collection.runtime.registry.tasks", "run",
    "--task-id", $CollectionTaskId,
    "--run-root", $RunRoot,
    "--kind", $Kind,
    "--platform", $Platform,
    "--success-units", [string]$SuccessUnits
)
if ($ArtifactPurpose) { $arguments += @("--purpose", $ArtifactPurpose) }
$arguments += @(
    "--",
    "python", "-m", $PythonModule,
    "--run-root", $RunRoot
) + $CollectorArguments

& python @arguments
exit $LASTEXITCODE
