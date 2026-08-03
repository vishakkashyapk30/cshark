#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Orchestrates a full C-Shark capture -> export -> AI/ML analysis -> report
    pipeline, in one command.

.DESCRIPTION
    This is the kind of runbook a network engineer scripts to make a manual,
    multi-step validation process (build the tool, run a timed capture,
    export it, analyze it, write up findings) repeatable and CI/cron-friendly
    - the same shape as an Azure Automation runbook or a DevOps pipeline step
    for periodic network health checks.

    Steps:
      1. Build C-Shark (`make`) if the binary is missing or stale.
      2. Run a headless, timed capture via C-Shark's CLI mode
         (`cshark -i <Interface> -t <DurationSeconds> -o <csv> --pcap <pcap>`).
      3. Run tools/anomaly_detect.py against the exported flow CSV for
         ML-assisted anomaly triage (falls back to a stdlib-only method if
         scikit-learn isn't installed - see tools/requirements.txt).
      4. Write a single timestamped Markdown report combining the
         rule-based alert summary and the ML anomaly ranking.

    Any failed step aborts the script with a non-zero exit code and a clear
    error, so this is safe to wire into CI/cron rather than only running it
    interactively.

.PARAMETER Interface
    Network interface to capture on (e.g. eth0, en0). Required.

.PARAMETER DurationSeconds
    How long to capture before automatically stopping. Default: 30.

.PARAMETER Filter
    Optional protocol filter passed straight to C-Shark's --filter flag:
    http|https|dns|arp|tcp|udp.

.PARAMETER OutputDir
    Directory to write the CSV/PCAP exports and the Markdown report into.
    Default: ./reports/<timestamp>/

.PARAMETER RepoRoot
    Path to the C-Shark repository root. Default: the parent directory of
    this script's own location, so it works out of the box when run from
    the checked-out repo.

.EXAMPLE
    sudo pwsh ./scripts/Invoke-CSharkWorkflow.ps1 -Interface eth0 -DurationSeconds 60

.EXAMPLE
    pwsh ./scripts/Invoke-CSharkWorkflow.ps1 -Interface eth0 -Filter tcp -OutputDir ./reports/nightly
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Interface,

    [int]$DurationSeconds = 30,

    [ValidateSet("http", "https", "dns", "arp", "tcp", "udp")]
    [string]$Filter,

    [string]$OutputDir,

    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-LastExitCode {
    param([string]$StepName)
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Step failed: $StepName (exit code $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not $OutputDir) {
    $OutputDir = Join-Path $RepoRoot "reports/$timestamp"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$cshark = Join-Path $RepoRoot "cshark"
$csvPath = Join-Path $OutputDir "session_flows.csv"
$pcapPath = Join-Path $OutputDir "session.pcap"
$alertsPath = Join-Path $OutputDir "session_alerts.csv"
$jsonPath = Join-Path $OutputDir "anomalies.json"
$reportPath = Join-Path $OutputDir "report.md"

# --- Step 1: Build ---
Write-Step "Building C-Shark"
if (-not (Test-Path $cshark) -or ((Get-Item (Join-Path $RepoRoot "main.c")).LastWriteTime -gt (Get-Item $cshark -ErrorAction SilentlyContinue).LastWriteTime)) {
    Push-Location $RepoRoot
    try {
        make | Write-Host
        Assert-LastExitCode "make"
    } finally {
        Pop-Location
    }
} else {
    Write-Host "Binary is up to date, skipping build."
}

# --- Step 2: Headless capture ---
Write-Step "Capturing on '$Interface' for $DurationSeconds second(s)"
$captureArgs = @("-i", $Interface, "-t", $DurationSeconds, "-o", $csvPath, "--pcap", $pcapPath)
if ($Filter) {
    $captureArgs += @("--filter", $Filter)
}

# Packet capture needs elevated privileges; on non-Windows platforms this
# script expects to already be run under sudo (see .EXAMPLE above) rather
# than re-invoking sudo itself, to avoid surprising password prompts mid-script.
& $cshark @captureArgs | Tee-Object -FilePath (Join-Path $OutputDir "capture.log")
Assert-LastExitCode "cshark capture"

if (-not (Test-Path $csvPath)) {
    Write-Error "Capture did not produce an export at $csvPath - aborting."
    exit 1
}

# The C tool doesn't have a dedicated headless "export alerts" flag (alerts
# are printed to capture.log and echoed to the CSV/PCAP exports' summary),
# so pull the alert lines back out of the capture log for the report and for
# anomaly_detect.py's cross-reference input.
$alertLines = Select-String -Path (Join-Path $OutputDir "capture.log") -Pattern "^\s*\[(PORT_SCAN|ARP_SPOOF)\]"
"timestamp,type,details" | Out-File -FilePath $alertsPath -Encoding utf8
foreach ($line in $alertLines) {
    if ($line.Line -match "^\s*\[(?<type>PORT_SCAN|ARP_SPOOF)\]\s+(?<details>.*)$") {
        $type = $Matches['type']
        $details = $Matches['details'].Replace('"', '""')
        "$timestamp,$type,`"$details`"" | Out-File -FilePath $alertsPath -Append -Encoding utf8
    }
}

# --- Step 3: AI/ML anomaly triage ---
Write-Step "Running ML-assisted anomaly triage"
$python = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python -ErrorAction SilentlyContinue
}
if (-not $python) {
    Write-Error "python3 not found on PATH - cannot run tools/anomaly_detect.py."
    exit 1
}

$analyzeArgs = @(
    (Join-Path $RepoRoot "tools/anomaly_detect.py"),
    $csvPath,
    "--alerts", $alertsPath,
    "--json", $jsonPath
)
$analysisOutput = & $python.Source @analyzeArgs 2>&1 | Tee-Object -FilePath (Join-Path $OutputDir "analysis.log")
Assert-LastExitCode "tools/anomaly_detect.py"

# --- Step 4: Markdown report ---
Write-Step "Writing report to $reportPath"
$alertCount = ($alertLines | Measure-Object).Count

$report = @"
# C-Shark Capture Report - $timestamp

- **Interface**: $Interface
- **Duration**: $DurationSeconds seconds
- **Filter**: $(if ($Filter) { $Filter } else { "none" })
- **Flow export**: ``$csvPath``
- **PCAP export**: ``$pcapPath`` (open in Wireshark)
- **Rule-based alerts raised**: $alertCount

## Rule-Based Alerts (detect.c: port-scan / ARP-spoof)

``````
$(if ($alertCount -gt 0) { ($alertLines | ForEach-Object { $_.Line }) -join "`n" } else { "No alerts raised during this capture window." })
``````

## AI/ML Anomaly Triage (tools/anomaly_detect.py)

``````
$($analysisOutput -join "`n")
``````

Full machine-readable ranking: ``$jsonPath``
"@

$report | Out-File -FilePath $reportPath -Encoding utf8

Write-Host ""
Write-Host "Workflow complete. Report: $reportPath" -ForegroundColor Green
