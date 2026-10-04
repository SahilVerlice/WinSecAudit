<#
.SYNOPSIS
    WinSecAudit - local Windows security posture auditor with a web dashboard.

.DESCRIPTION
    Scans the local Windows host against a curated set of CIS-aligned hardening
    controls, then serves an interactive security report in your browser.

    Read-only: no system changes, no data leaves the machine.

.PARAMETER NoBrowser
    Do not open a browser automatically.

.PARAMETER NoServe
    Only generate the report files; do not start the local web server.

.PARAMETER Port
    Port for the local dashboard (default: random free port).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\start.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\start.ps1 -NoServe
#>
[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [switch]$NoServe,
    [int]$Port = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root 'lib/Engine.ps1')
. (Join-Path $root 'lib/Server.ps1')

$script:TemplatePath = Join-Path $root 'web/report.html'
$checksPath = Join-Path $root 'checks'

$outDir = Join-Path $root 'reports'
$stamp  = (Get-Date).ToString('yyyyMMdd-HHmmss')
$jsonPath = Join-Path $outDir "winsecaudit-$stamp.json"
$htmlPath = Join-Path $outDir "winsecaudit-$stamp.html"

# Run the scan.
$report = Invoke-WinSecAudit -ChecksPath $checksPath -ReportPath $jsonPath
if ($null -eq $report) { exit 1 }

# Render the standalone HTML report.
Save-HtmlReport -Report $report -Path $htmlPath

if ($NoServe) {
    Write-Host "  Open the report file in a browser:" -ForegroundColor Cyan
    Write-Host "  $htmlPath" -ForegroundColor Cyan
    exit 0
}

# Serve + open the dashboard.
Start-ReportServer -HtmlPath $htmlPath -JsonPath $jsonPath -NoBrowser:$NoBrowser -Port $Port
