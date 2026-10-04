# WinSecAudit - Core engine
# Windows security posture auditor. Read-only. No admin required.
# The scan engine is Windows-only; the HTML report renderer is cross-platform
# (so it can be developed/tested on Linux with PowerShell 7).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:WinSecVersion = '1.0.0'

# Registry of checks contributed by the files in /checks.
$script:Checks = [System.Collections.Generic.List[object]]::new()
# Path to the HTML template (set by the entry-point script).
$script:TemplatePath = $null

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------
function New-Finding {
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info','Pass')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Evidence = '',
        [string]$Remediation = '',
        [string]$Refs = '',
        [bool]$Skipped = $false
    )
    [pscustomobject]@{
        Check       = $Check
        Category    = $Category
        Severity    = $Severity
        Title       = $Title
        Evidence    = $Evidence
        Remediation = $Remediation
        Refs        = $Refs
        Skipped     = $Skipped
    }
}

# Severity weights used for the posture score.
$script:SeverityWeight = @{ Critical = 40; High = 18; Medium = 7; Low = 2; Info = 0; Pass = 0 }

function Add-Finding {
    param([Parameter(Mandatory)][object]$Report, [Parameter(Mandatory)][object]$Finding)
    $Report.Findings.Add($Finding) | Out-Null
}

function Get-RegValue {
    <#
      Safely read a registry value. Returns $null if the key or value is absent.
      Needed because under Set-StrictMode accessing a missing property on the
      object returned by Get-ItemProperty throws - which would make a check skip
      silently instead of reporting a finding.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $null }
}

function Invoke-Check {
    <#
      Runs a single check scriptblock defensively. A check that throws or is
      unsupported on this host yields a Skipped/Info finding instead of aborting
      the whole scan. Every check is read-only.
    #>
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][scriptblock]$Body
    )
    Write-Host ("  [{0}] {1}" -f $Category, $Name) -ForegroundColor DarkGray
    try {
        $result = & $Body
        if ($null -eq $result) { return }
        foreach ($f in @($result)) {
            if ($null -ne $f) { Add-Finding -Report $Report -Finding $f }
        }
    }
    catch {
        Add-Finding -Report $Report -Finding (New-Finding -Check $Name -Category $Category `
            -Severity 'Info' -Skipped $true `
            -Title "Check could not complete on this host" `
            -Evidence ($_.Exception.Message) `
            -Remediation 'Run WinSecAudit as an administrator for full coverage.')
    }
}

# ---------------------------------------------------------------------------
# Posture score  (0-100, higher is safer)
# ---------------------------------------------------------------------------
function Get-PostureScore {
    param([Parameter(Mandatory)][object]$Report)
    $penalty = 0.0
    foreach ($f in $Report.Findings) {
        if ($f.Severity -eq 'Pass' -or $f.Skipped) { continue }
        $penalty += [double]$script:SeverityWeight[$f.Severity]
    }
    $score = [math]::Max(0, [math]::Round(100 - $penalty, 0))
    $grade = if ($score -ge 90) { 'A' } elseif ($score -ge 80) { 'B' } elseif ($score -ge 70) { 'C' } elseif ($score -ge 55) { 'D' } else { 'F' }
    [pscustomobject]@{ Score = $score; Grade = $grade }
}

# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
function Invoke-WinSecAudit {
    param(
        [string]$ChecksPath,
        [string]$ReportPath,
        [string]$OpenReport,
        [switch]$NoOpen
    )

    if ($env:OS -ne 'Windows_NT') {
        Write-Host "WinSecAudit: the scan engine only runs on Windows." -ForegroundColor Red
        Write-Host "Detected platform: $([System.Environment]::OSVersion.Platform)" -ForegroundColor Red
        Write-Host "Copy this folder to a Windows machine and run start.ps1 there." -ForegroundColor Yellow
        return $null
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    Write-Host ""
    Write-Host "  WinSecAudit v$script:WinSecVersion - Windows security posture audit" -ForegroundColor Cyan
    Write-Host ("  Host: {0}   User: {1}   Admin: {2}" -f $env:COMPUTERNAME, $env:USERNAME, $isAdmin) -ForegroundColor DarkGray
    Write-Host ""

    $report = [pscustomobject]@{
        Version      = $script:WinSecVersion
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Hostname     = $env:COMPUTERNAME
        Username     = $env:USERNAME
        IsAdmin      = $isAdmin
        OS           = $null
        Findings     = [System.Collections.Generic.List[object]]::new()
        Score        = $null
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $report.OS = [pscustomobject]@{
            Caption = $os.Caption
            Version = $os.Version
            Build   = $os.BuildNumber
            Arch    = $os.OSArchitecture
        }
    } catch {
        $report.OS = [pscustomobject]@{ Caption = "Unknown"; Version = ""; Build = ""; Arch = "" }
    }

    if (-not $isAdmin) {
        Add-Finding -Report $report -Finding (New-Finding -Check 'Privilege' -Category 'System' `
            -Severity 'Low' -Title 'Audit running without administrator rights' `
            -Evidence 'Some checks (BitLocker, Defender ASR, firewall profiles) will be incomplete.' `
            -Remediation 'Re-run start.ps1 from an elevated PowerShell window for full coverage.')
    }

    # Load every check file, then run each registered check.
    Get-ChildItem -Path $ChecksPath -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
        . $_.FullName
    }

    foreach ($check in $script:Checks) {
        Invoke-Check -Report $report -Name $check.Name -Category $check.Category -Body $check.Body
    }

    $report.Score = Get-PostureScore -Report $report

    # Persist JSON (raw data + report for the UI).
    $dir = Split-Path -Parent $ReportPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8
    Write-Host ""
    Write-Host ("  Report written: {0}" -f $ReportPath) -ForegroundColor Green
    Write-Host ("  Posture score: {0}/100 (grade {1})" -f $report.Score.Score, $report.Score.Grade) -ForegroundColor Green
    Write-Host ""

    return $report
}

# ---------------------------------------------------------------------------
# Embedded HTML report  (cross-platform: pure string templating)
# ---------------------------------------------------------------------------
function ConvertTo-HtmlReport {
    param([Parameter(Mandatory)][object]$Report)

    $json = $Report | ConvertTo-Json -Depth 8 -Compress
    # Avoid breaking out of the <script> block.
    $json = $json -replace '</script>', '<\/script>'
    $template = Get-Content -Path $script:TemplatePath -Raw -Encoding UTF8
    $template.Replace('__REPORT_JSON__', $json)
}

function Save-HtmlReport {
    param([Parameter(Mandatory)][object]$Report, [Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ConvertTo-HtmlReport -Report $Report | Set-Content -Path $Path -Encoding UTF8
    Write-Host ("  HTML report:   {0}" -f $Path) -ForegroundColor Green
}
