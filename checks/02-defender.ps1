# Microsoft Defender / anti-malware checks
# Requires the Defender PowerShell module (present on Windows 10/11 + Server 2016+).

# Friendly names for the ASR rule GUIDs we care about.
$script:AsrRules = @{
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Block executable content from email/webmail'
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Block Office child processes'
    '3B576869-A4EC-4529-8536-B80A7769E899' = 'Block Office creating executable content'
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Block Office injecting into other processes'
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Block obfuscated script execution'
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Block Win32 API calls from Office macros'
    '26190899-1602-49E8-8B27-EB1D0A1CE869' = 'Block Office communication app child processes'
    '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C' = 'Block Adobe Reader child processes'
    'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Block JS/VBS launching downloaded executables'
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Block credential stealing from lsass.exe'
    'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Block untrusted/unsigned processes from USB'
    'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 'Use advanced ransomware protection'
}

function Get-DefenderStatus {
    try { Get-MpComputerStatus -ErrorAction Stop } catch { $null }
}

# --- Real-time / engine health ----------------------------------------------
$script:Checks.Add(@{
    Name = 'Defender real-time protection'
    Category = 'Defender'
    Body = {
        $s = Get-DefenderStatus
        if (-not $s) {
            return (New-Finding -Check 'DefRT' -Category 'Defender' -Severity 'Info' -Skipped $true `
                -Title 'Microsoft Defender not detected' `
                -Evidence 'Get-MpComputerStatus unavailable (third-party AV, or Defender module missing).')
        }
        if (-not $s.RealTimeProtectionEnabled) {
            New-Finding -Check 'DefRT' -Category 'Defender' -Severity 'Critical' `
                -Title 'Defender real-time protection is OFF' `
                -Evidence 'RealTimeProtectionEnabled=False - the machine is actively unprotected.' `
                -Remediation 'Enable it: Set-MpPreference -DisableRealtimeMonitoring $false (or via Windows Security).' `
                -Refs 'CIS 18.9.x, NIST SI-3'
        }
        else {
            New-Finding -Check 'DefRT' -Category 'Defender' -Severity 'Pass' `
                -Title 'Defender real-time protection is enabled' -Evidence 'RealTimeProtectionEnabled=True'
        }
    }
})

# --- Anti-virus / anti-spyware engine enabled --------------------------------
$script:Checks.Add(@{
    Name = 'Defender engine enabled'
    Category = 'Defender'
    Body = {
        $s = Get-DefenderStatus
        if (-not $s) { return $null }
        if (-not ($s.AntivirusEnabled -and $s.AntispywareEnabled)) {
            New-Finding -Check 'DefEngine' -Category 'Defender' -Severity 'High' `
                -Title 'Defender antivirus/antispyware engine is disabled' `
                -Evidence "AntivirusEnabled=$($s.AntivirusEnabled), AntispywareEnabled=$($s.AntispywareEnabled)" `
                -Remediation 'Re-enable Defender AV via Windows Security or Set-MpPreference.'
        }
        else {
            New-Finding -Check 'DefEngine' -Category 'Defender' -Severity 'Pass' `
                -Title 'Defender antivirus and antispyware engines are enabled' -Evidence 'AV+AS on'
        }
    }
})

# --- Signature freshness -----------------------------------------------------
$script:Checks.Add(@{
    Name = 'Defender signature age'
    Category = 'Defender'
    Body = {
        $s = Get-DefenderStatus
        if (-not $s) { return $null }
        $age = $s.AntivirusSignatureAge
        if ($null -eq $age) { return $null }
        if ($age -gt 3) {
            New-Finding -Check 'DefSigAge' -Category 'Defender' -Severity 'Medium' `
                -Title "Defender signatures are $age days old" `
                -Evidence "AntivirusSignatureAge=$age days, LastUpdated=$($s.AntivirusSignatureLastUpdated)" `
                -Remediation 'Update signatures: Update-MpSignature' `
                -Refs 'CIS 18.9.x'
        }
        else {
            New-Finding -Check 'DefSigAge' -Category 'Defender' -Severity 'Pass' `
                -Title "Defender signatures are current ($age day(s) old)" -Evidence "SignatureAge=$age"
        }
    }
})

# --- Tamper protection -------------------------------------------------------
$script:Checks.Add(@{
    Name = 'Defender tamper protection'
    Category = 'Defender'
    Body = {
        $s = Get-DefenderStatus
        if (-not $s) { return $null }
        if ($s.IsTamperProtected -eq $true) {
            New-Finding -Check 'DefTamper' -Category 'Defender' -Severity 'Pass' `
                -Title 'Tamper protection is enabled' -Evidence 'IsTamperProtected=True'
        }
        else {
            New-Finding -Check 'DefTamper' -Category 'Defender' -Severity 'Medium' `
                -Title 'Defender tamper protection is disabled' `
                -Evidence 'IsTamperProtected=False - malware can disable Defender settings.' `
                -Remediation 'Enable tamper protection in Windows Security > Virus & threat protection settings.'
        }
    }
})

# --- Cloud-delivered protection / MAPS --------------------------------------
$script:Checks.Add(@{
    Name = 'Defender cloud protection'
    Category = 'Defender'
    Body = {
        $p = Get-MpPreference -ErrorAction Stop
        if (-not $p.MAPSReporting) {
            New-Finding -Check 'DefCloud' -Category 'Defender' -Severity 'Low' `
                -Title 'Cloud-delivered protection (MAPS) is disabled' `
                -Evidence 'MAPSReporting=0' `
                -Remediation 'Set-MpPreference -MAPSReporting Advanced'
        }
        else {
            New-Finding -Check 'DefCloud' -Category 'Defender' -Severity 'Pass' `
                -Title 'Cloud-delivered protection is enabled' -Evidence "MAPSReporting=$($p.MAPSReporting)"
        }
    }
})

# --- Attack Surface Reduction rules -----------------------------------------
$script:Checks.Add(@{
    Name = 'Defender ASR rules'
    Category = 'Defender'
    Body = {
        $p = Get-MpPreference -ErrorAction Stop
        $ids = @($p.AttackSurfaceReductionRules_Ids)
        $acts = @($p.AttackSurfaceReductionRules_Actions)
        if ($ids.Count -eq 0) {
            return (New-Finding -Check 'DefASR' -Category 'Defender' -Severity 'Medium' `
                -Title 'No Attack Surface Reduction (ASR) rules configured' `
                -Evidence 'AttackSurfaceReductionRules is empty - no ASR hardening in place.' `
                -Remediation 'Deploy ASR rules in Block mode, e.g. Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Enabled. Key rules: Block Office child processes, Block credential stealing from lsass.exe.' `
                -Refs 'MITRE ATT&CK T1566, T1059')
        }
        $enforced = 0; $audit = 0; $off = 0
        $lines = @()
        for ($i = 0; $i -lt $ids.Count; $i++) {
            $guid = ([string]$ids[$i]).ToUpper()
            $act = if ($i -lt $acts.Count) { $acts[$i] } else { 0 }
            $name = if ($script:AsrRules.ContainsKey($guid)) { $script:AsrRules[$guid] } else { $guid }
            switch ($act) {
                1 { $enforced++; $state = 'Block' }
                6 { $enforced++; $state = 'Warn' }
                2 { $audit++;    $state = 'Audit' }
                default { $off++; $state = 'Disabled' }
            }
            $lines += "$name = $state"
        }
        $sev = if ($enforced -eq 0) { 'Medium' } elseif ($enforced -lt 4) { 'Low' } else { 'Pass' }
        New-Finding -Check 'DefASR' -Category 'Defender' -Severity $sev `
            -Title "ASR rules: $enforced enforcing, $audit auditing, $off disabled" `
            -Evidence ($lines -join "`n") `
            -Remediation 'Set high-value ASR rules to Block (action 1) rather than Audit.'
    }
})

# --- Defender exclusions (potential blind spots) ----------------------------
$script:Checks.Add(@{
    Name = 'Defender exclusions'
    Category = 'Defender'
    Body = {
        $p = Get-MpPreference -ErrorAction Stop
        $paths = @($p.ExclusionPath) | Where-Object { $_ }
        $exts = @($p.ExclusionExtension) | Where-Object { $_ }
        $procs = @($p.ExclusionProcess) | Where-Object { $_ }
        $total = $paths.Count + $exts.Count + $procs.Count
        if ($total -eq 0) {
            New-Finding -Check 'DefExcl' -Category 'Defender' -Severity 'Pass' `
                -Title 'No Defender exclusions configured' -Evidence 'No exclusion paths, extensions or processes.'
        }
        else {
            $ev = @()
            if ($paths.Count) { $ev += "Paths: " + ($paths -join ', ') }
            if ($exts.Count)  { $ev += "Extensions: " + ($exts -join ', ') }
            if ($procs.Count) { $ev += "Processes: " + ($procs -join ', ') }
            New-Finding -Check 'DefExcl' -Category 'Defender' -Severity 'Medium' `
                -Title "Defender has $total exclusion(s) configured" `
                -Evidence ($ev -join "`n") `
                -Remediation 'Review exclusions - attackers commonly add broad exclusions (e.g. C:\, .exe, powershell.exe) to evade scanning.'
        }
    }
})
