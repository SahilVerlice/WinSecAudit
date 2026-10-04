# System-level hardening checks

# --- BitLocker full-disk encryption -----------------------------------------
$script:Checks.Add(@{
    Name = 'BitLocker disk encryption'
    Category = 'System'
    Body = {
        $vols = Get-BitLockerVolume -ErrorAction Stop |
                Where-Object { $_.VolumeType -eq 'OperatingSystem' }
        if (-not $vols) { return $null }
        foreach ($v in $vols) {
            $status = [string]$v.ProtectionStatus
            if ($status -ne 'On') {
                New-Finding -Check 'BitLocker' -Category 'System' -Severity 'High' `
                    -Title "System drive $($v.MountPoint) is not encrypted" `
                    -Evidence "ProtectionStatus=$status, EncryptionPercentage=$($v.EncryptionPercentage)%" `
                    -Remediation 'Enable BitLocker: Settings > Privacy & security > Device encryption, or run: Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -TpmProtector' `
                    -Refs 'CIS 3.1, NIST SP 800-53 SC-28'
            }
            else {
                New-Finding -Check 'BitLocker' -Category 'System' -Severity 'Pass' `
                    -Title "System drive $($v.MountPoint) is encrypted" `
                    -Evidence "EncryptionMethod=$($v.EncryptionMethod), ProtectionStatus=$status"
            }
        }
    }
})

# --- Secure Boot -------------------------------------------------------------
$script:Checks.Add(@{
    Name = 'Secure Boot state'
    Category = 'System'
    Body = {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) {
            New-Finding -Check 'SecureBoot' -Category 'System' -Severity 'Pass' `
                -Title 'Secure Boot is enabled' -Evidence 'UEFI Secure Boot active.'
        }
        else {
            New-Finding -Check 'SecureBoot' -Category 'System' -Severity 'High' `
                -Title 'Secure Boot is disabled' `
                -Evidence 'Firmware reports Secure Boot off (boot integrity is not enforced).' `
                -Remediation 'Enable Secure Boot in UEFI/BIOS firmware settings.' `
                -Refs 'CIS 18.x, NIST SP 800-53 SI-7'
        }
    }
})

# --- Legacy SMBv1 protocol ---------------------------------------------------
$script:Checks.Add(@{
    Name = 'SMBv1 protocol disabled'
    Category = 'System'
    Body = {
        $s = Get-SmbServerConfiguration -ErrorAction Stop
        if ($s.EnableSMB1Protocol) {
            New-Finding -Check 'SMBv1' -Category 'System' -Severity 'High' `
                -Title 'Legacy SMBv1 protocol is enabled' `
                -Evidence 'EnableSMB1Protocol=True (EternalBlue/WannaCry vector).' `
                -Remediation 'Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' `
                -Refs 'CVE-2017-0144, CIS 2.3.9.1'
        }
        else {
            New-Finding -Check 'SMBv1' -Category 'System' -Severity 'Pass' `
                -Title 'SMBv1 is disabled' -Evidence 'EnableSMB1Protocol=False'
        }
    }
})

# --- Remote Desktop exposure -------------------------------------------------
$script:Checks.Add(@{
    Name = 'Remote Desktop (RDP) exposure'
    Category = 'System'
    Body = {
        $rdp = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
        if ($null -eq $rdp) { return $null }
        if ($rdp -eq 0) {
            $nla = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication
            $sev = if ($nla -eq 1) { 'Medium' } else { 'High' }
            $ev = "RDP enabled. Network Level Authentication (NLA) = $(if($nla -eq 1){'enabled'}else{'DISABLED'})."
            New-Finding -Check 'RDP' -Category 'System' -Severity $sev `
                -Title 'Remote Desktop is enabled' -Evidence $ev `
                -Remediation 'If RDP is not required, disable it: Set-ItemProperty ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'' fDenyTSConnections 1. Otherwise enforce NLA and restrict source IPs.' `
                -Refs 'CIS 18.9.x'
        }
        else {
            New-Finding -Check 'RDP' -Category 'System' -Severity 'Pass' `
                -Title 'Remote Desktop is disabled' -Evidence 'fDenyTSConnections=1'
        }
    }
})

# --- Windows Script Host / macro-style execution -----------------------------
$script:Checks.Add(@{
    Name = 'Windows Script Host enabled'
    Category = 'System'
    Body = {
        $wsh = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -ErrorAction SilentlyContinue
        if ($null -eq $wsh) {
            New-Finding -Check 'WSH' -Category 'System' -Severity 'Info' `
                -Title 'Windows Script Host is enabled (default)' `
                -Evidence 'WSH not disabled; .vbs/.js files can execute. Common malware vector.' `
                -Remediation 'If not needed, disable WSH: New-ItemProperty ''HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'' Enabled -Value 0'
        }
        elseif ($wsh.Enabled -eq 0) {
            New-Finding -Check 'WSH' -Category 'System' -Severity 'Pass' `
                -Title 'Windows Script Host is disabled' -Evidence 'Enabled=0'
        }
    }
})

# --- Autorun / AutoPlay ------------------------------------------------------
$script:Checks.Add(@{
    Name = 'AutoRun for all drives disabled'
    Category = 'System'
    Body = {
        $v = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun
        if ($v -eq 0xFF) {
            New-Finding -Check 'AutoRun' -Category 'System' -Severity 'Pass' `
                -Title 'AutoRun disabled for all drive types' -Evidence 'NoDriveTypeAutoRun=0xFF'
        }
        else {
            New-Finding -Check 'AutoRun' -Category 'System' -Severity 'Low' `
                -Title 'AutoRun is not disabled for all drives' `
                -Evidence "NoDriveTypeAutoRun=$(if($null -eq $v){'<not set>'}else{$v})" `
                -Remediation 'Set NoDriveTypeAutoRun=0xFF under HKLM:\...\Policies\Explorer to block USB autorun.' `
                -Refs 'CIS 18.7.x'
        }
    }
})

# --- Windows Update service health ------------------------------------------
$script:Checks.Add(@{
    Name = 'Windows Update service running'
    Category = 'System'
    Body = {
        $svc = Get-Service -Name wuauserv -ErrorAction Stop
        if ($svc.Status -ne 'Running') {
            New-Finding -Check 'WinUpdateSvc' -Category 'System' -Severity 'Medium' `
                -Title 'Windows Update service is not running' `
                -Evidence "wuauserv status=$($svc.Status), StartType=$($svc.StartType)" `
                -Remediation 'Set the service back to Manual/Automatic and start it: Set-Service wuauserv -StartupType Manual; Start-Service wuauserv'
        }
        else {
            New-Finding -Check 'WinUpdateSvc' -Category 'System' -Severity 'Pass' `
                -Title 'Windows Update service is running' -Evidence 'wuauserv=Running'
        }
    }
})

# --- PowerShell execution policy --------------------------------------------
$script:Checks.Add(@{
    Name = 'PowerShell execution policy'
    Category = 'System'
    Body = {
        $p = Get-ExecutionPolicy -Scope LocalMachine
        if ($p -in @('Unrestricted','Bypass')) {
            New-Finding -Check 'ExecPolicy' -Category 'System' -Severity 'Medium' `
                -Title "PowerShell execution policy is $p" `
                -Evidence "LocalMachine scope = $p" `
                -Remediation 'Set a stricter policy: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine' `
                -Refs 'CIS 18.10.x'
        }
        else {
            New-Finding -Check 'ExecPolicy' -Category 'System' -Severity 'Pass' `
                -Title "PowerShell execution policy is $p" -Evidence "LocalMachine scope = $p"
        }
    }
})
