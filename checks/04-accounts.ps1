# Account & authentication hygiene checks

# --- Guest account -----------------------------------------------------------
$script:Checks.Add(@{
    Name = 'Guest account state'
    Category = 'Accounts'
    Body = {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if (-not $guest) {
            return (New-Finding -Check 'Guest' -Category 'Accounts' -Severity 'Pass' `
                -Title 'Guest account is not present' -Evidence 'No local Guest account.')
        }
        if ($guest.Enabled) {
            New-Finding -Check 'Guest' -Category 'Accounts' -Severity 'High' `
                -Title 'Guest account is enabled' `
                -Evidence 'The built-in Guest account is active and can be used anonymously.' `
                -Remediation 'Disable it: Disable-LocalUser -Name Guest' `
                -Refs 'CIS 2.3.1.2'
        }
        else {
            New-Finding -Check 'Guest' -Category 'Accounts' -Severity 'Pass' `
                -Title 'Guest account is disabled' -Evidence 'Guest.Enabled=False'
        }
    }
})

# --- Local administrator group membership -----------------------------------
$script:Checks.Add(@{
    Name = 'Local Administrators membership'
    Category = 'Accounts'
    Body = {
        $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        $names = @($admins | ForEach-Object { $_.Name })
        # Flag unexpected/enabled local admin accounts beyond the usual suspects.
        $baseline = @('Administrator','Domain Admins','Enterprise Admins')
        $extra = @($names | Where-Object { $n = $_; -not ($baseline | Where-Object { $n -like "*$_" }) })
        $sev = if ($extra.Count -gt 2) { 'Medium' } else { 'Low' }
        New-Finding -Check 'Admins' -Category 'Accounts' -Severity $sev `
            -Title "Local Administrators group has $($names.Count) member(s)" `
            -Evidence (($names | ForEach-Object { "- $_" }) -join "`n") `
            -Remediation 'Enforce least privilege - remove accounts that do not require local admin. Prefer separate admin accounts.'
    }
})

# --- Accounts with blank / no password --------------------------------------
$script:Checks.Add(@{
    Name = 'Accounts without a password'
    Category = 'Accounts'
    Body = {
        $blank = Get-LocalUser -ErrorAction Stop |
            Where-Object { $_.Enabled -and $_.PasswordRequired -eq $false }
        if ($blank.Count -gt 0) {
            New-Finding -Check 'BlankPw' -Category 'Accounts' -Severity 'High' `
                -Title "$($blank.Count) enabled account(s) do not require a password" `
                -Evidence (($blank | ForEach-Object { "- $($_.Name)" }) -join "`n") `
                -Remediation 'Require passwords: Set-LocalUser -Name <user> -PasswordNeverExpires $false; and set a strong password.'
        }
        else {
            New-Finding -Check 'BlankPw' -Category 'Accounts' -Severity 'Pass' `
                -Title 'All enabled local accounts require a password' -Evidence 'No password-less enabled accounts.'
        }
    }
})

# --- Autologon credentials ---------------------------------------------------
$script:Checks.Add(@{
    Name = 'Windows Autologon'
    Category = 'Accounts'
    Body = {
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $auto = Get-RegValue -Path $key -Name 'AutoAdminLogon'
        $pw = Get-RegValue -Path $key -Name 'DefaultPassword'
        if ($auto -eq '1' -or $pw) {
            New-Finding -Check 'AutoLogon' -Category 'Accounts' -Severity 'High' `
                -Title 'Windows Autologon is configured with stored credentials' `
                -Evidence 'AutoAdminLogon is enabled and/or a DefaultPassword value is present in the registry (plaintext).' `
                -Remediation 'Remove AutoAdminLogon/DefaultPassword values. Autologon stores credentials in cleartext readable by admins.' `
                -Refs 'CIS 2.3.x'
        }
        else {
            New-Finding -Check 'AutoLogon' -Category 'Accounts' -Severity 'Pass' `
                -Title 'Autologon is not configured' -Evidence 'No AutoAdminLogon/DefaultPassword.'
        }
    }
})

# --- Password policy ---------------------------------------------------------
$script:Checks.Add(@{
    Name = 'Local password policy'
    Category = 'Accounts'
    Body = {
        $o = net accounts 2>$null
        $minLen = 0; $maxAge = 0; $lockout = 'never'
        foreach ($line in $o) {
            if ($line -match 'Minimum password length:\s+(\d+)') { $minLen = [int]$Matches[1] }
            if ($line -match 'Maximum password age \(days\):\s+(\S+)') { $maxAge = $Matches[1] }
            if ($line -match 'Lockout threshold:\s+(\S+)') { $lockout = $Matches[1] }
        }
        if ($minLen -lt 12) {
            New-Finding -Check 'PwPolicy' -Category 'Accounts' -Severity 'Medium' `
                -Title "Minimum password length is $minLen" `
                -Evidence "Minimum password length = $minLen (recommended >= 14). Lockout threshold = $lockout." `
                -Remediation 'Increase minimum length via secpol.msc or: net accounts /minpwlen:14' `
                -Refs 'CIS 1.1.4'
        }
        else {
            New-Finding -Check 'PwPolicy' -Category 'Accounts' -Severity 'Pass' `
                -Title "Minimum password length is $minLen" -Evidence "minpwlen=$minLen"
        }
        if ($lockout -eq 'Never' -or $lockout -eq 'never') {
            New-Finding -Check 'Lockout' -Category 'Accounts' -Severity 'Medium' `
                -Title 'Account lockout is not configured' `
                -Evidence 'Lockout threshold = Never - brute-force / password-spray has no lockout protection.' `
                -Remediation 'Configure an account lockout policy (e.g. threshold 5-10 attempts) via secpol.msc.'
        }
        else {
            New-Finding -Check 'Lockout' -Category 'Accounts' -Severity 'Pass' `
                -Title "Account lockout threshold is $lockout" -Evidence "LockoutThreshold=$lockout"
        }
    }
})

# --- UAC ---------------------------------------------------------------------
$script:Checks.Add(@{
    Name = 'User Account Control (UAC)'
    Category = 'Accounts'
    Body = {
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $lua = Get-RegValue -Path $key -Name 'EnableLUA'
        $cba = Get-RegValue -Path $key -Name 'ConsentPromptBehaviorAdmin'
        if ($null -eq $lua) { return $null }
        $issues = @()
        if ($lua -ne 1)      { $issues += 'EnableLUA is not 1 (UAC disabled)' }
        if ($cba -eq 0) { $issues += 'Admins elevate without prompting (ConsentPromptBehaviorAdmin=0)' }
        if ($issues.Count -gt 0) {
            New-Finding -Check 'UAC' -Category 'Accounts' -Severity 'High' `
                -Title 'UAC is weakened' -Evidence ($issues -join '; ') `
                -Remediation 'Enable UAC (EnableLUA=1) and require admin consent (ConsentPromptBehaviorAdmin=2 or 5).' `
                -Refs 'CIS 2.3.17.x'
        }
        else {
            New-Finding -Check 'UAC' -Category 'Accounts' -Severity 'Pass' `
                -Title 'UAC is enabled and prompts administrators' `
                -Evidence "EnableLUA=$lua, ConsentPromptBehaviorAdmin=$cba"
        }
    }
})

# --- Anonymous SMB / share enumeration --------------------------------------
$script:Checks.Add(@{
    Name = 'Anonymous SMB access'
    Category = 'Accounts'
    Body = {
        $ra  = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous'
        $ras = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM'
        if ($null -eq $ra -and $null -eq $ras) { return $null }
        $issues = @()
        if ($ra -ne 1) { $issues += 'RestrictAnonymous is not 1' }
        if ($ras -ne 1) { $issues += 'RestrictAnonymousSAM is not 1' }
        if ($issues.Count -gt 0) {
            New-Finding -Check 'AnonSMB' -Category 'Accounts' -Severity 'Medium' `
                -Title 'Anonymous SMB access is not fully restricted' `
                -Evidence ($issues -join '; ') `
                -Remediation 'Set RestrictAnonymous=1 and RestrictAnonymousSAM=1 under HKLM:\SYSTEM\CurrentControlSet\Control\Lsa.' `
                -Refs 'CIS 2.3.10.x'
        }
        else {
            New-Finding -Check 'AnonSMB' -Category 'Accounts' -Severity 'Pass' `
                -Title 'Anonymous SMB access is restricted' -Evidence 'RestrictAnonymous=1, RestrictAnonymousSAM=1'
        }
    }
})

# --- Shared folders ----------------------------------------------------------
$script:Checks.Add(@{
    Name = 'SMB shares exposed'
    Category = 'Accounts'
    Body = {
        $shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notlike '*$' }
        if ($shares.Count -eq 0) {
            return (New-Finding -Check 'Shares' -Category 'Accounts' -Severity 'Pass' `
                -Title 'No user-defined SMB shares' -Evidence 'Only default administrative shares exist.')
        }
        $ev = ($shares | ForEach-Object { "$($_.Name) -> $($_.Path)" }) -join "`n"
        New-Finding -Check 'Shares' -Category 'Accounts' -Severity 'Low' `
            -Title "$($shares.Count) SMB share(s) exposed" -Evidence $ev `
            -Remediation 'Confirm each share is intended and its ACL restricts access to authorised principals.'
    }
})
