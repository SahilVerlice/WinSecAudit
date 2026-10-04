# Persistence & autostart inspection (malware TTP surface)
# These are the places malware commonly uses to survive reboot.

# --- Registry Run keys -------------------------------------------------------
$script:Checks.Add(@{
    Name = 'Registry Run keys'
    Category = 'Persistence'
    Body = {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        )
        $items = @()
        foreach ($k in $keys) {
            if (-not (Test-Path $k)) { continue }
            $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                $items += "$k :: $($p.Name) = $($p.Value)"
            }
        }
        if ($items.Count -eq 0) {
            New-Finding -Check 'RunKeys' -Category 'Persistence' -Severity 'Pass' `
                -Title 'No autostart Run key entries found' -Evidence 'Run/RunOnce keys empty.'
        }
        else {
            # Flag entries pointing at user-writable / temp locations (common malware).
            $susp = @($items | Where-Object { $_ -match '(?i)\\(AppData|Temp|Users\\Public|ProgramData)\\|\.(vbs|js|jse|bat|cmd|ps1|scr)\b' })
            $sev = if ($susp.Count -gt 0) { 'High' } else { 'Low' }
            $ev = ($items | ForEach-Object { "- $_" }) -join "`n"
            if ($susp.Count -gt 0) { $ev += "`n`nSUSPICIOUS (user-writable/script paths):`n" + (($susp | ForEach-Object { "  ! $_" }) -join "`n") }
            New-Finding -Check 'RunKeys' -Category 'Persistence' -Severity $sev `
                -Title "$($items.Count) autostart Run entry(ies)$(if($susp.Count){" - $($susp.Count) look suspicious"})" `
                -Evidence $ev `
                -Remediation 'Verify each entry against the software you installed. Remove anything unrecognised, especially scripts running from AppData/Temp.' `
                -Refs 'MITRE ATT&CK T1547.001'
        }
    }
})

# --- Winlogon helper hijack --------------------------------------------------
$script:Checks.Add(@{
    Name = 'Winlogon helper values'
    Category = 'Persistence'
    Body = {
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $shell = Get-RegValue -Path $key -Name 'Shell'
        $userinit = Get-RegValue -Path $key -Name 'Userinit'
        if ($null -eq $shell -and $null -eq $userinit) { return $null }
        $expectShell = 'explorer.exe'
        $expectUserinit = 'C:\Windows\system32\userinit.exe,'
        $issues = @()
        if ($shell -and ($shell -ne $expectShell)) { $issues += "Shell = $shell (expected explorer.exe)" }
        if ($userinit -and ($userinit -notlike "$expectUserinit*")) { $issues += "Userinit = $userinit (expected $expectUserinit)" }
        if ($issues.Count -gt 0) {
            New-Finding -Check 'Winlogon' -Category 'Persistence' -Severity 'Critical' `
                -Title 'Winlogon Shell/Userinit values are non-standard (possible persistence)' `
                -Evidence ($issues -join "`n") `
                -Remediation 'Restore Shell=explorer.exe and Userinit=C:\Windows\system32\userinit.exe, - investigate what added the change.' `
                -Refs 'MITRE ATT&CK T1547.004'
        }
        else {
            New-Finding -Check 'Winlogon' -Category 'Persistence' -Severity 'Pass' `
                -Title 'Winlogon Shell/Userinit values are standard' -Evidence "Shell=$shell, Userinit=$userinit"
        }
    }
})

# --- AppInit DLLs ------------------------------------------------------------
$script:Checks.Add(@{
    Name = 'AppInit_DLLs injection'
    Category = 'Persistence'
    Body = {
        $found = @()
        foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
            if (-not (Test-Path $k)) { continue }
            $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
            if ($p.AppInit_DLLs -and $p.AppInit_DLLs.Trim() -ne '') { $found += "$k AppInit_DLLs=$($p.AppInit_DLLs)" }
            if ($p.LoadAppInit_DLLs -eq 1) { $found += "$k LoadAppInit_DLLs=1" }
        }
        if ($found.Count -gt 0) {
            New-Finding -Check 'AppInit' -Category 'Persistence' -Severity 'High' `
                -Title 'AppInit_DLLs is configured' `
                -Evidence ($found -join "`n") `
                -Remediation 'AppInit_DLLs loads a DLL into every process - almost never legitimate. Clear AppInit_DLLs and set LoadAppInit_DLLs=0.' `
                -Refs 'MITRE ATT&CK T1546.010'
        }
        else {
            New-Finding -Check 'AppInit' -Category 'Persistence' -Severity 'Pass' `
                -Title 'AppInit_DLLs is not configured' -Evidence 'No AppInit DLL injection.'
        }
    }
})

# --- Suspicious scheduled tasks ---------------------------------------------
$script:Checks.Add(@{
    Name = 'Scheduled tasks'
    Category = 'Persistence'
    Body = {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' }
        $rows = foreach ($t in $tasks) {
            $action = $t.Actions | Where-Object { $_.Execute } | Select-Object -First 1
            $exe = if ($action) { $action.Execute } else { '' }
            $arg = if ($action) { $action.Arguments } else { '' }
            [pscustomobject]@{
                Path = "$($t.TaskPath)$($t.TaskName)"
                Exec = $exe
                Args = $arg
                Susp = ($exe + ' ' + $arg) -match '(?i)(powershell|wscript|cscript|mshta|rundll32|cmd(\.exe)?\s+/c|AppData|Temp|Public|\\Downloads\\|FromBase64|-enc )'
            }
        }
        $rows = @($rows)
        $susp = @($rows | Where-Object { $_.Susp })
        if ($susp.Count -gt 0) {
            $ev = ($susp | ForEach-Object { "$($_.Path) -> $($_.Exec) $($_.Args)" }) -join "`n"
            New-Finding -Check 'Tasks' -Category 'Persistence' -Severity 'High' `
                -Title "$($susp.Count) scheduled task(s) run script/LOLBin interpreters" `
                -Evidence $ev `
                -Remediation 'Review each task. Legitimate software rarely schedules powershell/mshta/rundll32 from user-writable paths. Disable or delete suspicious tasks.' `
                -Refs 'MITRE ATT&CK T1053.005'
        }
        else {
            New-Finding -Check 'Tasks' -Category 'Persistence' -Severity 'Pass' `
                -Title "No suspicious non-Microsoft scheduled tasks ($($rows.Count) reviewed)" `
                -Evidence (($rows | Select-Object -First 10 | ForEach-Object { "- $($_.Path)" }) -join "`n")
        }
    }
})

# --- Auto-start services with suspicious paths -------------------------------
$script:Checks.Add(@{
    Name = 'Auto-start services'
    Category = 'Persistence'
    Body = {
        $svcs = Get-CimInstance Win32_Service -ErrorAction Stop |
            Where-Object { $_.StartMode -eq 'Auto' }
        # Unquoted service path with spaces is a classic privilege-escalation vector.
        $unquoted = @($svcs | Where-Object {
            $_.PathName -and $_.PathName -notmatch '^\s*"' -and $_.PathName -match '^[A-Za-z]:\\[^"]*\s+[^"]*\.exe'
        })
        $susp = @($svcs | Where-Object { $_.PathName -match '(?i)(AppData|Temp|Users\\Public|ProgramData)' })
        $issues = @()
        if ($unquoted.Count -gt 0) {
            $issues += "Unquoted service paths ($($unquoted.Count)):" + "`n" +
                (($unquoted | Select-Object -First 10 | ForEach-Object { "  - $($_.Name): $($_.PathName)" }) -join "`n")
        }
        if ($susp.Count -gt 0) {
            $issues += "Services running from user-writable paths ($($susp.Count)):" + "`n" +
                (($susp | Select-Object -First 10 | ForEach-Object { "  - $($_.Name): $($_.PathName)" }) -join "`n")
        }
        if ($issues.Count -gt 0) {
            New-Finding -Check 'SvcPaths' -Category 'Persistence' -Severity 'High' `
                -Title 'Auto-start services with risky binary paths' `
                -Evidence ($issues -join "`n`n") `
                -Remediation 'Quote unquoted service binary paths and move services out of user-writable directories.' `
                -Refs 'MITRE ATT&CK T1543.003, CWE-428'
        }
        else {
            New-Finding -Check 'SvcPaths' -Category 'Persistence' -Severity 'Pass' `
                -Title 'No auto-start services with risky paths' -Evidence "$($svcs.Count) auto-start services checked."
        }
    }
})

# --- Startup folders ---------------------------------------------------------
$script:Checks.Add(@{
    Name = 'Startup folder contents'
    Category = 'Persistence'
    Body = {
        $folders = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
            "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        $files = foreach ($f in $folders) {
            if (Test-Path $f) { Get-ChildItem $f -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } }
        }
        $files = @($files)
        if ($files.Count -eq 0) {
            New-Finding -Check 'StartupFolder' -Category 'Persistence' -Severity 'Pass' `
                -Title 'Startup folders are empty' -Evidence 'No startup items.'
        }
        else {
            New-Finding -Check 'StartupFolder' -Category 'Persistence' -Severity 'Low' `
                -Title "$($files.Count) item(s) in Startup folders" `
                -Evidence (($files | ForEach-Object { "- $_" }) -join "`n") `
                -Remediation 'Confirm each startup item is expected; remove unrecognised shortcuts/scripts.'
        }
    }
})
