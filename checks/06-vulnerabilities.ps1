# Vulnerability / patch level checks

# --- Missing security updates -----------------------------------------------
$script:Checks.Add(@{
    Name = 'Missing security updates'
    Category = 'Vulnerabilities'
    Body = {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $updates = @($result.Updates)
        if ($updates.Count -eq 0) {
            New-Finding -Check 'Updates' -Category 'Vulnerabilities' -Severity 'Pass' `
                -Title 'No missing software updates reported' -Evidence 'Windows Update reports 0 pending updates.'
            return
        }
        $names = @($updates | ForEach-Object { $_.Title } | Select-Object -First 25)
        # Security-critical updates are the high-severity signal.
        $security = @($updates | Where-Object { $_.Title -match '(?i)security|critical|defender|cumulative' })
        $sev = if ($security.Count -gt 0) { 'High' } else { 'Medium' }
        New-Finding -Check 'Updates' -Category 'Vulnerabilities' -Severity $sev `
            -Title "$($updates.Count) pending update(s), $($security.Count) security-related" `
            -Evidence (($names | ForEach-Object { "- $_" }) -join "`n") `
            -Remediation 'Install pending updates: Settings > Windows Update, or: (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()' `
            -Refs 'CIS 18.x, NIST SI-2'
    }
})

# --- OS end-of-life / build currency ----------------------------------------
$script:Checks.Add(@{
    Name = 'Operating system version'
    Category = 'Vulnerabilities'
    Body = {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $build = [int]$os.BuildNumber
        $caption = $os.Caption
        # Windows 11 builds are 22000+; Windows 10 is 10240-19045; Server 2016=14393, 2019=17763, 2022=20348, 2025=26100.
        $eol = $false; $note = ''
        if ($caption -match 'Windows 10' -and $build -lt 19045) { $eol = $true; $note = 'Windows 10 build is behind the final servicing baseline.' }
        if ($caption -match 'Windows 7|Windows 8|Server 2008|Server 2012') { $eol = $true; $note = 'This OS family is end-of-life and receives no security updates.' }
        if ($build -lt 14393) { $eol = $true; $note = 'Very old build.' }
        if ($eol) {
            New-Finding -Check 'OSVer' -Category 'Vulnerabilities' -Severity 'High' `
                -Title "Unsupported / outdated OS: $caption (build $build)" `
                -Evidence $note -Remediation 'Upgrade to a supported, patched Windows release.' `
                -Refs 'NIST SI-2'
        }
        else {
            New-Finding -Check 'OSVer' -Category 'Vulnerabilities' -Severity 'Pass' `
                -Title "Supported OS: $caption (build $build)" -Evidence "Version $($os.Version), build $build"
        }
    }
})

# --- Third-party / potentially risky software inventory ----------------------
$script:Checks.Add(@{
    Name = 'Installed software inventory'
    Category = 'Vulnerabilities'
    Body = {
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $apps = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher -Unique

        # Known-risky / commonly-outdated families worth flagging for patch review.
        $riskyPatterns = '(?i)(java|jre|jdk|adobe (reader|acrobat|flash)|7-?zip|winrar|vlc|chrome|firefox|flash|quicktime|teamviewer|anydesk|log4j|putty|notepad\+\+|python|node\.js|wireshark)'
        $risky = @($apps | Where-Object { $_.DisplayName -match $riskyPatterns })
        $total = @($apps).Count

        New-Finding -Check 'Software' -Category 'Vulnerabilities' -Severity 'Info' `
            -Title "$total application(s) installed; $($risky.Count) commonly-targeted families" `
            -Evidence (($risky | ForEach-Object { "- $($_.DisplayName) $($_.DisplayVersion) [$($_.Publisher)]" }) -join "`n") `
            -Remediation 'Keep browser/PDF/Java/archiver/runtime software current - these are frequent exploit targets. Remove software that is no longer used.'
    }
})

# --- Stale / unsupported .NET & runtime note --------------------------------
$script:Checks.Add(@{
    Name = 'Legacy runtime components'
    Category = 'Vulnerabilities'
    Body = {
        $legacy = @()
        foreach ($k in @(
            'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727',
            'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\NET Framework Setup\NDP\v2.0.50727',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\NET Framework Setup\NDP\v3.5'
        )) {
            if (Test-Path $k) { $legacy += (Split-Path $k -Leaf) }
        }
        if ($legacy.Count -gt 0) {
            New-Finding -Check 'LegacyRuntime' -Category 'Vulnerabilities' -Severity 'Low' `
                -Title 'Legacy .NET Framework 2.0/3.5 components present' `
                -Evidence ("Installed: " + (($legacy | Select-Object -Unique) -join ', ')) `
                -Remediation 'If no application requires .NET 2.0/3.5, remove the feature: Disable-WindowsOptionalFeature -Online -FeatureName NetFx3'
        }
        else {
            New-Finding -Check 'LegacyRuntime' -Category 'Vulnerabilities' -Severity 'Pass' `
                -Title 'No legacy .NET 2.0/3.5 components detected' -Evidence 'Modern .NET only.'
        }
    }
})

# --- Dangerous PowerShell logging (audit visibility) ------------------------
$script:Checks.Add(@{
    Name = 'PowerShell script-block logging'
    Category = 'Vulnerabilities'
    Body = {
        $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        $v = Get-RegValue -Path $k -Name 'EnableScriptBlockLogging'
        if ($v -ne 1) {
            New-Finding -Check 'PSLogging' -Category 'Vulnerabilities' -Severity 'Low' `
                -Title 'PowerShell script-block logging is not enabled' `
                -Evidence 'EnableScriptBlockLogging is not set - malicious PowerShell is harder to detect after the fact.' `
                -Remediation 'Enable script-block logging (Event ID 4104) to capture PowerShell execution for detection/IR.' `
                -Refs 'MITRE ATT&CK T1059.001, T1562.002'
        }
        else {
            New-Finding -Check 'PSLogging' -Category 'Vulnerabilities' -Severity 'Pass' `
                -Title 'PowerShell script-block logging is enabled' -Evidence 'EnableScriptBlockLogging=1'
        }
    }
})
