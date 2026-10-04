# Windows Firewall checks

# --- Per-profile firewall state ---------------------------------------------
$script:Checks.Add(@{
    Name = 'Firewall profile state'
    Category = 'Firewall'
    Body = {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $bad = @($profiles | Where-Object { -not $_.Enabled })
        if ($bad.Count -gt 0) {
            New-Finding -Check 'FwState' -Category 'Firewall' -Severity 'High' `
                -Title "Firewall disabled on profile(s): $(($bad.Name) -join ', ')" `
                -Evidence (($profiles | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled)" }) -join "`n") `
                -Remediation 'Enable all profiles: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True' `
                -Refs 'CIS 9.1, NIST SC-7'
        }
        else {
            New-Finding -Check 'FwState' -Category 'Firewall' -Severity 'Pass' `
                -Title 'Firewall enabled on all profiles' `
                -Evidence (($profiles | ForEach-Object { "$($_.Name): Enabled=True" }) -join "`n")
        }
    }
})

# --- Default inbound action --------------------------------------------------
$script:Checks.Add(@{
    Name = 'Firewall default inbound policy'
    Category = 'Firewall'
    Body = {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $allow = @($profiles | Where-Object { $_.DefaultInboundAction -ne 'Block' })
        if ($allow.Count -gt 0) {
            New-Finding -Check 'FwInbound' -Category 'Firewall' -Severity 'High' `
                -Title "Inbound traffic not blocked by default on: $(($allow.Name) -join ', ')" `
                -Evidence (($profiles | ForEach-Object { "$($_.Name): DefaultInboundAction=$($_.DefaultInboundAction)" }) -join "`n") `
                -Remediation 'Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block' `
                -Refs 'CIS 9.2'
        }
        else {
            New-Finding -Check 'FwInbound' -Category 'Firewall' -Severity 'Pass' `
                -Title 'Inbound traffic blocked by default on all profiles' -Evidence 'DefaultInboundAction=Block'
        }
    }
})

# --- Logging ---------------------------------------------------------------
$script:Checks.Add(@{
    Name = 'Firewall logging'
    Category = 'Firewall'
    Body = {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $nolog = @($profiles | Where-Object { -not $_.LogBlocked })
        if ($nolog.Count -gt 0) {
            New-Finding -Check 'FwLog' -Category 'Firewall' -Severity 'Low' `
                -Title "Firewall blocked-packet logging disabled on: $(($nolog.Name) -join ', ')" `
                -Evidence 'LogBlocked=False - dropped traffic is not recorded for forensics.' `
                -Remediation 'Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True'
        }
        else {
            New-Finding -Check 'FwLog' -Category 'Firewall' -Severity 'Pass' `
                -Title 'Firewall blocked-packet logging is enabled' -Evidence 'LogBlocked=True'
        }
    }
})

# --- Overly permissive inbound allow rules ----------------------------------
$script:Checks.Add(@{
    Name = 'Firewall permissive inbound rules'
    Category = 'Firewall'
    Body = {
        # Inbound rules that allow traffic from any source, on any protocol/port,
        # enabled, and not part of the built-in baseline - a common weak config.
        $risky = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop |
            Where-Object { $_.Profile -ne 'NotApplicable' } |
            ForEach-Object {
                $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $af = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    Rule    = $_.DisplayName
                    Profile = [string]$_.Profile
                    Proto   = [string]$pf.Protocol
                    Port    = if ($pf.LocalPort) { ($pf.LocalPort -join ',') } else { 'Any' }
                    Remote  = if ($af.RemoteAddress) { ($af.RemoteAddress -join ',') } else { 'Any' }
                }
            } |
            Where-Object { $_.Remote -eq 'Any' -and ($_.Proto -eq 'Any' -or $_.Port -eq 'Any') }

        if ($risky.Count -gt 0) {
            $ev = ($risky | Select-Object -First 15 | ForEach-Object {
                "$($_.Rule) [profile=$($_.Profile), proto=$($_.Proto), port=$($_.Port), remote=$($_.Remote)]"
            }) -join "`n"
            New-Finding -Check 'FwRules' -Category 'Firewall' -Severity 'Medium' `
                -Title "$($risky.Count) inbound rule(s) allow any-source / any-port traffic" `
                -Evidence $ev `
                -Remediation 'Review each rule and scope RemoteAddress to a trusted subnet. Remove rules you do not recognise.'
        }
        else {
            New-Finding -Check 'FwRules' -Category 'Firewall' -Severity 'Pass' `
                -Title 'No blanket any-source inbound allow rules found' -Evidence 'All enabled inbound allow rules are scoped.'
        }
    }
})

# --- Listening TCP ports -----------------------------------------------------
$script:Checks.Add(@{
    Name = 'Exposed listening ports'
    Category = 'Firewall'
    Body = {
        # Ports bound to all interfaces (0.0.0.0 / ::) - reachable from the network.
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $_.LocalAddress -in @('0.0.0.0','::') } |
            Select-Object -Property LocalPort, OwningProcess -Unique

        $rows = foreach ($l in $listeners) {
            $proc = try { Get-Process -Id $l.OwningProcess -ErrorAction Stop } catch { $null }
            [pscustomobject]@{
                Port = $l.LocalPort
                Name = if ($proc) { $proc.ProcessName } else { "pid:$($l.OwningProcess)" }
            }
        }
        $rows = @($rows | Sort-Object Port)

        $sensitive = @(21,23,135,139,445,1433,3306,3389,5900,5985,5986,6379,27017)
        $exposed = @($rows | Where-Object { $_.Port -in $sensitive })

        if ($exposed.Count -gt 0) {
            New-Finding -Check 'Ports' -Category 'Firewall' -Severity 'Medium' `
                -Title "$($exposed.Count) sensitive port(s) listening on all interfaces" `
                -Evidence (($exposed | ForEach-Object { "port $($_.Port) -> $($_.Name)" }) -join "`n") `
                -Remediation 'Bind services to localhost or restrict with firewall rules. Ports such as 445, 3389, 5985 expose attack surface.'
        }
        else {
            New-Finding -Check 'Ports' -Category 'Firewall' -Severity 'Pass' `
                -Title 'No sensitive ports exposed on all interfaces' `
                -Evidence ("Listening (all-interfaces) ports: " + (($rows | ForEach-Object { "$($_.Port)/$($_.Name)" }) -join ', '))
        }
    }
})
