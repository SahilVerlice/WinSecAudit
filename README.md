# WinSecAudit

A local **Windows security posture auditor** with a web dashboard. It scans the
machine it runs on against a curated set of CIS-aligned hardening controls and
renders a SOC-style report in your browser.

- **Read-only** — it inspects configuration, it never changes anything.
- **Offline** — no telemetry, no network calls; the report is generated locally.
- **Zero dependencies** — pure Windows PowerShell 5.1 (built into Windows). No
  Python, Node, or package installs.

---

## Quick start

1. Copy the `WinSecAudit` folder to your Windows machine.
2. **Right-click `run.bat` → Run** (or just double-click it).

It re-launches itself elevated (accept the UAC prompt for full coverage), runs
the scan, and opens the dashboard at `http://localhost:<port>/`.

### Or run it manually

From an **elevated** PowerShell window (for BitLocker / Defender / firewall
checks):

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Options:

| Flag | Effect |
|------|--------|
| `-NoBrowser` | Don't auto-open the browser |
| `-NoServe`   | Only write the report files, don't start the server |
| `-Port 8080` | Use a specific port |

Report files are written to `reports/` as both `.html` (standalone, openable by
double-click) and `.json` (raw data).

> Running without admin still works, but BitLocker, Secure Boot, some Defender
> settings and firewall profiles will be reported as incomplete.

---

## What it checks (39 controls)

| Category | Examples |
|----------|----------|
| **System** | BitLocker encryption, Secure Boot, SMBv1, RDP exposure, AutoRun, Windows Update service, PowerShell execution policy |
| **Defender** | Real-time protection, AV/AS engines, signature age, tamper protection, cloud protection, ASR rules, exclusions |
| **Firewall** | Per-profile state, default inbound action, logging, blanket any-source allow rules, sensitive listening ports |
| **Accounts** | Guest account, admin group membership, password-less accounts, autologon creds, password/lockout policy, UAC, anonymous SMB, shares |
| **Persistence** | Run keys, Winlogon helper hijack, AppInit_DLLs, suspicious scheduled tasks, risky service paths, Startup folder |
| **Vulnerabilities** | Missing updates, OS end-of-life, installed software inventory, legacy .NET, PowerShell logging |

Each finding carries a **severity**, the raw **evidence** it was based on, a
**remediation** step, and a **reference** (CIS / NIST / MITRE ATT&CK).

## The report

- Posture **score (0–100)** and **letter grade** with an animated gauge.
- Severity tiles + per-category breakdown bars.
- Searchable, filterable findings list (by severity and category).
- **Export JSON** and **Print / PDF** buttons.

## Scoring

Starts at 100 and subtracts a weighted penalty per non-pass finding:

`Critical −40 · High −18 · Medium −7 · Low −2`

Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 55, else F.

## Extending

Add a `.ps1` file to `checks/` and append a check:

```powershell
$script:Checks.Add(@{
    Name     = 'My check'
    Category = 'System'
    Body     = {
        # return one New-Finding per issue, or $null / 'Pass' findings
        New-Finding -Check 'MyCheck' -Category 'System' -Severity 'High' `
            -Title 'Something is wrong' -Evidence 'details' -Remediation 'how to fix'
    }
})
```

Helpers available in every check: `New-Finding`, `Get-RegValue` (null-safe
registry read). Files are dot-sourced, so `$script:Checks` and any maps you
define at the top of a file are visible inside check bodies.

## Project layout

```
WinSecAudit/
├── run.bat                 # Windows double-click launcher (self-elevating)
├── start.ps1               # entry point: scan → render → serve
├── lib/
│   ├── Engine.ps1          # finding model, scoring, orchestrator, HTML render
│   └── Server.ps1          # local HttpListener dashboard server
├── checks/                 # 6 files, 39 controls
├── web/report.html         # dashboard template (data injected at render time)
└── reports/                # generated .html + .json (created on first run)
```

## Disclaimer

This is a configuration audit and indicator tool, **not** a penetration test or
a substitute for professional assessment. Validate every finding before acting.
