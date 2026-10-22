# Active Directory Threat Detection Lab

A self-built Windows Active Directory environment used to practice directory administration, Group Policy hardening, and attack detection through log analysis in Splunk. Built from scratch, hardened, then attacked — with each attack traced through to the events it produced.

**Status:** Ongoing — started July 2026
**Author:** John Smith Jr

> All testing was performed by me against my own lab, on an isolated host-only virtual network. Nothing here was run against any system I do not own.

## Overview

This lab simulates a small enterprise Windows domain and the telemetry a defender has to work with. I wanted three things from it:

1. Hands-on Active Directory administration — users, groups, OUs, and Group Policy — beyond what an IT support role exposes you to.
2. A feel for which attacks leave which artifacts, and where.
3. Practice writing Splunk searches against real events I generated, rather than a canned dataset.

The most useful outcome wasn't a detection that worked — it was finding an attack my logging *didn't* catch, documented under Findings below.

## Environment

| Host | Role | OS | Notes |
| --- | --- | --- | --- |
| `DC01` | Domain controller | Windows Server 2022 | AD DS, DNS |
| `WIN11-01` | Domain-joined workstation | Windows 11 | Standard user endpoint |
| `KALI-01` | Attacker | Kali Linux | Same subnet, unauthenticated start |
| `SPLUNK-01` | Log aggregation | Splunk (dedicated VM) | Universal Forwarder on DC01 and WIN11-01 |

- **Domain:** `homelab.local`
- **Hypervisor:** VMware Workstation Pro
- **Network:** host-only / isolated — attack traffic stays inside the lab
- **Endpoint telemetry:** Sysmon with the SwiftOnSecurity configuration on `DC01` and `WIN11-01`, forwarded to Splunk alongside the Windows Security log

## Build

### 1. Domain controller

Promoted a clean Windows Server 2022 install to a domain controller for a new forest.

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "homelab.local" -InstallDNS
```

### 2. Organizational units and users

Built an OU structure mirroring a small company rather than leaving everything in the default `Users` container, and created 10–15 test accounts with PowerShell so the build is repeatable and reviewable. The script is in `scripts/New-LabUsers.ps1` (sanitized — no real passwords committed).

```
homelab.local
├── OU=Users            (IT, HR, Finance test accounts)
├── OU=Workstations     (WIN11-01)
├── OU=Servers          (DC01)
└── OU=ServiceAccounts  (dedicated service identities)
```

### 3. Group Policy hardening

Controls I configured and verified:

| Control | What I set | Why |
| --- | --- | --- |
| Password & lockout policy | Minimum length/complexity; lockout threshold and duration | Make credential-guessing expensive and make spraying visible when it trips lockout |
| PowerShell script-block logging | Event ID 4104 to the PowerShell/Operational log | Capture what attacker scripts actually do, not just that PowerShell ran |
| Audit policy | Logon/logoff, account logon, and account management auditing | Produce the 4624/4625/4740 events the detections below depend on |

Each of these is a control I *configured* — a different thing from a threat I can *detect*. The detection section keeps that distinction explicit.

### 4. Logging pipeline

Universal Forwarder on `DC01` and `WIN11-01` forwarding to `SPLUNK-01`.

| Source | Sourcetype | What it catches |
| --- | --- | --- |
| Windows Security log | `WinEventLog:Security` | Authentication, lockout, account management |
| PowerShell Operational | `WinEventLog:Microsoft-Windows-PowerShell/Operational` | Script-block logging (4104) |
| Sysmon | `WinEventLog:Microsoft-Windows-Sysmon/Operational` | Process creation (1), network connections (3), and more |

## Attack scenarios

### Scenario 1 — Password spray

**Objective.** Confirm low-and-slow credential guessing shows up in the logs, and that the lockout policy behaves as configured.

**Method.** From `KALI-01`, attempted a small set of common passwords across the lab accounts.

**What it produced.** A cluster of `EventCode=4625` (failed logon) events across multiple accounts from a single source, followed by `EventCode=4740` (account lockout) once an account crossed the configured threshold — confirming the lockout policy fired as intended.

**Detection search.**

```
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| stats count dc(Account_Name) as targeted_accounts by Source_Network_Address, _time
| where targeted_accounts > 3
```

**Result.** Detection worked. The 4625 pattern was unmistakable, and correlating it with the 4740 lockout gave a clean before/after story: the control I configured and the event I detected lined up.

### Scenario 2 — LLMNR / Responder poisoning

**Objective.** Capture credentials off broadcast name resolution, then see whether my logging caught it.

**Method.** Ran Responder on `KALI-01` to answer LLMNR/NBT-NS queries on the subnet, captured a `WIN11-01` user's NetNTLM hash, and cracked it offline with hashcat.

**What it produced.** The capture and crack succeeded end to end. In Splunk, however, the attack was nearly invisible — see Findings.

**Result.** Attack succeeded; **detection did not.** The most useful result in the lab, written up below rather than dressed up as a win.

## Findings

- **The password spray was easy to see; the LLMNR attack was nearly invisible.** My hardening was host- and account-focused — password policy, lockout, audit logging, PowerShell logging. None of it watches the network layer where LLMNR/NBT-NS poisoning happens, so Responder captured and I cracked a credential while my Security-log-based detections showed essentially nothing.
- **A configured control is not a detection.** The lockout policy *stopped* the spray and the audit policy *showed* it. Against LLMNR I had neither — the gap wasn't a misconfiguration, it was a missing data source.
- **Closing the gap is a data problem, not a policy one.** Catching this class of attack needs network-level visibility (disabling LLMNR/NBT-NS via GPO to remove the attack surface, and/or capturing the traffic) rather than another endpoint audit setting.

## Next steps

- Disable LLMNR and NBT-NS via Group Policy and re-run Responder to confirm the attack surface is gone.
- Add Kerberoasting (4769 analysis) as a third scenario.
- Build a saved-search alert for the password-spray pattern instead of running it ad hoc.
- Expand Sysmon coverage and map detections to MITRE ATT&CK technique IDs.

## Repository structure

```
active-directory-threat-detection/
├── README.md
├── docs/
├── scripts/
│   └── New-LabUsers.ps1
├── splunk/
│   └── detection-queries.spl
└── screenshots/
```
