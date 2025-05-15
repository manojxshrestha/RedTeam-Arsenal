# Basic Methodology - Port 512 (REXEC)

This README explores exploiting the Remote Execution (REXEC) service on port 512, focusing on using rlogin for remote access and brute-forcing credentials with the Sparta GUI.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Rlogin Access](#rlogin-access)
- [Brute-Force with Sparta GUI](#brute-force-with-sparta-gui)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

REXEC on port 512 is a legacy remote execution service, part of the Berkeley r-services (rsh, rlogin, rexec), often found on older Unix systems. It allows remote command execution but requires authentication, making it a target for credential guessing. This guide covers using rlogin to access the service and brute-forcing credentials with Sparta.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target REXEC server.
- **Tools**: Install rsh-client (e.g., `apt install rsh-client` on Debian-based systems) for rlogin, and download Sparta GUI (available in Kali Linux or from its repository).
- **IP Address**: Identify the target IP address (e.g., `<IP address>`).
- **Credentials**: Have a list of usernames (e.g., root) and passwords ready for brute-forcing.

## Rlogin Access

Attempt to access the REXEC service using rlogin.

```bash
$ rlogin -l root <IP address>  # Uses rlogin to connect to the target at <IP address> as the root user, prompting for a password (Linux).
```

Example:

```bash
$ rlogin -l root 192.168.1.100
```

If authentication succeeds, you'll get a shell; otherwise, it will prompt for a password or fail.

**Note**: REXEC requires a username and password, unlike rsh, which may use .rhosts for trusted access. Check for misconfigurations allowing password-less access.

## Brute-Force with Sparta GUI

Guess credentials using Sparta.

### Sparta GUI Setup

Launch Sparta (`sparta` in terminal or via GUI), add the target IP (`<IP address>`), and configure the REXEC module:

1. Set the port to 512.
2. Provide a username list (e.g., root, admin) or use a default list.
3. Provide a password list (e.g., `/usr/share/wordlists/rockyou.txt`).
4. Start the brute-force attack to guess credentials.

### Outcome

If successful, Sparta will display valid credentials (e.g., `root:password123`), which can be used with rlogin.

## Black Hat Mindset

- **Target Legacy Systems**: Focus on older Unix systems where REXEC is still enabled, as they often lack modern security controls.
- **Exploit Weak Credentials**: Use rlogin with default or guessed credentials to gain a shell.
- **Brute-Force Efficiently**: Leverage Sparta to systematically guess credentials without triggering lockouts.
- **Stay Silent**: Minimize login attempts to avoid detection by logging mechanisms.

## Resources

- REXEC Protocol
- rlogin Manual
- Sparta GitHub
- R-Services Security

