# Basic Methodology - Port 25 (SMTP)

This README explores exploiting the Simple Mail Transfer Protocol (SMTP) on port 25, focusing on enumerating users through VRFY and EXPN commands, and using Nmap NSE scripts to identify vulnerabilities.
## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating Users](#enumerating-users)
- [Nmap NSE Scripts](#nmap-nse-scripts)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

SMTP on port 25 is used for email transmission and can reveal user information if VRFY (verify) or EXPN (expand) commands are enabled. This guide covers enumerating users with command-line tools and scanning with Nmap NSE scripts to assess the mail server's security posture.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target SMTP server.
- **Tools**: Install `nc` (netcat, e.g., `apt install netcat`), `smtp-user-enum` (e.g., `apt install smtp-user-enum`), and `nmap` (e.g., `apt install nmap`).
- **Wordlists**: Prepare a user file (e.g., `users.txt`) or use `/usr/share/wordlists/metasploit/unix_users.txt`.
- **IP Address**: Identify the target IP address (e.g., `<IP address>`) from initial enumeration.
- **Permissions**: No authentication is typically required for enumeration if VRFY/EXPN is enabled.

## Enumerating Users

Identify valid email users via SMTP commands.

```bash
# Loop through users.txt, sending VRFY commands
for user in $(cat users.txt); do echo VRFY $user | nc -nv -w 1 <IP address> 25 2>/dev/null | grep ^"250"; done

# Use smtp-user-enum with VRFY method
smtp-user-enum.pl -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <IP address>

# Use smtp-user-enum with EXPN method
smtp-user-enum.pl -M EXPN -U /usr/share/wordlists/metasploit/unix_users.txt -t <IP address>
```

Example Output: Look for responses like `250 <user@domain>` indicating a valid user.

## Nmap NSE Scripts

Scan for SMTP vulnerabilities using Nmap's scripting engine.

```bash
# List SMTP-related NSE scripts
ls -la /usr/share/nmap/scripts | grep "smtp"
```

Example usage:

```bash
# Enumerate users if VRFY/EXPN is enabled
nmap -p 25 --script smtp-enum-users <IP address>

# Retrieve supported SMTP commands
nmap -p 25 --script smtp-commands <IP address>
```

## Black Hat Mindset

- **Expose Users**: Use VRFY/EXPN to build a target list for password spraying or phishing.
- **Scan Quietly**: Leverage Nmap NSE scripts to map server capabilities without triggering alerts.
- **Target Misconfigs**: Focus on servers with open enumeration to gain initial footholds.
- **Stay Low-Profile**: Limit connection attempts to avoid rate-limiting or logging.

## Resources

- SMTP Protocol
- smtp-user-enum Documentation
- Nmap NSE Documentation
- Netcat Guide
- SMTP Enumeration Techniques

