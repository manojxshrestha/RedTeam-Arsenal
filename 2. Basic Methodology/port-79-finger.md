# Basic Methodology - Port 79 (Finger) README

This README explores exploiting the Finger protocol on port 79, focusing on connecting to Finger services, guessing users, and enumerating usernames to gather information about the target system.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Connecting to Finger Services](#connecting-to-finger-services)
- [User Guessing](#user-guessing)
- [User Enumeration](#user-enumeration)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

The Finger protocol on port 79 is an outdated service that provides user information (e.g., login names, last login time, home directory) on Unix-like systems. If left enabled, it can leak sensitive data, making it a prime target for enumeration. This guide covers connecting to Finger services, guessing users, and enumerating usernames using command-line tools.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target Finger server.
- **Tools**: Install `finger` (e.g., `apt install finger` on Debian-based systems), `nc` (netcat, e.g., `apt install netcat`), and `finger-user-enum.pl` (available from tools like SecLists or Kali repositories).
- **Wordlists**: Use a username list (e.g., `/usr/share/seclists/usernames/names` from SecLists).
- **IP Address**: Identify the target IP address (e.g., `<IP address>`) from initial enumeration.
- **Permissions**: No authentication is typically required as Finger is often an open service.

## Connecting to Finger Services

Establish a connection to the Finger server to test its availability.

```bash
# Uses netcat to connect to the Finger service on port 79 at <IP address>, with verbose output to confirm connectivity (Linux)
nc -v <IP address> 79

# Uses telnet to connect to the Finger service on port 79 (Linux)
telnet <IP address> 79
```

### Example Interaction:

- After connecting with nc, type a username (e.g., root) and press Enter to query user details.
- Look for responses like login names, last login times, or home directories.

## User Guessing

Probe for specific users on the target system.

```bash
# Queries the Finger service for <username> at <IP address>
finger <username>@<IP address>
```

For example, `finger root@<IP address>` checks if the root user exists and returns details like login status or home directory (Linux).

### Example Output:

```
Login: root   Name: root
Directory: /root   Shell: /bin/bash
Last login: Mon May 12 10:15 2025
```

## User Enumeration

Enumerate usernames to build a target list.

```bash
# Uses finger-user-enum.pl to enumerate users against the Finger service
finger-user-enum.pl -U /usr/share/seclists/usernames/names -t <IP address>
```

### Example Output:

```
root@<IP address>: [root] - Directory: /root
admin@<IP address>: [admin] - Directory: /home/admin
```

### Alternative Command:

```bash
# Loops through a custom usernames.txt file to query each user manually (Linux)
for user in $(cat usernames.txt); do finger $user@<IP address>; done
```

## Black Hat Mindset

- **Leak User Info**: Use Finger to gather usernames, home directories, and login details for further attacks (e.g., password spraying).
- **Target Legacy Systems**: Focus on older Unix systems where Finger is still enabled, as they often have other outdated vulnerabilities.
- **Build Profiles**: Combine user data with OS enumeration to craft targeted exploits (e.g., SSH brute-force).
- **Stay Quiet**: Avoid excessive queries to prevent triggering logging or rate-limiting mechanisms.

## Resources

- Finger Protocol
- SecLists GitHub
- Netcat Guide
- Finger Enumeration Techniques

