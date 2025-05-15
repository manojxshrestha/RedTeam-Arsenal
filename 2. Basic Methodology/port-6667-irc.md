# Basic Methodology - Port 6667 (IRC)

This README provides a methodology for exploiting Internet Relay Chat (IRC) services running on port 6667. The focus is on determining the IRC server version using irssi and enumerating vulnerabilities with Nmap NSE scripts.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Determining IRC Server Version](#determining-irc-server-version)
- [Enumerating with Nmap NSE Scripts](#enumerating-with-nmap-nse-scripts)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

IRC, running on port 6667, is a protocol for real-time text communication, often used for chat servers. IRC servers are targeted due to misconfigurations, outdated software, or weak authentication, which may allow unauthorized access or exploitation. This guide covers connecting to an IRC server with irssi to identify its version and using Nmap NSE scripts to enumerate and identify vulnerabilities.

## Setup and Prerequisites

To begin, ensure the following:

### Environment
- A Linux host (e.g., Kali Linux) with network access to the target IRC server.

### Tools
- Install irssi (e.g., `sudo apt install irssi` on Debian-based systems).
- Install Nmap with NSE scripts (e.g., `sudo apt install nmap`).

### Requirements
- Target Information: Obtain the target IP address (e.g., `192.168.1.100`).
- Optional: Prepare a list of usernames or nicknames for testing authentication, if required by the server.

## Determining IRC Server Version

Use irssi to connect to the IRC server and identify its version or configuration.

### Command
```bash
irssi -c <IP address> --port 6667
```

### Example
```bash
irssi -c 192.168.1.100 --port 6667
```

### Behavior
- Connects to the IRC server at the specified IP and port.
- Upon connection, the server typically sends a welcome message, including its version (e.g., `UnrealIRCd-5.0.2` or `ircd-hybrid-8.2.26`).
- In irssi, type `/whois <your_nickname>` or observe the server's MOTD (Message of the Day) to gather version details.

### Notes
- Some servers may require a nickname or user registration (e.g., `/nick testuser` or `/user testuser 0 * :Test User`).
- If authentication is required, test default or weak credentials (e.g., `admin:admin` for operator access).
- Note the server software and version for further research into known vulnerabilities (e.g., CVEs for UnrealIRCd or ngIRCd).
- Use `/quit` to disconnect from the server cleanly.

## Enumerating with Nmap NSE Scripts

Use Nmap NSE scripts to enumerate the IRC server and identify potential vulnerabilities.

### List Available IRC NSE Scripts
```bash
ls -la /usr/share/nmap/scripts | grep "irc"
```

#### Example Output
```
-rw-r--r-- 1 root root  12345 Jan 10 2025 irc-botnet-channels.nse
-rw-r--r-- 1 root root  23456 Jan 10 2025 irc-info.nse
-rw-r--r-- 1 root root  34567 Jan 10 2025 irc-sasl-brute.nse
-rw-r--r-- 1 root root  45678 Jan 10 2025 irc-unrealircd-backdoor.nse
```

Lists all IRC-related NSE scripts available in Nmap.

### Run Key IRC NSE Scripts

#### Gather IRC Server Information
```bash
nmap --script irc-info -p 6667 192.168.1.100
```
Retrieves server version, uptime, and configuration details.

#### Check for UnrealIRCd Backdoor
```bash
nmap --script irc-unrealircd-backdoor -p 6667 192.168.1.100
```
Tests for the UnrealIRCd 3.2.8.1 backdoor vulnerability (CVE-2010-2075).

#### Brute-Force SASL Authentication
```bash
nmap --script irc-sasl-brute -p 6667 192.168.1.100
```
Attempts to guess SASL credentials if the server supports SASL authentication.

#### Detect Botnet Channels
```bash
nmap --script irc-botnet-channels -p 6667 192.168.1.100
```
Identifies channels associated with botnet activity.

### Notes
- Ensure Nmap is updated to include the latest NSE scripts (`nmap --script-updatedb`).
- Use `--script-args` to provide custom username/password lists for irc-sasl-brute (e.g., `--script-args userdb=users.txt,passdb=pass.txt`).
- The irc-unrealircd-backdoor script is particularly useful for detecting older, vulnerable UnrealIRCd versions.
- Combine scripts (e.g., `irc-info,irc-unrealircd-backdoor`) for comprehensive enumeration.

## Black Hat Mindset

To exploit IRC effectively, think like an attacker:

- **Exploit Misconfigurations**: Target servers with weak or no authentication, allowing unauthorized access to channels or operator privileges.
- **Leverage Known Vulnerabilities**: Research CVEs for the identified server version (e.g., UnrealIRCd backdoors) and use tools like Metasploit for exploitation.
- **Enumerate Aggressively**: Use Nmap NSE scripts to uncover server details, authentication methods, and potential backdoors.
- **Evade Detection**: Minimize connection attempts and avoid flooding the server to prevent triggering logging or bans.

## Resources

- IRC Protocol Documentation
- irssi Documentation
- Nmap NSE Documentation
- UnrealIRCd Security Advisories

