# Basic Methodology - Port 5900 (VNC)

This README provides a methodology for exploiting Virtual Network Computing (VNC) services running on port 5900. The focus is on connecting to VNC using `vncviewer` with known or guessed passwords and utilizing Nmap NSE scripts for enumeration and vulnerability scanning.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Connecting to VNC](#connecting-to-vnc)
- [Enumerating with Nmap NSE Scripts](#enumerating-with-nmap-nse-scripts)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

VNC, running on port 5900, is a protocol for remote desktop access to systems, commonly used on Linux, Windows, and macOS. It is a frequent target due to weak or default passwords and misconfigurations that allow unauthorized access. This guide covers connecting to a VNC server using `vncviewer` and enumerating vulnerabilities with Nmap NSE scripts.

## Setup and Prerequisites

To begin, ensure the following:

### Environment
- A Linux host (e.g., Kali Linux) with network access to the target VNC server.

### Tools
- Install `vncviewer` (e.g., `sudo apt install xtightvncviewer` or `tigervnc-viewer` on Debian-based systems).
- Install Nmap with NSE scripts (e.g., `sudo apt install nmap`).

### Requirements
- Target Information: Obtain the target IP address (e.g., `192.168.1.100`) and port (default is `5900`).
- Credential Information: Prepare a password or password list, focusing on common or default VNC passwords (e.g., `password`, `vnc123`).

## Connecting to VNC

Use `vncviewer` to attempt connecting to the VNC server with a known or guessed password.

### Command
```bash
vncviewer <IP address>:<port> -passwd <password>
```

### Example
```bash
vncviewer 192.168.1.100:5900 -passwd password
```

### Behavior
- If the password is valid, `vncviewer` establishes a remote desktop session.
- If the password is incorrect, the connection fails with an error (e.g., "Authentication failed").

### Notes
- VNC servers often use simple passwords or none at all, especially in misconfigured setups.
- If no password is required (common in insecure configurations), omit the `-passwd` flag.
- Test default passwords or those reused from other services.
- Use tools like `hydra` or `metasploit` for automated password guessing if manual attempts fail.

## Enumerating with Nmap NSE Scripts

Use Nmap NSE scripts to enumerate the VNC server and identify potential vulnerabilities.

### List Available VNC NSE Scripts

```bash
ls -la /usr/share/nmap/scripts | grep "vnc"
```

Example Output:
```
-rw-r--r-- 1 root root  12345 Jan 10 2025 vnc-brute.nse
-rw-r--r-- 1 root root  23456 Jan 10 2025 vnc-info.nse
-rw-r--r-- 1 root root  34567 Jan 10 2025 vnc-title.nse
```

Lists all VNC-related NSE scripts available in Nmap.

### Run Key VNC NSE Scripts

#### Gather VNC Information
```bash
nmap --script vnc-info -p 5900 192.168.1.100
```
Retrieves server version, protocol, and authentication details.

#### Brute-Force Passwords
```bash
nmap --script vnc-brute -p 5900 192.168.1.100
```
Attempts to guess VNC passwords using default or provided password lists.

#### Capture Desktop Title
```bash
nmap --script vnc-title -p 5900 192.168.1.100
```
Retrieves the title of the VNC desktop session, which may reveal system details.

### Notes
- Ensure Nmap is updated to include the latest NSE scripts (`nmap --script-updatedb`).
- Use `--script-args` to provide custom password lists for `vnc-brute` (e.g., `--script-args passdb=pass.txt`).
- Check for open port 5900 with a basic scan (`nmap -p 5900 192.168.1.100`) before running scripts.
- Look for no-authentication configurations or weak protocol versions (e.g., VNC 3.3) that are easier to exploit.

## Black Hat Mindset

To exploit VNC effectively, think like an attacker:

- **Exploit Weak Passwords**: Target default, blank, or reused passwords, as VNC often lacks strong authentication.
- **Enumerate Thoroughly**: Use Nmap NSE scripts to uncover server details, authentication settings, and vulnerabilities.
- **Maximize Access**: Once connected, capture screenshots, log keystrokes, or escalate privileges via the remote desktop.
- **Evade Detection**: Minimize connection attempts and use stealthy enumeration to avoid triggering monitoring or logging.

## Resources

- VNC Protocol Documentation
- Nmap NSE Documentation
- TigerVNC Documentation
- VNC Security Best Practices

