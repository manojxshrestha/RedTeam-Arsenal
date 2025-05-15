# Basic Methodology - Connecting to Targets README

This README explores techniques for establishing connections to target systems using protocols like RDP, WinRM, SSH, and SMB, as well as setting up shares for file transfers.
## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Connecting via RDP with xfreerdp](#connecting-via-rdp-with-xfreerdp)
- [Connecting via WinRM with Evil-WinRM](#connecting-via-winrm-with-evil-winrm)
- [Connecting via SSH](#connecting-via-ssh)
- [Connecting to SMB Shares with smbclient](#connecting-to-smb-shares-with-smbclient)
- [Setting Up an SMB Share with smbserver.py](#setting-up-an-smb-share-with-smbserverpy)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Connecting to targets is a critical step in penetration testing or malicious attacks, enabling remote access, file transfers, and further exploitation. This guide covers connecting to systems using RDP (via xfreerdp), WinRM (via evil-winrm), SSH, and SMB (via smbclient), as well as setting up an SMB share on an attack host for file transfers using smbserver.py.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target system.
- **Tools**: Install `freerdp2-x11` (e.g., `apt install freerdp2-x11` for xfreerdp), `evil-winrm` (e.g., `gem install evil-winrm`), `ssh` (pre-installed on most systems), `smbclient` (e.g., `apt install smbclient`), and download `smbserver.py` from Impacket (e.g., `pip install impacket`).
- **IP Address**: Identify the target IP address (e.g., `<ip>`).
- **Credentials**: Have usernames and passwords ready (e.g., `Lafi:Lafi-vault`, `user:password`).
- **Directory**: Ensure `/home/<nameofuser>/Documents/` exists for smbserver.py.

## Connecting via RDP with xfreerdp

Establish an RDP session with the target.

```bash
$ xfreerdp /v:<ip> /u:Lafi /p:Lafi-vault
```

Uses xfreerdp to connect to the target at `<ip>` via RDP with username `Lafi` and password `Lafi-vault` (Linux).

Example:

```bash
$ xfreerdp /v:192.168.1.100 /u:Lafi /p:Lafi-vault
```

Opens an RDP session if credentials are valid.

## Connecting via WinRM with Evil-WinRM

Establish a PowerShell session using WinRM.

```bash
$ evil-winrm -i <ip> -u user -p password
```

Uses evil-winrm to connect to the target at `<ip>` via WinRM with the specified username and password, providing a PowerShell session (Linux).

Example:

```bash
$ evil-winrm -i 192.168.1.100 -u Administrator -p Password123
```

Output: Opens a PowerShell prompt on the target.

## Connecting via SSH

Connect to the target using SSH.

```bash
$ ssh user@<ip>
```

Uses ssh to connect to the target at `<ip>` as the specified user, prompting for a password (Linux).

Example:

```bash
$ ssh user@192.168.1.100
```

Enter the password to gain a shell.

## Connecting to SMB Shares with smbclient

Access an SMB share on the target.

```bash
$ smbclient -U user \\\\<ip>\\SHARENAME
```

Uses smbclient to connect to the SMB share SHARENAME on the target at `<ip>` with the specified username, prompting for a password (Linux).

Example:

```bash
$ smbclient -U user \\\\192.168.1.100\\C$
```

Enter the password to access the share.

## Setting Up an SMB Share with smbserver.py

Create an SMB share on the attack host for file transfers.

```bash
$ python3 smbserver.py -smb2support CompData /home/<nameofuser>/Documents/
```

Uses smbserver.py to create an SMB share named CompData, serving files from `/home/<nameofuser>/Documents/` with SMB2 support (Linux).

Example:

```bash
$ python3 smbserver.py -smb2support CompData /home/user/Documents/
```

From the target: `\\<attack_host_ip>\CompData` can be accessed to transfer files.

## Black Hat Mindset

- **Gain Access**: Use valid credentials to connect via RDP, WinRM, SSH, or SMB for remote control.
- **Transfer Files**: Set up an SMB share with smbserver.py to exfiltrate data from the target.
- **Maintain Persistence**: Establish sessions (e.g., via evil-winrm) for ongoing access.
- **Stay Silent**: Use legitimate credentials and protocols to blend in with normal traffic.

## Resources

- [FreeRDP GitHub](https://github.com/FreeRDP/FreeRDP)
- [Evil-WinRM GitHub](https://github.com/Hackplayers/evil-winrm)
- [SSH Manual](https://man.openbsd.org/ssh.1)
- [smbclient Manual](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [Impacket GitHub](https://github.com/SecureAuthCorp/impacket)

