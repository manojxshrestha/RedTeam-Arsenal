# Active Directory Initial Enumeration

This README covers the initial steps to gather network and domain information, identifying live hosts, DNS mappings, and potential user accounts in a target environment.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Network Enumeration](#network-enumeration)
- [Domain and User Enumeration](#domain-and-user-enumeration)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Initial enumeration in an Active Directory environment involves discovering network infrastructure, live hosts, and potential user accounts to establish a foothold. This guide uses `nslookup`, `tcpdump`, Responder, `fping`, `nmap`, and kerbrute to perform these tasks, assuming you have access to a compromised Linux host on the target network.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target AD environment.
- **Tools**: Install basic networking tools (e.g., `nslookup`, `tcpdump`, `fping`, `nmap`) and Git (e.g., `apt install git`).
- **kerbrute**: Clone and compile from its GitHub repository (see setup steps below).
- **Network Interface**: Identify the target interface (e.g., `ens224`) using `ip link`.
- **Host List**: Prepare a file (e.g., `hosts.txt`) with IP addresses or hostnames to scan.
- **User List**: Prepare a file (e.g., `users.txt`) with potential usernames for enumeration.

## Network Enumeration

Gather information about the network and active devices.

```bash
# Query DNS to resolve the IP address of ns1.inlanefreight.com
nslookup ns1.inlanefreight.com

# Capture network packets on the ens224 interface
sudo tcpdump -i ens224

# Start Responder in Passive Analysis mode
sudo responder -I ens224 -A

# Perform a ping sweep on the network segment
fping -asgq 172.16.5.0/23

# Run comprehensive nmap scan
sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum
```

## Domain and User Enumeration

Identify potential users and domain details.

```bash
# Clone kerbrute repository
sudo git clone https://github.com/ropnop/kerbrute.git

# List compilation options
make help

# Compile kerbrute binaries
sudo make all

# Test the compiled binary
./kerbrute_linux_amd64

# Move kerbrute to system path
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

# Run kerbrute user enumeration
./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 users.txt -o kerb-results
```

## Black Hat Mindset

- **Map Quietly**: Use passive tools like `tcpdump` and `Responder -A` to avoid detection during initial probing.
- **Identify Live Targets**: Leverage `fping` and `nmap` to pinpoint active hosts without alerting defenders.
- **Target Users**: Use kerbrute to discover valid accounts for password spraying or brute-forcing.
- **Stay Low-Profile**: Compile and move tools like kerbrute to blend into the environment and evade static analysis.

## Resources

- [nslookup Documentation](https://linux.die.net/man/1/nslookup)
- [tcpdump Guide](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Responder GitHub](https://github.com/lgandx/Responder)
- [fping Manual](https://fping.org/fping.1.html)
- [nmap Documentation](https://nmap.org/docs.html)
- [kerbrute GitHub](https://github.com/ropnop/kerbrute)
- Initial Enumeration Techniques

