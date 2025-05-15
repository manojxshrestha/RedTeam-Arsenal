# Basic Methodology - Port 69 (UDP-TFTP)

This README explores exploiting the Trivial File Transfer Protocol (TFTP) over UDP on port 69, focusing on connecting to TFTP servers to upload or download files.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Connecting to TFTP Servers](#connecting-to-tftp-servers)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

TFTP on port 69 (UDP) is a lightweight file transfer protocol often used in embedded devices or network appliances, lacking authentication in many cases. This makes it a potential vector for unauthorized file access or payload delivery. This guide covers connecting to TFTP servers using command-line tools to assess and exploit them.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target TFTP server.
- **Tools**: Install `tftp` (e.g., `apt install tftp-hpa` on Debian-based systems) or `atftp` (e.g., `apt install atftp`).
- **IP Address**: Identify the target IP address (e.g., `<IP address>`) from initial enumeration.
- **Permissions**: No authentication is typically required for read access; write access depends on server configuration.

## Connecting to TFTP Servers

Establish a connection to the TFTP server to transfer files.

```bash
$ tftp <IP address>    # Launches the tftp client and connects to the TFTP server at <IP address>
```
Use commands like `get` (e.g., `get config.txt`) to download files or `put` (e.g., `put shell.sh`) to upload files (Linux).

```bash
$ atftp <IP address>   # Connects to the TFTP server at <IP address> using the atftp client
```
Similar to `tftp`, use `get` or `put` commands to transfer files (Linux).

### Example Workflow:

```bash
tftp <IP address>
tftp> get config.conf    # Downloads config.conf if readable
tftp> put backdoor.sh    # Uploads backdoor.sh if write access is allowed
tftp> quit               # Exits the session
```

## Black Hat Mindset

- **Probe for Access**: Test for open TFTP services to extract sensitive files (e.g., configuration backups) without credentials.
- **Deliver Payloads**: Upload malicious scripts or binaries to compromised devices with minimal detection.
- **Stay Stealthy**: Use UDP's connectionless nature to avoid leaving persistent traces during file transfers.
- **Target Weak Devices**: Focus on embedded systems or IoT devices where TFTP is often unsecured.

## Resources

- [TFTP Protocol](https://tools.ietf.org/html/rfc1350)
- [tftp-hpa Manual](https://linux.die.net/man/1/tftp)
- [atftp Documentation](https://linux.die.net/man/1/atftp)
- [TFTP Security Guide](https://www.cisco.com/c/en/us/about/security-center/tftp-best-practices.html)

