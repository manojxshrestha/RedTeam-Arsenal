# Basic Methodology - Port 513 (Rlogin)

This README explores exploiting the Remote Login (Rlogin) service on port 513, focusing on using rlogin to gain unauthorized access to the target system.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Rlogin Access](#rlogin-access)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Rlogin on port 513 is a legacy remote login service, part of the Berkeley r-services suite (rsh, rexec, rlogin), commonly found on older Unix systems. It allows users to log in remotely but is notoriously insecure due to its reliance on `.rhosts` files for authentication, often bypassing password requirements. This guide covers using rlogin to access the service and exploit misconfigurations.

## Setup and Prerequisites
    
- **Environment**: Linux host with network access to the target Rlogin server.
- **Tools**: Install rsh-client (e.g., `apt install rsh-client` on Debian-based systems) to use rlogin.
- **IP Address**: Identify the target IP address (e.g., `<IP address>`).
- **Permissions**: Rlogin may allow access without a password if `.rhosts` or `/etc/hosts.equiv` is misconfigured.

## Rlogin Access

Attempt to log in to the target system using rlogin.

```bash
$ rlogin -l root <IP address>  # Uses rlogin to connect to the target at <IP address> as the root user (Linux)
```

Example:

```bash
$ rlogin -l root 192.168.1.100
```

If the target has a misconfigured `.rhosts` file (e.g., `+ +` in `/root/.rhosts`), you may gain access without a password. Otherwise, it will prompt for a password or fail.

Alternative:

```bash
$ rlogin -l admin <IP address>  # Try with admin user
$ rlogin -l user <IP address>   # Try with regular user
```

## Black Hat Mindset

- **Target Legacy Systems**: Focus on older Unix systems where Rlogin is still enabled, as they often lack modern security controls.
- **Exploit Misconfigs**: Leverage `.rhosts` or `/etc/hosts.equiv` misconfigurations to bypass authentication.
- **Gain Shell Access**: Use successful logins to obtain a remote shell and escalate privileges.
- **Stay Silent**: Minimize login attempts to avoid triggering logging or detection mechanisms.

## Resources

- Rlogin Protocol
- rlogin Manual
- R-Services Security

