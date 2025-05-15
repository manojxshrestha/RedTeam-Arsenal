# Basic Methodology - Port 514 (RSH)

This README explores exploiting the Remote Shell (RSH) service on port 514, focusing on using rsh to execute commands remotely.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [RSH Access](#rsh-access)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

RSH on port 514 is a legacy remote shell service, part of the Berkeley r-services suite (rsh, rexec, rlogin), commonly found on older Unix systems. It allows remote command execution, often relying on `.rhosts` or `/etc/hosts.equiv` for trust-based authentication, making it a target for attackers. This guide covers using rsh to access the service and exploit misconfigurations.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target RSH server.
- **Tools**: Install rsh-client (e.g., `apt install rsh-client` on Debian-based systems) to use rsh.
- **IP Address**: Identify the target IP address (e.g., `<IP address>`).
- **Permissions**: RSH may allow command execution without a password if `.rhosts` or `/etc/hosts.equiv` is misconfigured.

## RSH Access

Attempt to execute commands on the target system using rsh.

```bash
$ rsh -l root <IP address> <command>
```
Uses rsh to connect to the target at `<IP address>` as the root user and execute `<command>` (Linux).

### Example:

```bash
$ rsh -l root 192.168.1.100 "whoami"
```
If `.rhosts` contains `+ +` or trusts your host, it executes whoami and returns the user (e.g., root). Otherwise, it prompts for a password or fails.

### Alternative:

- Try other commands: 
```bash
$ rsh -l user 192.168.1.100 "ls -l"
```
to list files.
- Specify a trusted host file: 
```bash
$ rsh -n -l root 192.168.1.100 "id"
```
(uses `/dev/null` for stdin).

## Black Hat Mindset

- **Target Legacy Systems**: Focus on older Unix systems where RSH is enabled, as they often lack modern security controls.
- **Exploit Trust**: Leverage `.rhosts` or `/etc/hosts.equiv` misconfigurations to execute commands without credentials.
- **Gain Shell Access**: Use RSH to run commands and escalate privileges on the target.
- **Stay Silent**: Limit command executions to avoid triggering logging or detection mechanisms.

## Resources

- RSH Protocol
- rsh Manual
- R-Services Security

