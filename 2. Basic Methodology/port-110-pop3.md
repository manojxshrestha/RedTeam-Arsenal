# Basic Methodology - Port 110 (POP3)

This README explores exploiting the Post Office Protocol version 3 (POP3) service on port 110, focusing on connecting to the server, logging in with guessed credentials, retrieving emails, and scanning for vulnerabilities with Nmap NSE scripts.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Connecting and Logging In](#connecting-and-logging-in)
- [Displaying and Retrieving Emails](#displaying-and-retrieving-emails)
- [Nmap NSE Scripts](#nmap-nse-scripts)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

POP3 on port 110 is used to retrieve emails from a mail server, often exposing sensitive data if credentials are weak or the service is misconfigured. This guide covers connecting to a POP3 server, logging in with default credentials, displaying and retrieving emails, and identifying vulnerabilities using Nmap NSE scripts.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target POP3 server.
- **Tools**: Install telnet (e.g., `apt install telnet`) and nmap (e.g., `apt install nmap`).
- **IP Address**: Identify the target IP address (e.g., `<IP address>`).
- **Credentials**: Have guessed or default credentials ready (e.g., admin/admin).

## Connecting and Logging In

Establish a connection to the POP3 server and attempt to log in.

```bash
$ telnet <IP address> 110    # Connects to the POP3 server on port 110 using telnet (Linux)
USER admin                   # Specifies the username admin
PASS admin                   # Attempts to authenticate with the password admin
```

Example Interaction:

```
$ telnet 192.168.1.100 110
+OK POP3 server ready
USER admin
+OK
PASS admin
+OK Logged in
```

## Displaying and Retrieving Emails

List and retrieve emails from the server.

```bash
LIST    # Displays a list of emails in the mailbox with their message numbers and sizes
```

Example Output:
```
+OK 2 messages: 1 512 2 1024
```

```bash
RETR 1    # Retrieves the email with message number 1, displaying its full content (headers and body)
```

Example:
```
LIST
+OK 1 messages: 1 512
RETR 1
+OK 512 octets
[Email content follows]
```

## Nmap NSE Scripts

Scan for POP3 vulnerabilities using Nmap's scripting engine.

```bash
# Lists POP3-related NSE scripts in the Nmap scripts directory
$ ls -la /usr/share/nmap/scripts | grep "pop3"

# Retrieves POP3 server capabilities
$ nmap -p 110 --script pop3-capabilities <IP address>

# Attempts to brute-force POP3 credentials
$ nmap -p 110 --script pop3-brute <IP address>
```

## Black Hat Mindset

- **Guess Credentials**: Test default credentials (e.g., admin/admin) to gain quick access to mailboxes.
- **Steal Emails**: Retrieve emails to extract sensitive information like credentials or business data.
- **Scan for Weaknesses**: Use Nmap NSE scripts to find misconfigurations or vulnerabilities in the POP3 service.
- **Stay Silent**: Avoid excessive login attempts to prevent triggering account lockouts or logging.

## Resources

- POP3 Protocol
- Nmap NSE Documentation
- Telnet Guide
- Email Server Security

