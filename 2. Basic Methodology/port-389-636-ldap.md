# Basic Methodology - Ports 389, 636 (LDAP)

This README explores exploiting the Lightweight Directory Access Protocol (LDAP) services on port 389 (LDAP) and port 636 (LDAPS), focusing on enumerating directory information using `ldapsearch`.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [LDAP Enumeration with Ldapsearch](#ldap-enumeration-with-ldapsearch)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

LDAP on port 389 (and LDAPS on port 636 for secure connections) is used to query and manage directory services, often in Active Directory or OpenLDAP environments. If misconfigured, LDAP servers can allow anonymous access, leaking sensitive information like usernames, groups, or organizational structure. This guide covers using `ldapsearch` to enumerate directory data.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target LDAP server.
- **Tools**: Install ldap-utils (e.g., `apt install ldap-utils` on Debian-based systems).
- **IP Address**: Identify the target IP address (e.g., `<IP address>`).
- **Base DN**: Determine the base Distinguished Name (e.g., `dc=mywebsite,dc=com`) through reconnaissance or guessing.
- **Permissions**: Anonymous access (`-x`) is often allowed on misconfigured servers; otherwise, credentials are needed.

## LDAP Enumeration with Ldapsearch

Query the LDAP directory to extract information.

Basic query:
```bash
ldapsearch -h <IP address> -p 389 -x -b "dc=mywebsite,dc=com"
```
Uses `ldapsearch` to connect to the LDAP server at `<IP address>` on port 389, with anonymous authentication (`-x`), querying the base DN `dc=mywebsite,dc=com` (Linux).

Example:
```bash
ldapsearch -h 192.168.1.100 -p 389 -x -b "dc=example,dc=com"
```

Example output:
```ldif
dn: cn=John Doe,ou=Users,dc=example,dc=com
objectClass: person
cn: John Doe
sn: Doe
mail: john.doe@example.com
```

Extended Query:
```bash
ldapsearch -h <IP address> -p 389 -x -b "dc=mywebsite,dc=com" "(objectClass=*)" *
```
Retrieves all attributes for all objects.

For LDAPS (port 636):
```bash
ldapsearch -h <IP address> -p 636 -x -b "dc=mywebsite,dc=com" -Z
```
Uses TLS (`-Z`).

## Black Hat Mindset

- **Enumerate Users**: Extract usernames, email addresses, and group memberships for password spraying or phishing.
- **Target Misconfigs**: Exploit anonymous access to gather organizational data without credentials.
- **Map the Network**: Use LDAP data to identify high-value targets (e.g., admins, service accounts) for further attacks.
- **Stay Silent**: Perform minimal queries to avoid triggering logging or rate-limiting.

## Resources

- [LDAP Protocol](https://ldap.com)
- [ldapsearch Manual](https://linux.die.net/man/1/ldapsearch)
- [LDAP Enumeration Techniques](https://book.hacktricks.xyz/pentesting/pentesting-ldap)

