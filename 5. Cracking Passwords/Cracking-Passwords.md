# Basic Methodology - Cracking Passwords

This README explores techniques for cracking various password hashes and encrypted files using tools like `hashcat`, `john`, and conversion scripts (`unshadow`, `ssh2john`, `office2john`, etc.).

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Cracking NTLM Hashes with Hashcat](#cracking-ntlm-hashes-with-hashcat)
- [Cracking a Single NTLM Hash with Hashcat](#cracking-a-single-ntlm-hash-with-hashcat)
- [Preparing and Cracking Unshadowed Hashes](#preparing-and-cracking-unshadowed-hashes)
- [Cracking MD5 Hashes with Hashcat](#cracking-md5-hashes-with-hashcat)
- [Cracking BitLocker Hashes with Hashcat](#cracking-bitlocker-hashes-with-hashcat)
- [Converting and Cracking SSH Key Hashes](#converting-and-cracking-ssh-key-hashes)
- [Converting and Cracking Office Document Hashes](#converting-and-cracking-office-document-hashes)
- [Converting and Cracking PDF Hashes](#converting-and-cracking-pdf-hashes)
- [Converting and Cracking ZIP Archives](#converting-and-cracking-zip-archives)
- [Converting and Cracking BitLocker Hashes](#converting-and-cracking-bitlocker-hashes)
- [Extracting and Cracking GZIP Archives](#extracting-and-cracking-gzip-archives)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

Password cracking involves extracting and breaking hashes or encrypted files to recover plaintext credentials. This guide covers cracking NTLM, MD5, BitLocker, SSH, Office, PDF, ZIP, and GZIP-protected data using `hashcat` and `john`, with preprocessing scripts to convert various file formats into crackable hashes.

## Setup and Prerequisites

### Environment
- Linux host with command-line access.

### Tools
- Install `hashcat` (e.g., `apt install hashcat`)
- Install `john` (e.g., `apt install john`)
- Perl scripts (`ssh2john.pl`, `office2john.py`, `pdf2john.pl`, `zip2john`, `bitlocker2john`) from the john package or John the Ripper jumbo version

### Files
- `dumpedhashes.txt`, `md5-hashes.list`, `backup.hash`, `SSH.private`, `Protected.docx`, `PDF.pdf`, `ZIP.zip`, `Backup.vhd`, `GZIP.gzip`, `passwd.bak`, `shadow.bak`

### Wordlists
- `/usr/share/wordlists/rockyou.txt`
- `/opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt`

### Permissions
- Ensure read/write access to output files (e.g., `unshadowed.hashes`, `backup.cracked`)

## Cracking NTLM Hashes with Hashcat

Crack multiple NTLM hashes using a wordlist:

```bash
hashcat -m 1000 dumpedhashes.txt /usr/share/wordlists/rockyou.txt
```

Example Output: Cracks hashes and displays successful matches.

## Cracking a Single NTLM Hash with Hashcat

Crack a specific NTLM hash and display results:

```bash
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt --show
```

Example Output:
```
64f12cddaa88057e06a81b54e73b949b:password123
```

## Preparing and Cracking Unshadowed Hashes

Combine and crack Linux password hashes:

```bash
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

## Cracking MD5 Hashes with Hashcat

Crack MD5 hashes using a wordlist:

```bash
hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

Example Output: Cracks and displays plaintext matches.

## Cracking BitLocker Hashes with Hashcat

Crack BitLocker hashes from a VHD file:

```bash
hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked
```

## Converting and Cracking SSH Key Hashes

Convert SSH keys to hashes and crack them:

```bash
ssh2john.pl SSH.private > ssh.hash
john ssh.hash --show
```

Example Output:
```
user:password123
```

## Converting and Cracking Office Document Hashes

Convert and crack a protected Office document:

```bash
office2john.py Protected.docx > protected-docx.hash
john --wordlist=rockyou.txt protected-docx.hash
```

## Converting and Cracking PDF Hashes

Convert and crack a protected PDF:

```bash
pdf2john.pl PDF.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash
```

## Converting and Cracking ZIP Archives

Convert and crack a protected ZIP file:

```bash
zip2john ZIP.zip > zip.hash
john --wordlist=rockyou.txt zip.hash
```

## Converting and Cracking BitLocker Hashes

Extract and crack BitLocker hashes from a VHD:

```bash
bitlocker2john -i Backup.vhd > backup.hashes
```

## Extracting and Cracking GZIP Archives

Attempt to extract a GZIP archive with password guesses:

```bash
file GZIP.gzip
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null | tar xz;done
```

## Black Hat Mindset

- **Target Diverse Hashes**: Use `hashcat` and `john` to crack NTLM, MD5, BitLocker, and other hash types.
- **Convert Files**: Leverage conversion scripts to unlock SSH keys, Office documents, PDFs, ZIPs, and archives.
- **Brute-Force Efficiently**: Use large wordlists like `rockyou.txt` and optimize with custom rules.
- **Stay Silent**: Perform cracking offline on an attack box to avoid network detection.

## Resources

- [Hashcat Documentation](https://hashcat.net/wiki/)
- [John the Ripper GitHub](https://github.com/openwall/john)
- [Impacket GitHub](https://github.com/SecureAuthCorp/impacket)
- [OpenSSL Manual](https://www.openssl.org/docs/)

