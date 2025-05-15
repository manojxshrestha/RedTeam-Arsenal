# Basic Methodology - Port 8080 (HTTP-Proxy)

This README provides a methodology for exploiting HTTP proxy services running on port 8080. The focus is on configuring Firefox to use a proxy for manual inspection and scanning the proxy with nikto to identify vulnerabilities.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Configuring Firefox to Use a Proxy](#configuring-firefox-to-use-a-proxy)
- [Scanning with Nikto Through a Proxy](#scanning-with-nikto-through-a-proxy)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

HTTP proxies, often running on port 8080, act as intermediaries for web traffic, forwarding requests between clients and servers. Misconfigured proxies can expose sensitive information, allow unauthorized access, or serve as pivots to internal networks. This guide covers configuring Firefox to route traffic through a target proxy for manual testing and using nikto to scan for vulnerabilities in the proxy service.

## Setup and Prerequisites

To begin, ensure the following:

### Environment
- A Linux host (e.g., Kali Linux) with network access to the target proxy server.

### Tools
- Install Firefox (pre-installed on Kali Linux or available via `sudo apt install firefox-esr`).
- Install nikto (e.g., `sudo apt install nikto`).
- Install Nmap with NSE scripts (e.g., `sudo apt install nmap`) for additional enumeration.

### Required Information
- Target Information: Obtain the target proxy IP address (e.g., `192.168.1.100`) and port (default is `8080`).
- Proxy Information: Identify a known proxy server for nikto scanning (e.g., `http://192.168.97.129:3128`).

## Configuring Firefox to Use a Proxy

Configure Firefox to route web traffic through the target proxy to inspect its behavior or access internal resources.

### Steps

1. **Open Firefox Preferences**:
   - Launch Firefox and navigate to Preferences (or Settings).
   - On Linux, click the menu (three horizontal lines) in the top-right corner and select Preferences.

2. **Access Network Settings**:
   - Scroll to the General tab and find the Network Settings section.
   - Click Settings next to Configure how Firefox connects to the internet.

3. **Configure Manual Proxy**:
   - Select Manual proxy configuration.
   - Enter the proxy details:
     - HTTP Proxy: `<IP address>` (e.g., `192.168.1.100`)
     - Port: `8080`
   - Optionally, enable Use this proxy server for all protocols or configure specific protocols (e.g., HTTPS, SOCKS).
   - Click OK to save.

4. **Test the Proxy**:
   - Browse to a website (e.g., http://example.com) to verify the proxy is routing traffic.
   - Check for errors (e.g., Proxy Authentication Required) or access to internal resources, indicating an open or misconfigured proxy.

### Notes

- If the proxy requires authentication, Firefox will prompt for a username and password. Test default credentials (e.g., `admin:admin`) or reused credentials.
- Look for signs of an open proxy (no authentication) or access to internal network resources, which could enable pivoting.
- Use Firefox's Developer Tools (F12) to inspect HTTP headers or responses for proxy-specific information.

## Scanning with Nikto Through a Proxy

Use nikto to scan the target proxy server for vulnerabilities, routing the scan through a specified proxy.

### Command
```bash
nikto -h <IP address> -useproxy http://<proxy_ip>:<proxy_port>
```

### Example
```bash
nikto -h 192.168.1.100 -useproxy http://192.168.97.129:3128
```

### Behavior
- Scans the target proxy server (`192.168.1.100:8080`) for common vulnerabilities, misconfigurations, or exposed resources.
- Routes the scan through the specified proxy (`192.168.97.129:3128`).
- Outputs findings such as outdated software, exposed admin panels, or misconfigured headers.

### Notes

- Ensure the proxy specified with `-useproxy` is accessible and allows traffic forwarding.
- If the target proxy requires authentication, use `-id <username>:<password>` (e.g., `-id admin:admin`).
- Look for vulnerabilities like open redirects, exposed configuration files, or weak authentication in the nikto output.
- Combine with Nmap for broader enumeration:
  ```bash
  nmap --script http* -p 8080 192.168.1.100
  ```
- Runs HTTP-related NSE scripts to identify proxy details or vulnerabilities.

## Black Hat Mindset

To exploit HTTP proxies effectively, think like an attacker:

- **Exploit Misconfigurations**: Target open proxies or those with weak authentication to access internal networks or bypass restrictions.
- **Enumerate Thoroughly**: Use nikto and Nmap to identify vulnerabilities, exposed endpoints, or proxy software details (e.g., Squid, Apache).
- **Pivot Strategically**: Leverage misconfigured proxies to access internal resources or chain attacks (e.g., SSRF, internal network scanning).
- **Evade Detection**: Minimize scan intensity (e.g., use `nikto -Tuning` to limit tests) and avoid triggering proxy logging or WAFs.

## Resources

- [Squid Proxy Documentation](https://wiki.squid-cache.org/)
- [Nikto Documentation](https://cirt.net/Nikto2)
- [Nmap NSE Documentation](https://nmap.org/nsedoc/)
- [OWASP Proxy Security Guide](https://owasp.org/www-community/controls/)

