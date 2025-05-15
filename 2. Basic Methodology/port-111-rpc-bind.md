# Basic Methodology - Port 111 (RPC Bind)

This README explores exploiting the RPC (Remote Procedure Call) bind service on port 111, focusing on enumerating available RPC services to identify potential attack vectors.

## Table of Contents

- [Introduction](#introduction)
- [Setup and Prerequisites](#setup-and-prerequisites)
- [Enumerating RPC Services](#enumerating-rpc-services)
- [Black Hat Mindset](#black-hat-mindset)
- [Resources](#resources)

## Introduction

The RPC bind service on port 111 is used by Unix-like systems to register and map RPC services to ports, commonly associated with NFS, NIS, or other networked applications. Enumerating these services can reveal exploitable endpoints, especially on unpatched or misconfigured systems. This guide covers using `rpcinfo` to identify RPC services.

## Setup and Prerequisites

- **Environment**: Linux host with network access to the target RPC server.
- **Tools**: Install `rpcbind` and `rpcinfo` (e.g., `apt install rpcbind` on Debian-based systems).
- **IP Address**: Identify the target IP address (e.g., `<IP address>`).
- **Permissions**: No authentication is typically required for basic enumeration.

## Enumerating RPC Services

Discover registered RPC services and their ports.

```bash
$ rpcinfo -p <IP address>
```

Uses `rpcinfo` to query the RPC bind service on `<IP address>`, listing registered programs, versions, protocols (TCP/UDP), and port numbers (Linux).

Example Output:
```
program vers proto   port  service
100000  4   tcp    111  portmapper
100000  3   tcp    111  portmapper
100003  2   udp   2049  nfs
100005  1   udp    635  mountd
```

### Interpretation:

- `100000`: Portmapper (RPC bind itself)
- `100003`: NFS (Network File System)
- `100005`: Mountd (NFS mount daemon)

Use this data to target specific services (e.g., NFS for unauthenticated mounts).

## Black Hat Mindset

- **Map Services**: Enumerate RPC services to identify exposed protocols like NFS or mountd for exploitation.
- **Target Weaknesses**: Focus on unpatched or misconfigured services (e.g., NFS export without restrictions).
- **Escalate Access**: Use discovered ports to probe for privilege escalation via unmounted shares or remote procedure calls.
- **Stay Low-Profile**: Perform enumeration quietly to avoid triggering IDS/IPS on the target network.

## Resources

- RPC Protocol
- rpcinfo Manual
- NFS Security Guide
- RPC Enumeration Techniques

