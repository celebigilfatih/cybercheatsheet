# Nmap Mastery - Complete Guide: Beginner to Elite Expert

> **Version 2.0** | 15,000+ characters | Advanced Techniques & Real-World Scenarios

---

## TABLE OF CONTENTS
1. [Foundation (Beginner)](#1-foundation-beginner)
2. [Core Techniques (Intermediate)](#2-core-techniques-intermediate)
3. [Advanced Methodologies](#3-advanced-methodologies)
4. [Expert-Level Exploitation](#4-expert-level-exploitation)
5. [Elite Red Team Operations](#5-elite-red-team-operations)
6. [Defensive Countermeasures](#6-defensive-countermeasures)
7. [Real-World Case Studies](#7-real-world-case-studies)

---

## 1. FOUNDATION (BEGINNER)

### 1.1 Understanding Network Basics

Before scanning, understand what you're targeting:

```bash
# Check your own network configuration first
ip addr show
ifconfig
route -n
netstat -rn

# Understand subnetting
# /24 = 256 IPs (192.168.1.0 - 192.168.1.255)
# /16 = 65,536 IPs (192.168.0.0 - 192.168.255.255)
# /8  = 16,777,216 IPs (10.0.0.0 - 10.255.255.255)
```

### 1.2 First Scans - Getting Started

```bash
# Your very first scan - discover what's alive
nmap -sn 192.168.1.0/24

# Scan a single host with verbosity
nmap -v 192.168.1.1

# Scan with progress display
nmap --stats-every 10s 192.168.1.0/24

# Save results for later analysis
nmap -oN basic_scan.txt 192.168.1.1
```

### 1.3 Target Specification Deep Dive

```bash
# IPv4 targets
nmap 192.168.1.1                    # Single host
nmap 192.168.1.1-50                 # Range
nmap 192.168.1.0/24                 # CIDR notation
nmap 192.168.1.*                    # Wildcard

# Multiple target types in one command
nmap 192.168.1.1 10.0.0.1/24 172.16.1.1-20

# From file with comments and exclusions
cat > targets.txt << 'EOF'
# Internal network
192.168.1.0/24

# DMZ servers
10.0.0.10
10.0.0.20

# Exclude these
!192.168.1.1        # Exclude gateway
!192.168.1.254      # Exclude broadcast
EOF

nmap -iL targets.txt

# Randomize target order (stealth)
nmap --randomize-hosts 192.168.1.0/24

# Limit scan to specific number of hosts
nmap -iL targets.txt --max-hostgroup 10
```

### 1.4 Port Scanning Fundamentals

```bash
# Understanding port states:
# open     - Service is listening
# closed   - Port responds but no service
# filtered - Firewall blocking
# unfiltered - Port responds but can't determine state

# Default scan (top 1000 ports)
nmap 192.168.1.1

# Full port scan - all 65535 ports
nmap -p- 192.168.1.1

# Specific ports
nmap -p 22 192.168.1.1              # Single port
nmap -p 22,80,443 192.168.1.1       # Multiple ports
nmap -p 1-1000 192.168.1.1          # Range
nmap -p-1000 192.168.1.1            # From start to 1000
nmap -p 1000- 192.168.1.1           # From 1000 to end

# Protocol specific
nmap -p T:22,80,443,U:53,161 192.168.1.1

# By service name
nmap -p http,https,ssh,ftp 192.168.1.1

# Exclude ports
nmap -p- --exclude-ports 1-1024 192.168.1.1

# Fast scan (top 100 ports)
nmap -F 192.168.1.1

# Top ports customization
nmap --top-ports 50 192.168.1.1
nmap --top-ports 5000 192.168.1.1
```

---

## 2. CORE TECHNIQUES (INTERMEDIATE)

### 2.1 TCP Scan Types in Detail

```bash
# TCP SYN Scan (-sS) - The Stealth King
# Sends SYN, receives SYN-ACK, sends RST (never completes handshake)
# Pros: Fast, stealthy, no log entries on most systems
# Cons: Requires root/admin privileges
sudo nmap -sS -v 192.168.1.1

# TCP Connect Scan (-sT)
# Completes full 3-way handshake
# Use when: No root access, scanning through proxy
# Cons: Slower, creates logs
nmap -sT -v 192.168.1.1

# TCP ACK Scan (-sA)
# Sends ACK packets - used for firewall rule mapping
# Determines if port is filtered or unfiltered
sudo nmap -sA 192.168.1.1

# TCP Window Scan (-sW)
# Similar to ACK but uses window size to determine open/closed
# Works on some systems where ACK scan doesn't
sudo nmap -sW 192.168.1.1

# TCP Maimon Scan (-sM)
# Sends FIN/ACK probe
# Named after Uriel Maimon who discovered the technique
sudo nmap -sM 192.168.1.1

# Custom TCP flags
# Build your own scan type
sudo nmap --scanflags SYNFIN 192.168.1.1
sudo nmap --scanflags URGACKPSHRST 192.168.1.1
sudo nmap --scanflags ALL 192.168.1.1
```

### 2.2 UDP Scanning Mastery

```bash
# UDP is connectionless - harder to scan accurately
# Open port: No response (usually)
# Closed port: ICMP port unreachable
# Filtered: No response or ICMP admin prohibited

# Basic UDP scan (VERY SLOW)
sudo nmap -sU 192.168.1.1

# UDP with specific ports
sudo nmap -sU -p 53,67,68,69,123,161,162,500,514,520 192.168.1.1

# UDP with version detection
sudo nmap -sU -sV --version-intensity 0 -p 53,161 192.168.1.1

# Speed up UDP scanning
sudo nmap -sU --max-retries 2 --host-timeout 30s 192.168.1.1

# UDP with custom payload (may trigger response)
sudo nmap -sU --data-length 50 192.168.1.1
```

### 2.3 Stealth & Evasion Techniques

```bash
# NULL Scan (-sN) - No flags set
# Bypasses non-stateful firewalls
# Open: No response, Closed: RST
sudo nmap -sN 192.168.1.1

# FIN Scan (-sF) - Only FIN flag
sudo nmap -sF 192.168.1.1

# Xmas Scan (-sX) - FIN, PSH, URG (lights up like Christmas tree)
sudo nmap -sX 192.168.1.1

# Zombie Scan (-sI) - The Ultimate Stealth
# Bounces scan off innocent "zombie" host
# Target never sees your IP!
# Step 1: Find zombie with predictable IP ID
nmap -O -v 192.168.1.5
# Step 2: Use as zombie
sudo nmap -sI 192.168.1.5:80 192.168.1.1

# Idle scan detailed
sudo nmap -Pn -p- -sI zombie_host:80 target_host -v
```

---

## 3. ADVANCED METHODOLOGIES

### 3.1 Service & Version Detection Deep Dive

```bash
# Basic version detection
nmap -sV 192.168.1.1

# Version detection levels
nmap -sV --version-light     # Fast, light probes
nmap -sV --version-intensity 5  # Medium (default)
nmap -sV --version-all       # Try ALL probes

# Aggressive detection (includes version, OS, traceroute, scripts)
sudo nmap -A 192.168.1.1

# Custom version probe intensity per port
nmap -sV --version-intensity 9 -p 80,443 192.168.1.1

# Show probe details
nmap -sV --version-trace 192.168.1.1

# RPC scan for RPC services
nmap -sR 192.168.1.1

# Banner grabbing alternatives
echo "" | nc -v -w 3 192.168.1.1 80
echo "QUIT" | nc -v -w 3 192.168.1.1 21
```

### 3.2 OS Fingerprinting & Detection

```bash
# Enable OS detection
sudo nmap -O 192.168.1.1

# Limit OS detection to promising targets
sudo nmap -O --osscan-limit 192.168.1.1

# Aggressive OS guessing
sudo nmap -O --osscan-guess 192.168.1.1

# Show fingerprint (for submission to Nmap)
sudo nmap -O --fuzzy 192.168.1.1

# Maximum retries for OS detection
sudo nmap -O --max-os-tries 2 192.168.1.1

# Combined with other options
sudo nmap -sS -O -sV --version-all 192.168.1.1
```

### 3.3 Timing & Performance Optimization

```bash
# Timing templates explained:
# T0 (Paranoid): 1 probe every 5+ minutes - IDS evasion
# T1 (Sneaky):   1 probe every 15 seconds
# T2 (Polite):   0.4 seconds between probes
# T3 (Normal):   Default, dynamic timing
# T4 (Aggressive): 1.25s timeout, 0ms delay
# T5 (Insane):   0.3s timeout, parallel everything

# Paranoid - maximum stealth
sudo nmap -T0 --max-retries 3 192.168.1.1

# Sneaky - balanced stealth/speed
sudo nmap -T1 -f 192.168.1.1

# Aggressive - internal network scanning
sudo nmap -T4 -A 192.168.1.0/24

# Insane - when you're in a hurry (may miss things)
sudo nmap -T5 -p- 192.168.1.1

# Custom timing controls
nmap --min-rtt-timeout 100ms --max-rtt-timeout 500ms 192.168.1.1
nmap --initial-rtt-timeout 200ms 192.168.1.1
nmap --max-retries 1 192.168.1.1
nmap --host-timeout 10m 192.168.1.0/24
nmap --scan-delay 1s --max-scan-delay 5s 192.168.1.1

# Parallelism controls
nmap --min-parallelism 50 --max-parallelism 200 192.168.1.1
nmap --min-hostgroup 32 --max-hostgroup 1024 192.168.1.0/16
```

---

## 4. EXPERT-LEVEL EXPLOITATION

### 4.1 NSE Scripting Engine Mastery

```bash
# Default scripts (safe and recommended)
nmap -sC 192.168.1.1

# Specific scripts
nmap --script http-title 192.168.1.1
nmap --script http-headers 192.168.1.1
nmap --script ssl-cert 192.168.1.1

# Multiple scripts
nmap --script http-title,http-headers,http-methods 192.168.1.1

# Script categories
nmap --script "safe" 192.168.1.1
nmap --script "default" 192.168.1.1
nmap --script "discovery" 192.168.1.1
nmap --script "vuln" 192.168.1.1
nmap --script "exploit" 192.168.1.1
nmap --script "auth" 192.168.1.1
nmap --script "brute" 192.168.1.1
nmap --script "intrusive" 192.168.1.1
nmap --script "malware" 192.168.1.1
nmap --script "version" 192.168.1.1

# Boolean logic for scripts
nmap --script "safe and default" 192.168.1.1
nmap --script "safe or version" 192.168.1.1
nmap --script "default and not intrusive" 192.168.1.1
nmap --script "(default or safe or intrusive) and not http-*" 192.168.1.1

# Script arguments
nmap --script http-title --script-args http.useragent="Mozilla/5.0" 192.168.1.1
nmap --script smb-brute --script-args smbuser=admin,smbpass=password123 192.168.1.1

# Script help
nmap --script-help http-title
nmap --script-help "*smb*"
nmap --script-help "*brute*"

# Update scripts
nmap --script-updatedb
```

### 4.2 Vulnerability Assessment

```bash
# Comprehensive vulnerability scan
nmap --script vuln 192.168.1.1

# Specific vulnerability checks
nmap --script ssl-heartbleed 192.168.1.1
nmap --script ssl-poodle 192.168.1.1
nmap --script ssl-dh-params 192.168.1.1
nmap --script http-shellshock 192.168.1.1
nmap --script smb-vuln-ms17-010 192.168.1.1
nmap --script smb-vuln-ms08-067 192.168.1.1
nmap --script rdp-vuln-ms12-020 192.168.1.1
nmap --script cve-2017-7494 192.168.1.1

# Vulners script (comprehensive CVE database)
nmap --script vulners 192.168.1.1

# Multiple vuln scripts at once
nmap --script "smb-vuln*,ssl-*vuln*,http-vuln*" 192.168.1.1

# With version detection for better accuracy
nmap -sV --script vuln 192.168.1.1
```

### 4.3 Authentication & Brute Force Testing

```bash
# FTP brute force
nmap --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.1
nmap --script ftp-brute --script-args brute.firstonly=true 192.168.1.1

# SSH brute force
nmap --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.1

# Telnet brute force
nmap --script telnet-brute 192.168.1.1

# HTTP form brute force
nmap --script http-form-brute --script-args "http-form-brute.path=/login.php,http-form-brute.method=POST" 192.168.1.1

# HTTP basic auth brute force
nmap --script http-brute --script-args http-brute.path=/admin/ 192.168.1.1

# SMB brute force
nmap --script smb-brute 192.168.1.1

# MySQL brute force
nmap --script mysql-brute 192.168.1.1

# PostgreSQL brute force
nmap --script pgsql-brute 192.168.1.1

# MongoDB brute force
nmap --script mongodb-brute 192.168.1.1

# Redis brute force
nmap --script redis-brute 192.168.1.1

# SNMP community string brute force
nmap --script snmp-brute 192.168.1.1

# Custom brute force settings
nmap --script ssh-brute --script-args brute.mode=creds,brute.credfile=credentials.txt 192.168.1.1
nmap --script ssh-brute --script-args brute.threads=10,brute.delay=1s 192.168.1.1
```

### 4.4 Service Enumeration Deep Dive

```bash
# HTTP/HTTPS comprehensive enumeration
nmap -p 80,443 --script "http-*" 192.168.1.1
nmap -p 80 --script http-enum 192.168.1.1
nmap -p 80 --script http-title,http-headers,http-methods 192.168.1.1
nmap -p 80 --script http-robots.txt,http-sitemap-generator 192.168.1.1
nmap -p 80 --script http-userdir-enum,http-apache-negotiation 192.168.1.1
nmap -p 80 --script http-backup-finder,http-config-backup 192.168.1.1
nmap -p 80 --script http-comments-displayer,http-errors 192.168.1.1
nmap -p 80 --script http-git,http-svn-enum 192.168.1.1
nmap -p 80 --script http-sql-injection,http-xssed 192.168.1.1
nmap -p 80 --script http-wordpress-enum,http-wordpress-brute 192.168.1.1
nmap -p 80 --script http-joomla-brute,http-drupal-enum 192.168.1.1

# SMB/CIFS enumeration
nmap -p 445 --script "smb*" 192.168.1.1
nmap -p 445 --script smb-enum-shares 192.168.1.1
nmap -p 445 --script smb-enum-users 192.168.1.1
nmap -p 445 --script smb-enum-domains 192.168.1.1
nmap -p 445 --script smb-enum-groups 192.168.1.1
nmap -p 445 --script smb-enum-sessions 192.168.1.1
nmap -p 445 --script smb-os-discovery 192.168.1.1
nmap -p 445 --script smb-security-mode 192.168.1.1
nmap -p 445 --script smb-server-stats 192.168.1.1
nmap -p 445 --script smb-system-info 192.168.1.1
nmap -p 445 --script smb-vuln* 192.168.1.1

# DNS enumeration
nmap -p 53 --script "dns*" 192.168.1.1
nmap -p 53 --script dns-brute --script-args dns-brute.domain=example.com
nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com
nmap -p 53 --script dns-service-discovery 192.168.1.1

# SMTP enumeration
nmap -p 25 --script "smtp*" 192.168.1.1
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY} 192.168.1.1
nmap -p 25 --script smtp-open-relay 192.168.1.1

# SNMP enumeration
nmap -p 161 --script "snmp*" 192.168.1.1
nmap -p 161 --script snmp-interfaces 192.168.1.1
nmap -p 161 --script snmp-processes 192.168.1.1
nmap -p 161 --script snmp-sysdescr 192.168.1.1
nmap -p 161 --script snmp-win32-services 192.168.1.1
nmap -p 161 --script snmp-win32-shares 192.168.1.1
nmap -p 161 --script snmp-win32-software 192.168.1.1
nmap -p 161 --script snmp-win32-users 192.168.1.1

# Database enumeration
nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-users,mysql-variables 192.168.1.1
nmap -p 5432 --script pgsql-brute 192.168.1.1
nmap -p 1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password 192.168.1.1
nmap -p 27017 --script mongodb-info 192.168.1.1
nmap -p 6379 --script redis-info 192.168.1.1

# SSL/TLS comprehensive testing
nmap -p 443 --script "ssl*" 192.168.1.1
nmap -p 443 --script ssl-cert,ssl-enum-ciphers 192.168.1.1
nmap -p 443 --script ssl-heartbleed,ssl-poodle 192.168.1.1
nmap -p 443 --script ssl-dh-params,ssl-ccs-injection 192.168.1.1
nmap -p 443 --script ssl-date,ssl-known-key 192.168.1.1
```

---

## 5. ELITE RED TEAM OPERATIONS

### 5.1 Advanced Evasion Techniques

```bash
# Fragment packets at IP level
sudo nmap -f 192.168.1.1
sudo nmap -ff 192.168.1.1  # Double fragment

# Set custom MTU
sudo nmap --mtu 8 192.168.1.1    # 8 bytes per fragment
sudo nmap --mtu 16 192.168.1.1

# Decoy scanning - hide in the crowd
sudo nmap -D RND:10 192.168.1.1           # 10 random decoys
sudo nmap -D RND:50,ME 192.168.1.1        # 50 decoys + your IP
sudo nmap -D 192.168.1.10,192.168.1.20,ME 192.168.1.1

# Source address spoofing
sudo nmap -S 192.168.1.100 -e eth0 192.168.1.1

# Use specific source port (bypass firewall rules)
sudo nmap --source-port 53 192.168.1.1
sudo nmap --source-port 80 192.168.1.1
sudo nmap --source-port 443 192.168.1.1
sudo nmap -g 53 192.168.1.1  # Short form

# Spoof MAC address
sudo nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1
sudo nmap --spoof-mac Apple 192.168.1.1     # Random Apple MAC
sudo nmap --spoof-mac 0 192.168.1.1         # Random MAC

# Append random data to packets
nmap --data-length 25 192.168.1.1
nmap --data-length 100 192.168.1.1

# Send bad checksums (bypass some firewalls)
sudo nmap --badsum 192.168.1.1

# Custom IP options
sudo nmap --ip-options "R 192.168.1.5" 192.168.1.1  # Record route
sudo nmap --ip-options "S 192.168.1.5" 192.168.1.1  # Strict source route
sudo nmap --ip-options "L 192.168.1.5" 192.168.1.1  # Loose source route
sudo nmap --ip-options "T" 192.168.1.1               # Timestamp

# Proxy chains
proxychains nmap -sT 192.168.1.1
```

### 5.2 Covert Channel Scanning

```bash
# ICMP echo scan (ping sweep with data)
nmap -PE --data-length 100 192.168.1.1

# ICMP timestamp scan
nmap -PP 192.168.1.1

# ICMP netmask scan
nmap -PM 192.168.1.1

# TCP SYN ping
nmap -PS22,80,443 192.168.1.1

# TCP ACK ping
nmap -PA80,443 192.168.1.1

# UDP ping
nmap -PU53,161 192.168.1.1

# ARP ping (local network)
sudo nmap -PR 192.168.1.0/24

# IP protocol ping
nmap -PO1,2,4 192.168.1.1

# No ping - assume host is up
nmap -Pn 192.168.1.1

# Combination ping methods
nmap -PE -PP -PM 192.168.1.1
```

### 5.3 Advanced Output & Reporting

```bash
# Multiple output formats simultaneously
nmap -oA scan_results 192.168.1.1
# Creates: scan_results.nmap, scan_results.xml, scan_results.gnmap

# Normal output
nmap -oN scan.txt 192.168.1.1

# XML output (for parsing)
nmap -oX scan.xml 192.168.1.1

# Greppable output
nmap -oG scan.gnmap 192.168.1.1

# Script kiddie output (1337 speak)
nmap -oS scan_1337.txt 192.168.1.1

# Append to existing file
nmap -oN scan.txt --append-output 192.168.1.2

# No output (for scripting)
nmap -oN /dev/null 192.168.1.1

# Verbosity levels
nmap -v 192.168.1.1       # Level 1
nmap -vv 192.168.1.1      # Level 2
nmap -vvv 192.168.1.1     # Level 3

# Debugging
nmap -d 192.168.1.1       # Debug level 1
nmap -d9 192.168.1.1      # Debug level 9 (maximum)

# Show packet trace
nmap --packet-trace 192.168.1.1

# Show reason for port state
nmap --reason 192.168.1.1

# Show open ports only
nmap --open 192.168.1.1

# Resume interrupted scan
nmap --resume scan.gnmap
```

---

## 6. DEFENSIVE COUNTERMEASURES

### 6.1 Detecting Nmap Scans

```bash
# Monitor for SYN scans
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'

# Monitor for NULL/FIN/Xmas scans
tcpdump -i eth0 'tcp[13] & 0x17 == 0x00'  # NULL
tcpdump -i eth0 'tcp[13] & 0x17 == 0x01'  # FIN
tcpdump -i eth0 'tcp[13] & 0x17 == 0x11'  # Xmas

# Detect OS fingerprinting attempts
tcpdump -i eth0 'tcp[13] == 0x2b or tcp[13] == 0x2f'

# Log unusual TCP flags
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "NULL SCAN: "
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG --log-prefix "SYN/FIN SCAN: "
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "SYN/RST SCAN: "
```

### 6.2 Rate Limiting & Blocking

```bash
# iptables rate limiting
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/minute --limit-burst 5 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# Block specific scan patterns
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP

# Port knocking (simple implementation)
iptables -A INPUT -p tcp --dport 7000 -m recent --set --name KNOCK1
iptables -A INPUT -p tcp --dport 8000 -m recent --rcheck --seconds 10 --name KNOCK1 -m recent --set --name KNOCK2
iptables -A INPUT -p tcp --dport 22 -m recent --rcheck --seconds 10 --name KNOCK2 -j ACCEPT
```

---

## 7. REAL-WORLD CASE STUDIES

### Case Study 1: Enterprise Network Assessment

```bash
# Phase 1: Discovery
nmap -sn -PE -PP -PM -oN discovery.txt 10.0.0.0/8

# Phase 2: Port scanning top 1000
nmap -sS -T4 -A -oN phase2.txt -iL live_hosts.txt

# Phase 3: Full port scan on critical systems
nmap -sS -p- -T4 -A -oN phase3.txt critical_hosts.txt

# Phase 4: Vulnerability assessment
nmap -sV --script vuln -oN vuln_scan.txt all_hosts.txt

# Phase 5: Service-specific deep dives
nmap -p 80,443 --script "http-*" -oN web_scan.txt web_servers.txt
nmap -p 445 --script "smb*" -oN smb_scan.txt windows_hosts.txt
```

### Case Study 2: CTF Competition Strategy

```bash
# Quick reconnaissance (5 minutes)
nmap -sn 192.168.1.0/24
nmap -F -A target_ip

# Targeted exploitation (15 minutes)
nmap -p- -sV target_ip
nmap --script vuln target_ip
nmap --script "*brute*" --script-args userdb=users.txt,passdb=common.txt target_ip

# Flag hunting (ongoing)
nmap -p 80,443,8080,3000,5000,8000 --script http-enum target_ip
nmap -p 21,22,23,445 --script ftp-anon,ssh-hostkey,telnet-brute,smb-enum-shares target_ip
```

### Case Study 3: Red Team Operation

```bash
# External reconnaissance
nmap -Pn -sS -T2 -f -D RND:20 --source-port 53 target.com

# Internal pivoting (after compromise)
nmap -sT -A --max-retries 1 --host-timeout 5m 10.0.0.0/24

# Stealth data exfiltration mapping
nmap -sS -T0 -f --data-length 100 --randomize-hosts --max-hostgroup 1 target_subnet

# Covert channel testing
nmap -sI compromised_host target_network
```

---

## QUICK REFERENCE CHEAT SHEET

| Scenario | Command |
|----------|---------|
| Quick host discovery | `nmap -sn 192.168.1.0/24` |
| Fast port scan | `nmap -F 192.168.1.1` |
| Full port scan | `nmap -p- 192.168.1.1` |
| Stealth SYN scan | `sudo nmap -sS 192.168.1.1` |
| Service detection | `nmap -sV 192.168.1.1` |
| OS detection | `sudo nmap -O 192.168.1.1` |
| Aggressive scan | `sudo nmap -A 192.168.1.1` |
| Vulnerability scan | `nmap --script vuln 192.168.1.1` |
| UDP scan | `sudo nmap -sU 192.168.1.1` |
| Fragmented scan | `sudo nmap -f 192.168.1.1` |
| With decoys | `sudo nmap -D RND:10 192.168.1.1` |
| XML output | `nmap -oX scan.xml 192.168.1.1` |
| Resume scan | `nmap --resume scan.gnmap` |

---

**Legal Disclaimer:** This guide is for educational purposes and authorized security testing only. Always obtain proper authorization before scanning any systems you do not own.

**Version:** 2.0 | **Last Updated:** 2026 | **Character Count:** 15,000+
