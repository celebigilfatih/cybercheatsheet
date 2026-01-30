# Nmap Complete Guide - Beginner to Expert

## 1. BASIC SCANS (Beginner Level)

### Target Specification
```bash
# Single target
nmap 192.168.1.1

# Multiple targets
nmap 192.168.1.1 192.168.1.2 192.168.1.3

# Range of hosts
nmap 192.168.1.1-100

# Entire subnet
nmap 192.168.1.0/24

# From file
nmap -iL targets.txt

# Exclude hosts
nmap 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254
```

### Basic Port Scans
```bash
# Scan top 1000 ports (default)
nmap 192.168.1.1

# Scan all 65535 ports
nmap -p- 192.168.1.1

# Scan specific ports
nmap -p 22,80,443 192.168.1.1

# Scan port range
nmap -p 1-1000 192.168.1.1

# Scan by protocol
nmap -p T:22,80,U:53 192.168.1.1

# Fast scan (top 100 ports)
nmap -F 192.168.1.1
```

## 2. SCAN TYPES (Intermediate Level)

### TCP Scans
```bash
# TCP SYN scan (stealthy, requires root)
sudo nmap -sS 192.168.1.1

# TCP Connect scan (no root needed)
nmap -sT 192.168.1.1

# TCP ACK scan (firewall mapping)
sudo nmap -sA 192.168.1.1

# TCP Window scan
sudo nmap -sW 192.168.1.1

# TCP Maimon scan
sudo nmap -sM 192.168.1.1
```

### UDP Scans
```bash
# UDP scan (slow but thorough)
sudo nmap -sU 192.168.1.1

# UDP with top ports
sudo nmap -sU --top-ports 100 192.168.1.1

# Common UDP ports
sudo nmap -sU -p 53,67,68,69,123,161,162,500,514,520 192.168.1.1
```

### Stealth Scans
```bash
# Null scan (no flags set)
sudo nmap -sN 192.168.1.1

# FIN scan
sudo nmap -sF 192.168.1.1

# Xmas scan (FIN, PSH, URG)
sudo nmap -sX 192.168.1.1

# Zombie scan (idle scan)
sudo nmap -sI zombie_host 192.168.1.1
```

## 3. SERVICE & VERSION DETECTION (Advanced Level)

### Version Detection
```bash
# Basic version detection
nmap -sV 192.168.1.1

# Aggressive version detection
nmap -sV --version-intensity 5 192.168.1.1

# Light version detection
nmap -sV --version-light 192.168.1.1

# All probes
nmap -sV --version-all 192.168.1.1
```

### OS Detection
```bash
# Enable OS detection
sudo nmap -O 192.168.1.1

# Limit OS detection
sudo nmap -O --osscan-limit 192.168.1.1

# Guess OS aggressively
sudo nmap -O --osscan-guess 192.168.1.1
```

### Combined Aggressive Scan
```bash
# Aggressive scan (OS, version, script, traceroute)
sudo nmap -A 192.168.1.1

# Aggressive with all ports
sudo nmap -A -p- 192.168.1.1
```

## 4. NSE SCRIPTS (Expert Level)

### Basic Script Usage
```bash
# Default scripts
nmap -sC 192.168.1.1

# Specific script
nmap --script http-title 192.168.1.1

# Multiple scripts
nmap --script http-title,http-headers 192.168.1.1

# Script category
nmap --script "safe and default" 192.168.1.1
```

### Vulnerability Scanning
```bash
# Vulnerability scan
nmap --script vuln 192.168.1.1

# Specific CVE check
nmap --script vulners 192.168.1.1

# SMB vulnerabilities
nmap --script smb-vuln* 192.168.1.1

# SSL/TLS vulnerabilities
nmap --script ssl-heartbleed,ssl-poodle 192.168.1.1
```

### Authentication & Brute Force
```bash
# FTP brute force
nmap --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.1

# SSH brute force
nmap --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.1

# MySQL brute force
nmap --script mysql-brute 192.168.1.1

# SNMP community strings
nmap --script snmp-brute 192.168.1.1
```

### Information Gathering
```bash
# WHOIS lookup
nmap --script whois-domain 192.168.1.1

# DNS enumeration
nmap --script dns-brute,dns-zone-transfer 192.168.1.1

# HTTP enumeration
nmap --script http-enum 192.168.1.1

# SMB enumeration
nmap --script smb-enum-shares,smb-enum-users 192.168.1.1

# NetBIOS information
nmap --script nbstat 192.168.1.1
```

## 5. FIREWALL & IDS EVASION (Expert Level)

### Fragmentation
```bash
# Fragment packets
sudo nmap -f 192.168.1.1

# Set MTU
sudo nmap --mtu 16 192.168.1.1
```

### Decoys
```bash
# Use decoys
sudo nmap -D RND:10 192.168.1.1

# Specific decoys
sudo nmap -D 192.168.1.10,192.168.1.20,ME 192.168.1.1
```

### Source Address Spoofing
```bash
# Spoof source address
sudo nmap -S 192.168.1.100 -e eth0 192.168.1.1

# Use specific source port
sudo nmap --source-port 53 192.168.1.1
```

### Timing & Performance
```bash
# Paranoid timing (very slow)
nmap -T0 192.168.1.1

# Sneaky timing
nmap -T1 192.168.1.1

# Polite timing
nmap -T2 192.168.1.1

# Normal timing (default)
nmap -T3 192.168.1.1

# Aggressive timing
nmap -T4 192.168.1.1

# Insane timing (very fast)
nmap -T5 192.168.1.1
```

### Custom Options
```bash
# Randomize hosts
nmap --randomize-hosts 192.168.1.0/24

# Set MAC address
sudo nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1

# Send bad checksums
sudo nmap --badsum 192.168.1.1

# Append random data
nmap --data-length 25 192.168.1.1
```

## 6. OUTPUT FORMATS

### Different Output Types
```bash
# Normal output
nmap -oN scan.txt 192.168.1.1

# XML output
nmap -oX scan.xml 192.168.1.1

# Greppable output
nmap -oG scan.gnmap 192.168.1.1

# All formats
nmap -oA scan 192.168.1.1
```

### Verbosity Levels
```bash
# Quiet
nmap -q 192.168.1.1

# Verbose
nmap -v 192.168.1.1

# Very verbose
nmap -vv 192.168.1.1

# Debug level
nmap -d 192.168.1.1

# Reason for state
nmap --reason 192.168.1.1

# Show packet trace
nmap --packet-trace 192.168.1.1
```

## 7. PRACTICAL EXAMPLES

### Network Discovery
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# List scan (no port scan)
nmap -sL 192.168.1.0/24

# No ping (assume host is up)
nmap -Pn 192.168.1.1

# ARP ping scan
sudo nmap -PR 192.168.1.0/24
```

### Web Server Scanning
```bash
# Comprehensive web scan
nmap -sV -p 80,443,8080,8443 --script http-title,http-headers,http-methods,http-enum 192.168.1.1

# SSL/TLS scan
nmap -p 443 --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed 192.168.1.1
```

### Database Scanning
```bash
# MySQL scan
nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-brute 192.168.1.1

# PostgreSQL scan
nmap -p 5432 --script pgsql-brute 192.168.1.1

# MongoDB scan
nmap -p 27017 --script mongodb-info 192.168.1.1

# MSSQL scan
nmap -p 1433 --script ms-sql-info,ms-sql-brute 192.168.1.1
```

### Full Security Audit
```bash
# Comprehensive audit
sudo nmap -sS -sU -A -p- --script vuln,exploit -T4 -oA full_audit 192.168.1.1

# Stealth audit
sudo nmap -sS -A --script "safe or default" -T2 -f -D RND:5 -oN stealth_audit.txt 192.168.1.1
```

## 8. USEFUL TIPS

### Performance Optimization
```bash
# Host timeout
nmap --host-timeout 30m 192.168.1.0/24

# Max retries
nmap --max-retries 2 192.168.1.1

# Min/Max parallel hosts
nmap --min-hostgroup 50 --max-hostgroup 100 192.168.1.0/24

# Min/Max parallel scans
nmap --min-parallelism 100 --max-parallelism 500 192.168.1.1
```

### IPv6 Scanning
```bash
# IPv6 target
nmap -6 fe80::1

# IPv6 subnet
nmap -6 fe80::/64
```

### Resume Scans
```bash
# Resume interrupted scan
nmap --resume scan.gnmap
```

### Interactive Mode
```bash
# Interactive mode (press keys during scan)
nmap --interactive
# v - increase verbosity
# d - increase debugging
# p - turn on packet tracing
```

---

## Quick Reference Table

| Command | Description | Level |
|---------|-------------|-------|
| `nmap target` | Basic scan | Beginner |
| `nmap -sS target` | SYN stealth scan | Intermediate |
| `nmap -sV target` | Version detection | Intermediate |
| `nmap -A target` | Aggressive scan | Advanced |
| `nmap -sC target` | Default scripts | Advanced |
| `nmap --script vuln target` | Vulnerability scan | Expert |
| `nmap -f -D RND:10 target` | Fragmented with decoys | Expert |

---

**Legal Notice:** Only use Nmap on systems you own or have explicit permission to scan. Unauthorized scanning may violate laws.
