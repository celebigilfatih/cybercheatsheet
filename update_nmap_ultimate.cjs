const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const NMAP_ULTIMATE_EN = `# Nmap - Network Mapper: Ultimate Comprehensive Training Guide (2026 Edition)

## 🟢 PART 1: BEGINNER FUNDAMENTALS

### What is Nmap?
Nmap (Network Mapper) is a free and open-source utility for network discovery and security auditing. It uses raw IP packets to determine:
- What hosts are available on the network
- What services (application name and version) those hosts are offering
- What operating systems they are running
- What type of packet filters/firewalls are in use

### 💿 Installation & Setup
- **Linux (Debian/Ubuntu)**: \`sudo apt update && sudo apt install nmap -y\`
- **Linux (Arch)**: \`sudo pacman -S nmap\`
- **macOS**: \`brew install nmap\`
- **Windows**: Download the [Official Installer](https://nmap.org/download.html).

### 🚀 Quick Start (Common Scans)
\`\`\`bash
nmap 192.168.1.1              # Scan a single host
nmap 192.168.1.0/24           # Scan a whole subnet
nmap -iL targets.txt          # Scan from a list of targets
nmap scanme.nmap.org          # Scan by hostname
\`\`\`

---

## 🟡 PART 2: CORE SCANNING TECHNIQUES

### TCP SYN Scan (-sS) [The Standard]
Default for root users. It's fast and stealthy because it never completes the three-way handshake (SYN -> SYN/ACK -> RST).
\`\`\`bash
sudo nmap -sS 192.168.1.1
\`\`\`

### TCP Connect Scan (-sT)
Used by non-root users. Completes the connection, making it easily loggable by the target.
\`\`\`bash
nmap -sT 192.168.1.1
\`\`\`

### UDP Scan (-sU)
Essential for finding services like DNS (53), SNMP (161), and DHCP (67).
\`\`\`bash
sudo nmap -sU -p 53,67,161 192.168.1.1
\`\`\`

### SCTP INIT Scan (-sY)
Used for scanning SCTP protocols, common in telecommunications.
\`\`\`bash
sudo nmap -sY 192.168.1.1
\`\`\`

---

## 🟠 PART 3: HOST DISCOVERY (PING SWEEPING)

### Find Alive Hosts
\`\`\`bash
nmap -sn 192.168.1.0/24       # Ping sweep only (No port scan)
nmap -Pn 192.168.1.1          # Skip ping (Treat all hosts as online)
nmap -PE 192.168.1.0/24       # ICMP Echo Request
nmap -PS80,443 192.168.1.0/24 # TCP SYN Ping on specific ports
nmap -PA22,80 192.168.1.0/24  # TCP ACK Ping
\`\`\`

---

## 🔵 PART 4: PORT SELECTION & SCANNING SPEED

### Targeting Specific Ports
\`\`\`bash
nmap -p 80 192.168.1.1            # Single port
nmap -p 1-1024 192.168.1.1        # Range
nmap -p- 192.168.1.1              # All 65,535 ports
nmap -p T:21,22,U:53 192.168.1.1  # TCP and UDP mixed
nmap --top-ports 100 192.168.1.1  # Most common 100 ports
\`\`\`

### Timing & Performance (-T0 to -T5)
\`\`\`bash
nmap -T0 192.168.1.1    # Paranoid (Slowest, evasive)
nmap -T3 192.168.1.1    # Normal (Default)
nmap -T4 192.168.1.1    # Aggressive (Fast, for modern networks)
nmap -T5 192.168.1.1    # Insane (Very fast, potentially unstable)
\`\`\`

---

## 🔴 PART 5: SERVICE & OS DETECTION

### Service Version Detection (-sV)
\`\`\`bash
nmap -sV 192.168.1.1
nmap -sV --version-light 192.168.1.1  # Speed over accuracy
nmap -sV --version-all 192.168.1.1    # Max accuracy
\`\`\`

### OS Fingerprinting (-O)
\`\`\`bash
sudo nmap -O 192.168.1.1
sudo nmap -O --osscan-guess 192.168.1.1 # More aggressive guessing
\`\`\`

### Combined Detection (-A)
\`\`\`bash
nmap -A 192.168.1.1 # Combines -sV, -O, -sC (scripts), and traceroute
\`\`\`

---

## 🟣 PART 6: NSE (NMAP SCRIPTING ENGINE) - POWERFUL SCRIPTS

### General Usage
\`\`\`bash
nmap -sC 192.168.1.1                  # Run default scripts
nmap --script=banner 192.168.1.1      # Grab service banners
nmap --script=http-title 192.168.1.1  # Get webpage titles
\`\`\`

### Vulnerability & Security Auditing
\`\`\`bash
nmap --script vuln 192.168.1.1        # Scan for known vulnerabilities
nmap --script safe 192.168.1.1        # Run only safe scripts
nmap --script auth 192.168.1.1        # Test authentication protocols
nmap --script exploit 192.168.1.1     # Attempt to exploit vulns (BE CAREFUL)
\`\`\`

### Database Specific Scripts
\`\`\`bash
nmap -p 3306 --script mysql-enum 192.168.1.1
nmap -p 5432 --script pgsql-brute 192.168.1.1
nmap -p 1433 --script ms-sql-info 192.168.1.1
\`\`\`

---

## 🛡️ PART 7: FIREWALL EVASION & STEALTH

### Advanced Techniques
\`\`\`bash
nmap -f 192.168.1.1                   # Fragment packets (Split packets)
nmap -mtu 24 192.168.1.1              # Set custom MTU
nmap -D 10.0.0.1,10.0.0.2,ME 192.168.1.1 # Decoy (Hide your IP among others)
nmap -S 1.2.3.4 192.168.1.1           # Spoof source IP
nmap -g 53 192.168.1.1                # Use specific source port (DNS)
nmap --proxies http://1.1.1.1:8080 192.168.1.1 # Route through proxies
\`\`\`

### Data Length Padding
\`\`\`bash
nmap --data-length 25 192.168.1.1     # Add random data to packets
\`\`\`

---

## 📊 PART 8: OUTPUT & DATA ANALYSIS

### Saving Results
\`\`\`bash
nmap -oN results.txt 192.168.1.1      # Normal output
nmap -oX results.xml 192.168.1.1      # XML format (for reporting tools)
nmap -oG results.grep 192.168.1.1     # Grepable format
nmap -oA scan_everything 192.168.1.1  # Save in all formats at once
\`\`\`

### Fast Analysis with CLI
\`\`\`bash
grep "open" results.grep | awk '{print $2}' # List only IPs with open ports
\`\`\`

---

## 🔥 PART 9: REAL-WORLD EXPERT SCENARIOS

### Scenario 1: Comprehensive Network Audit
\`\`\`bash
sudo nmap -sS -p- -sV -O -sC --script=vuln,default -T4 -oA full_network_scan 10.0.0.0/24
\`\`\`

### Scenario 2: Web Server Deep Scan
\`\`\`bash
nmap -p 80,443 --script http-methods,http-headers,http-enum,http-sql-injection,http-shellshock 192.168.1.50
\`\`\`

### Scenario 3: Windows/SMB Enumeration
\`\`\`bash
nmap -p 445 --script smb-os-discovery,smb-enum-shares,smb-vuln-ms17-010 192.168.1.10
\`\`\`

### Scenario 4: Large Scale Asset Discovery
\`\`\`bash
nmap -sn -PS22,80,443,3389 -oG live_hosts.grep 172.16.0.0/16
\`\`\`

---

## ⚠️ LEGAL & ETHICAL GUIDELINES
1. **Permission**: Never scan a network you don't own or have explicit written permission for.
2. **Impact**: High-speed scans (-T5) can crash older hardware or unstable services.
3. **Logs**: Professional auditors always log their own activity for accountability.

---

## 📖 RESOURCES
- [Official Nmap Book](https://nmap.org/book/)
- [NSE Script Database](https://nmap.org/nsedoc/)
- [Zenmap GUI](https://nmap.org/zenmap/)
`;

const NMAP_ULTIMATE_TR = `# Nmap - Network Mapper: Nihai Kapsamlı Eğitim Rehberi (2026 Versiyonu)

## 🟢 BÖLÜM 1: TEMELLER (YENİ BAŞLAYANLAR İÇİN)

### Nmap Nedir?
Nmap (Network Mapper), ağ keşfi ve güvenlik denetimi için kullanılan, dünya standardında ücretsiz bir araçtır. 

### 🚀 Hızlı Başlangıç Örnekleri
\`\`\`bash
nmap 192.168.1.1              # Tek bir IP tarama
nmap 192.168.1.0/24           # Tüm alt ağı tara
nmap -iL hedefler.txt         # Dosyadaki listeyi tara
\`\`\`

---

## 🟡 BÖLÜM 2: TEMEL TARAMA TEKNİKLERİ

### TCP SYN Taraması (-sS) [Gizli Tarama]
En popüler tarama türüdür. Üçlü el sıkışmayı tamamlamadığı için hızlıdır ve sistem loglarına daha az yakalanır.
\`\`\`bash
sudo nmap -sS 192.168.1.1
\`\`\`

### UDP Taraması (-sU)
DNS (53), SNMP (161) ve DHCP (67) gibi servisleri bulmak için kritiktir.
\`\`\`bash
sudo nmap -sU -p 53,67,161 192.168.1.1
\`\`\`

---

## 🔴 BÖLÜM 3: NSE (NMAP SCRIPTING ENGINE) - GÜÇLÜ SCRIPT'LER

### Zafiyet Taraması
Bilinen güvenlik açıklarını otomatik olarak kontrol eder.
\`\`\`bash
nmap --script vuln 192.168.1.1
\`\`\`

### Web Sunucusu Analizi
\`\`\`bash
nmap --script http-title,http-enum 192.168.1.1
\`\`\`

---

## 🛡️ BÖLÜM 4: GÜVENLİK DUVARI ATLATMA (EVASION)

### Gelişmiş Teknikler
\`\`\`bash
nmap -f 192.168.1.1                   # Paketleri parçala (Fragmentation)
nmap -D sahte1,sahte2,ME 192.168.1.1  # Sahte kaynaklar (Decoys)
nmap -g 53 192.168.1.1                # Kaynak portunu 53 (DNS) yap
\`\`\`

---

## 🔥 BÖLÜM 5: GERÇEK DÜNYA SENARYOLARI (UZMAN)

### Senaryo 1: Tam Altyapı Denetimi
\`\`\`bash
sudo nmap -sS -p- -sV -O -sC --script=vuln,default -T4 -oA denetim_raporu 10.0.0.0/24
\`\`\`

### Senaryo 2: Veritabanı Güvenlik Testi
\`\`\`bash
nmap -p 3306,5432,1433 --script mysql-enum,pgsql-brute,ms-sql-info 192.168.1.1
\`\`\`

---

## ⚠️ YASAL VE ETİK UYARI
- İzniniz olmayan ağlarda tarama yapmak suçtur.
- Her zaman yazılı onay alın.
- Yüksek hızlı taramalar (-T5) eski sistemleri çökertebilir.
`;

async function updateUltimateNmap() {
  try {
    const cheatsheet = await prisma.cheatsheet.update({
      where: { id: 264 },
      data: {
        titleEn: 'Nmap - Network Mapper: Ultimate Comprehensive Training Guide (Beginner to Expert)',
        titleTr: 'Nmap - Network Mapper: Nihai Kapsamlı Eğitim Rehberi (Başlangıçtan Uzmana)',
        descEn: NMAP_ULTIMATE_EN,
        descTr: NMAP_ULTIMATE_TR,
        tags: [
          'nmap',
          'network-security',
          'pentesting',
          'reconnaissance',
          'vulnerability-scanning',
          'stealth-scanning',
          'advanced',
          'expert-level',
          'nse-scripts',
          'evasion',
          'firewall-bypass',
          'complete-guide'
        ]
      }
    });

    console.log('✓ Nmap cheatsheet updated with ULTIMATE content!');
    console.log(`  ID: ${cheatsheet.id}`);
    console.log(`  Total Content Length EN: ${cheatsheet.descEn.length} characters`);
    console.log(`  Total Content Length TR: ${cheatsheet.descTr.length} characters`);
    console.log(`  Total Tags: ${cheatsheet.tags.length}`);
  } catch (error) {
    console.error('✗ Error updating Nmap content:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

updateUltimateNmap();
