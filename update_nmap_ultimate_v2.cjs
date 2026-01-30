const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const NMAP_ULTIMATE_V2_EN = `# Nmap - Network Mapper: Ultimate Beginner to Expert Guide (2026 Edition)

## 🟢 PART 1: BEGINNER FUNDAMENTALS

### What is Nmap?
Nmap (Network Mapper) is a free and open-source utility for network discovery and security auditing. It uses raw IP packets to determine:
- What hosts are available on the network
- What services (application name and version) those hosts are offering
- What operating systems they are running
- What type of packet filters/firewalls are in use

### 💿 Installation & Setup
- **Linux (Debian/Ubuntu)**: \`sudo apt update && sudo apt install nmap -y\`
- **Linux (CentOS/RHEL)**: \`sudo yum install nmap\`
- **Linux (Arch)**: \`sudo pacman -S nmap\`
- **macOS**: \`brew install nmap\`
- **Windows**: Download the [Official Installer](https://nmap.org/download.html) or use \`choco install nmap\`.

### 🚀 Quick Start Examples
\`\`\`bash
nmap 192.168.1.1              # Scan a single host
nmap 192.168.1.0/24           # Scan a whole subnet
nmap 192.168.1.1-50           # Scan a range of IPs
nmap -iL targets.txt          # Scan from a list of targets
nmap scanme.nmap.org          # Scan by hostname
\`\`\`

---

## 🟡 PART 2: CORE SCANNING TECHNIQUES

### TCP SYN Scan (-sS) [Stealth Scan]
Default for root users. Fast and relatively stealthy as it never completes TCP connections (SYN -> SYN/ACK -> RST).
\`\`\`bash
sudo nmap -sS 192.168.1.1
\`\`\`

### TCP Connect Scan (-sT)
Default for non-root users. Completes the three-way handshake, making it slower and easily loggable.
\`\`\`bash
nmap -sT 192.168.1.1
\`\`\`

### UDP Scan (-sU)
Essential for finding services like DNS (53), SNMP (161), and DHCP (67). Slower than TCP scans.
\`\`\`bash
sudo nmap -sU -p 53,67,161 192.168.1.1
\`\`\`

### ACK Scan (-sA)
Used to map firewall rule sets. Determines if ports are filtered or unfiltered.
\`\`\`bash
nmap -sA 192.168.1.1
\`\`\`

### NULL, FIN, Xmas Scans (-sN, -sF, -sX)
Advanced scans that exploit TCP RFC compliance. Useful against systems not using stateful firewalls.
\`\`\`bash
nmap -sN 192.168.1.1 # NULL
nmap -sF 192.168.1.1 # FIN
nmap -sX 192.168.1.1 # Xmas
\`\`\`

---

## 🟠 PART 3: HOST DISCOVERY (PING SWEEPING)

### Find Alive Hosts
\`\`\`bash
nmap -sn 192.168.1.0/24       # Ping sweep only (No port scan)
nmap -Pn 192.168.1.1          # Skip ping (Treat all hosts as online)
nmap -PE 192.168.1.0/24       # ICMP Echo Request
nmap -PP 192.168.1.0/24       # ICMP Timestamp Request
nmap -PM 192.168.1.0/24       # ICMP Address Mask Request
nmap -PS80,443 192.168.1.0/24 # TCP SYN Ping on specific ports
nmap -PA22,80 192.168.1.0/24  # TCP ACK Ping
nmap -PU53,161 192.168.1.0/24 # UDP Ping
nmap -PR 192.168.1.0/24       # ARP Ping (For local networks)
\`\`\`

---

## 🔵 PART 4: PORT SELECTION & PERFORMANCE

### Targeting Specific Ports
\`\`\`bash
nmap -p 80 192.168.1.1            # Single port
nmap -p 22,80,443 192.168.1.1     # Multiple ports
nmap -p 1-1024 192.168.1.1        # Range
nmap -p- 192.168.1.1              # All 65,535 ports
nmap -p T:21,22,U:53 192.168.1.1  # TCP and UDP mixed
nmap -p http,https 192.168.1.1    # By service name
nmap -F 192.168.1.1               # Fast scan (top 100 ports)
nmap --top-ports 100 192.168.1.1  # Most common 100 ports
\`\`\`

### Timing & Performance Templates
\`\`\`bash
nmap -T0 192.168.1.1    # Paranoid (Slowest, evasive)
nmap -T1 192.168.1.1    # Sneaky
nmap -T2 192.168.1.1    # Polite
nmap -T3 192.168.1.1    # Normal (Default)
nmap -T4 192.168.1.1    # Aggressive (Fast, modern networks)
nmap -T5 192.168.1.1    # Insane (Potentially unstable)
\`\`\`

### Manual Timing Control
\`\`\`bash
nmap --scan-delay 5s 192.168.1.1
nmap --min-rate 100 192.168.1.1
nmap --max-retries 2 192.168.1.1
nmap --host-timeout 15m 192.168.1.1
\`\`\`

---

## 🔴 PART 5: SERVICE & OS DETECTION

### Service/Version Detection (-sV)
\`\`\`bash
nmap -sV 192.168.1.1
nmap -sV --version-intensity 5 192.168.1.1 # 0-9 intensity
nmap -sV --version-light 192.168.1.1       # Speed over accuracy
nmap -sV --version-all 192.168.1.1         # Max accuracy
\`\`\`

### OS Fingerprinting (-O)
\`\`\`bash
sudo nmap -O 192.168.1.1
sudo nmap -O --osscan-guess 192.168.1.1    # More aggressive guessing
sudo nmap -O --max-os-tries 1 192.168.1.1  # Limit attempts
\`\`\`

### Combined Detection (-A)
Enables OS detection, version detection, script scanning, and traceroute.
\`\`\`bash
nmap -A 192.168.1.1
\`\`\`

---

## 🟣 PART 6: NSE (NMAP SCRIPTING ENGINE)

### General & Discovery
\`\`\`bash
nmap -sC 192.168.1.1                  # Run default scripts
nmap --script=banner 192.168.1.1      # Grab service banners
nmap --script=http-title 192.168.1.1  # Get webpage titles
nmap --script=http-enum 192.168.1.1   # Enumerate HTTP resources
nmap --script=dns-brute 192.168.1.1   # Brute force subdomains
\`\`\`

### Vulnerability & Security
\`\`\`bash
nmap --script vuln 192.168.1.1        # Scan for known vulnerabilities
nmap --script safe 192.168.1.1        # Run only safe scripts
nmap --script auth 192.168.1.1        # Test authentication
nmap --script exploit 192.168.1.1     # Attempt to exploit (CAREFUL)
nmap --script malware 192.168.1.1     # Check for malware infections
\`\`\`

### Bruteforce & Database
\`\`\`bash
nmap --script ssh-brute 192.168.1.1
nmap --script ftp-brute 192.168.1.1
nmap -p 3306 --script mysql-enum 192.168.1.1
nmap -p 5432 --script pgsql-brute 192.168.1.1
nmap -p 445 --script smb-vuln-ms17-010 192.168.1.1
\`\`\`

---

## 🛡️ PART 7: FIREWALL EVASION & STEALTH

### Advanced Evasion
\`\`\`bash
nmap -f 192.168.1.1                   # Fragment packets (Split packets)
nmap --mtu 24 192.168.1.1             # Set custom MTU
nmap -D 10.0.0.1,10.0.0.2,ME 192.168.1.1 # Decoy (Hide your IP)
nmap -S 1.2.3.4 192.168.1.1           # Spoof source IP
nmap -g 53 192.168.1.1                # Spoof source port (DNS)
nmap --proxies http://1.1.1.1:8080 192.168.1.1 # Route through proxies
nmap --data-length 25 192.168.1.1     # Add random data to packets
nmap --badsum 192.168.1.1             # Send packets with bad checksums
\`\`\`

---

## ⚡ PART 8: LARGE-SCALE SCANNING

### Parallel Scanning Strategy
\`\`\`bash
# Shell loop for subnet scanning
BASE_NET="192.168.0"
for i in {0..255}; do
  nmap -sn \${BASE_NET}.\${i}.0/24 -oG results/subnet_\${i}.txt &
  if [ $((i % 10)) -eq 0 ]; then wait; fi
done
wait
\`\`\`

### Performance Tuning
\`\`\`bash
# Low-resource scan
nmap --max-parallelism 50 --max-hostgroup 100 -T3 10.0.0.0/16

# High-performance scan
nmap --max-parallelism 1024 --max-hostgroup 512 -T5 10.0.0.0/16
\`\`\`

---

## 📊 PART 9: OUTPUT & DATA ANALYSIS

### Saving Results
- **Normal**: \`-oN results.txt\`
- **XML**: \`-oX results.xml\` (Best for reporting tools)
- **Grepable**: \`-oG results.grep\`
- **All Formats**: \`-oA my_scan\`

### Quick Analysis with CLI
\`\`\`bash
grep "open" results.grep | awk '{print $2}' # List only open IPs
grep "80/open" results.grep | cut -d" " -f2 # List IPs with port 80 open
\`\`\`

---

## 🔥 PART 10: EXPERT REAL-WORLD SCENARIOS

### Scenario 1: Comprehensive Network Audit
\`\`\`bash
sudo nmap -sS -p- -sV -O -sC --script=vuln,default -T4 -oA network_audit 10.0.0.0/24
\`\`\`

### Scenario 2: Web Infrastructure Deep Scan
\`\`\`bash
nmap -p 80,443 --script http-methods,http-headers,http-enum,http-sql-injection,http-waf-detect 192.168.1.1
\`\`\`

### Scenario 3: Windows/AD Enumeration
\`\`\`bash
nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln-* 192.168.1.10
\`\`\`

### Scenario 4: Large Scale Asset Discovery
\`\`\`bash
nmap -sn -PS22,80,443,3389 -oG live_assets.grep 172.16.0.0/12
\`\`\`

---

## 📋 QUICK COMMAND REFERENCE TABLE

| Goal | Command |
|------|---------|
| Host Discovery | \`nmap -sn 192.168.1.0/24\` |
| Quick Service Scan | \`nmap -sV -F 192.168.1.1\` |
| All Ports + Version | \`nmap -sV -p- 192.168.1.1\` |
| Stealth Vuln Scan | \`sudo nmap -sS --script vuln 192.168.1.1\` |
| Aggressive OS/Ver | \`nmap -A 192.168.1.1\` |
| Firewall Evasion | \`nmap -f -D RND:10 192.168.1.1\` |

---

## ⚠️ LEGAL & ETHICAL GUIDELINES
1. **Authorization**: Never scan without explicit written permission.
2. **Impact**: High-speed scans (-T5) can crash older hardware.
3. **Responsibility**: You are responsible for any disruption caused.

---

## 📖 RESOURCES
- [Official Nmap Book](https://nmap.org/book/)
- [NSE Script Documentation](https://nmap.org/nsedoc/)
- [Zenmap GUI](https://nmap.org/zenmap/)
- [Nmap Reference Guide](https://linux.die.net/man/1/nmap)
`;

const NMAP_ULTIMATE_V2_TR = `# Nmap - Network Mapper: Nihai Başlangıçtan Uzmana Eğitim Rehberi (2026 Versiyonu)

## 🟢 BÖLÜM 1: TEMELLER (YENİ BAŞLAYANLAR İÇİN)

### Nmap Nedir?
Nmap (Network Mapper), ağ keşfi ve güvenlik denetimi için kullanılan, dünya standardında ücretsiz bir araçtır. 

### 🚀 Hızlı Başlangıç Örnekleri
\`\`\`bash
nmap 192.168.1.1              # Tek bir IP tarama
nmap 192.168.1.0/24           # Tüm alt ağı tara
nmap -iL hedefler.txt         # Dosyadaki listeyi tara
nmap scanme.nmap.org          # Hostname ile tara
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

## 🟠 BÖLÜM 3: ANA BİLGİSAYAR KEŞFİ (PING SWEEP)

### Canlı Makineleri Bulma
\`\`\`bash
nmap -sn 192.168.1.0/24       # Sadece ping sweep (Port taraması yapmaz)
nmap -Pn 192.168.1.1          # Ping atmadan tara (Her şeyi canlı sayar)
nmap -PR 192.168.1.0/24       # ARP Ping (Yerel ağ için)
\`\`\`

---

## 🔵 BÖLÜM 4: PORT SEÇİMİ VE PERFORMANS

### Belirli Portları Hedefleme
\`\`\`bash
nmap -p 80,443 192.168.1.1        # Belirli portlar
nmap -p- 192.168.1.1              # Tüm portlar (65535)
nmap --top-ports 100 192.168.1.1  # En yaygın 100 port
\`\`\`

### Zamanlama Şablonları (-T0 ile -T5)
\`\`\`bash
nmap -T0 192.168.1.1    # Paranoid (Çok yavaş, en gizli)
nmap -T3 192.168.1.1    # Normal (Varsayılan)
nmap -T4 192.168.1.1    # Agresif (Hızlı, modern ağlar için)
\`\`\`

---

## 🔴 BÖLÜM 5: SERVİS VE İŞLETİM SİSTEMİ TESPİTİ

### Servis Versiyon Tespiti (-sV)
\`\`\`bash
nmap -sV 192.168.1.1
\`\`\`

### İşletim Sistemi Tespiti (-O)
\`\`\`bash
sudo nmap -O 192.168.1.1
\`\`\`

### Hepsi Bir Arada (-A)
Versiyon, OS tespiti, Script taraması ve Traceroute'u birleştirir.
\`\`\`bash
nmap -A 192.168.1.1
\`\`\`

---

## 🟣 BÖLÜM 6: NSE (NMAP SCRIPTING ENGINE)

### Güçlü Script Kullanımı
\`\`\`bash
nmap -sC 192.168.1.1                  # Varsayılan scriptler
nmap --script vuln 192.168.1.1        # Zafiyet taraması
nmap --script http-title 192.168.1.1  # Web sayfa başlığı al
nmap --script brute 192.168.1.1       # Şifre deneme saldırıları
\`\`\`

---

## 🛡️ BÖLÜM 7: GÜVENLİK DUVARI ATLATMA (EVASION)

### Gelişmiş Teknikler
\`\`\`bash
nmap -f 192.168.1.1                   # Paketleri parçala (Fragmentation)
nmap -D sahte1,sahte2,ME 192.168.1.1  # Sahte kaynaklar (Decoys)
nmap -g 53 192.168.1.1                # Kaynak portunu 53 (DNS) yap
nmap --mtu 24 192.168.1.1             # Özel MTU ayarla
\`\`\`

---

## ⚡ BÖLÜM 8: BÜYÜK ÖLÇEKLİ TARAMA

### Paralel Tarama Stratejisi
\`\`\`bash
# Bash döngüsü ile alt ağ tarama
BASE_NET="192.168.0"
for i in {0..255}; do
  nmap -sn \${BASE_NET}.\${i}.0/24 -oG sonuclar_\${i}.txt &
done
wait
\`\`\`

---

## 🔥 BÖLÜM 9: GERÇEK DÜNYA SENARYOLARI (UZMAN)

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

async function updateUltimateNmapV2() {
  try {
    const cheatsheet = await prisma.cheatsheet.update({
      where: { id: 264 },
      data: {
        titleEn: 'Nmap - Network Mapper: Ultimate Beginner to Expert Training Guide',
        titleTr: 'Nmap - Network Mapper: Başlangıçtan Uzmana Nihai Eğitim Rehberi',
        descEn: NMAP_ULTIMATE_V2_EN,
        descTr: NMAP_ULTIMATE_V2_TR,
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
          'large-scale-scanning',
          'complete-guide'
        ]
      }
    });

    console.log('✓ Nmap cheatsheet updated with ULTIMATE V2 content!');
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

updateUltimateNmapV2();
