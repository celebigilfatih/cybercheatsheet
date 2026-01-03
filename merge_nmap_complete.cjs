const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const NMAP_COMPLETE_EN = `# Nmap - Network Mapper: Complete Comprehensive Guide (Beginner to Expert)

## PART 1: BEGINNER FUNDAMENTALS

### What is Nmap?

Nmap (Network Mapper) is a free and open-source utility for network discovery and security auditing. It uses raw IP packets to determine:
- What hosts are available on the network
- What services (application name and version) those hosts are offering
- What operating systems they are running
- What type of packet filters/firewalls are in use
- And dozens of other characteristics

### Installation

**Linux (Debian/Ubuntu):**
\`\`\`bash
sudo apt update
sudo apt install nmap
\`\`\`

**Linux (CentOS/RHEL):**
\`\`\`bash
sudo yum install nmap
\`\`\`

**macOS:**
\`\`\`bash
brew install nmap
\`\`\`

**Windows:**
Download from https://nmap.org/download.html or use:
\`\`\`
choco install nmap
\`\`\`

**Verify Installation:**
\`\`\`bash
nmap --version
\`\`\`

---

## PART 2: BASIC SCAN TYPES

### TCP Connect Scan (-sT)

Completes full three-way handshake - slowest but most reliable, leaves logs on target systems.

\`\`\`bash
nmap -sT 192.168.1.0/24
\`\`\`

### TCP SYN Scan (-sS) [Stealth Scan]

Default for root users. Sends SYN, receives SYN-ACK, sends RST (never completes handshake). Faster and less logged.

\`\`\`bash
sudo nmap -sS 192.168.1.0/24
\`\`\`

### UDP Scan (-sU)

Scans UDP ports - slower than TCP but many services use UDP (DNS, SNMP, DHCP).

\`\`\`bash
sudo nmap -sU 192.168.1.0/24
\`\`\`

### ACK Scan (-sA)

Used to map firewall rule sets. Determines if ports are filtered or unfiltered.

\`\`\`bash
nmap -sA 192.168.1.0/24
\`\`\`

### NULL, FIN, Xmas Scans (-sN, -sF, -sX)

Advanced scans that exploit TCP RFC compliance. Useful against old systems.

\`\`\`bash
nmap -sN 192.168.1.1
nmap -sF 192.168.1.1
nmap -sX 192.168.1.1
\`\`\`

---

## PART 3: HOST DISCOVERY

### Ping Sweep (Find alive hosts)

\`\`\`bash
nmap -sn 192.168.1.0/24
\`\`\`

### Skip ping (assume hosts are alive)

\`\`\`bash
nmap -Pn 192.168.1.1
\`\`\`

### ICMP Echo Request

\`\`\`bash
nmap -PE 192.168.1.0/24
\`\`\`

### TCP SYN Ping

\`\`\`bash
nmap -PS80,443 192.168.1.0/24
\`\`\`

### TCP ACK Ping

\`\`\`bash
nmap -PA80,443 192.168.1.0/24
\`\`\`

---

## PART 4: PORT SELECTION

### Scan common ports

\`\`\`bash
nmap 192.168.1.1
\`\`\`

### Scan specific ports

\`\`\`bash
nmap -p 22,80,443 192.168.1.1
\`\`\`

### Scan port range

\`\`\`bash
nmap -p 1-1000 192.168.1.1
\`\`\`

### Scan all 65535 ports

\`\`\`bash
nmap -p- 192.168.1.1
\`\`\`

### Scan by service name

\`\`\`bash
nmap -p http,https,ssh 192.168.1.1
\`\`\`

---

## PART 5: SERVICE & VERSION DETECTION

### Detect service versions (-sV)

\`\`\`bash
nmap -sV 192.168.1.1
\`\`\`

### Detect OS (-O)

\`\`\`bash
sudo nmap -O 192.168.1.1
\`\`\`

### All detection combined (-A)

\`\`\`bash
nmap -A 192.168.1.1
# Combines: -sV (version), -O (OS), -sC (scripts), --traceroute
\`\`\`

---

## PART 6: NSE (NMAP SCRIPTING ENGINE) - BEGINNER

### Default scripts (-sC)

\`\`\`bash
nmap -sC 192.168.1.1
\`\`\`

### Specific script

\`\`\`bash
nmap --script ssh-hostkey 192.168.1.1
\`\`\`

### Multiple scripts

\`\`\`bash
nmap --script=http-title,http-robots.txt 192.168.1.1
\`\`\`

### Script category

\`\`\`bash
nmap --script default 192.168.1.1
nmap --script vuln 192.168.1.1
\`\`\`

### Find available scripts

\`\`\`bash
ls /usr/share/nmap/scripts/
nmap --script-help=ssl-cert
\`\`\`

---

## PART 7: TIMING & PERFORMANCE

### Timing templates (-T0 to -T5)

\`\`\`bash
nmap -T0 192.168.1.1    # Paranoid (slowest, stealthiest)
nmap -T1 192.168.1.1    # Sneaky
nmap -T2 192.168.1.1    # Polite
nmap -T3 192.168.1.1    # Normal (default)
nmap -T4 192.168.1.1    # Aggressive
nmap -T5 192.168.1.1    # Insane (fastest, most aggressive)
\`\`\`

### Manual timing control

\`\`\`bash
nmap --scan-delay 5s 192.168.1.1
nmap --min-rate 50 192.168.1.1
nmap --max-rate 100 192.168.1.1
\`\`\`

---

## PART 8: OUTPUT FORMATS

### Normal output

\`\`\`bash
nmap 192.168.1.1
\`\`\`

### Verbosity

\`\`\`bash
nmap -v 192.168.1.1
nmap -vv 192.168.1.1
\`\`\`

### Save to file (normal format)

\`\`\`bash
nmap -oN output.txt 192.168.1.1
\`\`\`

### Save to XML (for parsing)

\`\`\`bash
nmap -oX output.xml 192.168.1.1
\`\`\`

### Save all formats

\`\`\`bash
nmap -oA output 192.168.1.1
\`\`\`

---

## PART 9: COMMON REAL-WORLD SCENARIOS

### Scenario 1: Quick host discovery

\`\`\`bash
nmap -sn 192.168.1.0/24 -oN alive_hosts.txt
\`\`\`

### Scenario 2: Full service audit

\`\`\`bash
sudo nmap -sS -p- -sV -O -sC --script=vuln 192.168.1.10 -oA server_scan
\`\`\`

### Scenario 3: Web server vulnerabilities

\`\`\`bash
nmap -p 80,443,8080,8443 --script=http-* --script=ssl-* 192.168.1.1
\`\`\`

### Scenario 4: Database enumeration

\`\`\`bash
nmap -p 3306,5432,1433 --script db-* 192.168.1.1
\`\`\`

### Scenario 5: Windows/SMB enumeration

\`\`\`bash
nmap -p 139,445 --script smb-* 192.168.1.1
\`\`\`

---

## PART 10: COMMON PORT REFERENCE

| Port | Service | Protocol |
|------|---------|----------|
| 21 | FTP | TCP |
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | TCP/UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 143 | IMAP | TCP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 3306 | MySQL | TCP |
| 3389 | RDP | TCP |
| 5432 | PostgreSQL | TCP |
| 5900 | VNC | TCP |
| 8080 | HTTP Alt | TCP |

---

## PART 11: ADVANCED TECHNIQUES

### Fragmentation and Decoys

\`\`\`bash
nmap -f -f 192.168.1.1  # Multiple fragmentation
nmap -f -D 192.168.1.5,192.168.1.6,ME 192.168.1.1  # With decoys
nmap -D RND:5 192.168.1.1  # 5 random decoys
\`\`\`

### Idle Scan (Zombie Scanning)

\`\`\`bash
nmap -sI zombiehost:proxyport targethost
nmap --script ipidseq 192.168.1.1  # Find idle host
\`\`\`

### Custom Ping Combinations

\`\`\`bash
nmap -PE -PA80 -PU53 -PP 192.168.1.0/24  # Multiple ping types
nmap -Pn 192.168.1.1 -p 1-65535  # No ping
nmap -PR 192.168.1.0/24  # ARP ping
\`\`\`

### Adaptive Timing

\`\`\`bash
nmap -T4 --initial-rtt-timeout 50ms --max-rtt-timeout 5000ms 192.168.1.1
nmap -T1 --initial-rtt-timeout 1000ms --max-rtt-timeout 10000ms 192.168.1.1
\`\`\`

---

## PART 12: NSE ADVANCED

### All NSE Categories

\`\`\`bash
nmap --script auth 192.168.1.1         # Authentication bypass
nmap --script brute 192.168.1.1        # Brute force attacks
nmap --script discovery 192.168.1.1    # Service discovery
nmap --script dos 192.168.1.1          # Denial of Service
nmap --script exploit 192.168.1.1      # Exploitation
nmap --script fuzzer 192.168.1.1       # Fuzzing
nmap --script intrusive 192.168.1.1    # Intrusive tests
nmap --script malware 192.168.1.1      # Malware detection
nmap --script safe 192.168.1.1         # Safe scripts
nmap --script version 192.168.1.1      # Version detection
nmap --script vuln 192.168.1.1         # Vulnerability detection
\`\`\`

### Web Application Assessment

\`\`\`bash
nmap -p 80,443,8080,8443,8000,8888 \\
  --script=http-*,ssl-*,web-* \\
  --script-args http.useragent="Mozilla/5.0" \\
  -sV -A \\
  -oX web_assessment.xml \\
  192.168.1.0/24
\`\`\`

### Database Security

\`\`\`bash
nmap -p 3306 --script=mysql-* 192.168.1.1      # MySQL
nmap -p 5432 --script=postgres-* 192.168.1.1   # PostgreSQL
nmap -p 1433 --script=mssql-* 192.168.1.1      # MSSQL
nmap -p 27017 --script=mongodb-* 192.168.1.1   # MongoDB
nmap -p 6379 --script=redis-* 192.168.1.1      # Redis
\`\`\`

### SMB/Windows Security

\`\`\`bash
nmap -p 139,445 --script=smb-*,cifs-* -sV -O 192.168.1.0/24
nmap -p 445 --script=smb-enum-shares 192.168.1.1
nmap -p 445 --script=smb-os-discovery 192.168.1.1
nmap -p 445 --script=smb-vuln-* 192.168.1.1
\`\`\`

---

## PART 13: LARGE-SCALE SCANNING

### Parallel Scanning

\`\`\`bash
BASE_NET="192.168.0"
for i in {0..255}; do
  nmap -sn \${BASE_NET}.\${i}.0/24 -oG results/subnet_\${i}.txt &
  if [ $((i % 10)) -eq 0 ]; then wait; fi
done
wait
\`\`\`

### Performance Optimization

\`\`\`bash
# Low-resource scan
nmap --max-parallelism 50 --max-hostgroup 100 -T3 192.168.1.0/24

# High-performance scan
nmap --max-parallelism 1024 --max-hostgroup 512 -T5 192.168.1.0/24

# Monitor memory
watch -n 1 'ps aux | grep nmap | grep -v grep'
\`\`\`

---

## PART 14: FIREWALL & IDS EVASION

### Ultra-Stealth Scanning

\`\`\`bash
nmap -T0 -f --scan-delay 30 --max-retries 0 \\
  -D RND:10 -g 53 --source-mac 00:11:22:33:44:55 \\
  -e eth0 192.168.1.1
\`\`\`

### IDS/IPS Bypass

\`\`\`bash
nmap -PS22,80,443,3306,5432 192.168.1.0/24  # Unusual port combinations
nmap --ip-options "S" 192.168.1.1            # Strict source route
nmap --randomize-hosts 192.168.1.0/24        # Randomize scan order
nmap -g 53 192.168.1.1                       # Source port spoofing
nmap -sW 192.168.1.1                         # ACK/Window scan
\`\`\`

---

## PART 15: DATA ANALYSIS & REPORTING

### XML Parsing

\`\`\`bash
# Extract all open ports
grep "<port protocol=\"tcp\" portid" scan.xml | grep -o 'portid="[^"]*"' | cut -d'"' -f2 | sort -u

# Find all services
grep "<service" scan.xml | grep -o 'name="[^"]*"' | cut -d'"' -f2 | sort | uniq -c

# Extract host status
grep "<status state=" scan.xml | grep -o 'state="[^"]*"' | sort | uniq -c
\`\`\`

### Integration with Metasploit

\`\`\`bash
nmap -sV -p- -A 192.168.1.0/24 -oX scan.xml
# In Metasploit: db_import scan.xml
\`\`\`

---

## PART 16: CTF & PENETRATION TESTING

### Quick CTF Enumeration

\`\`\`bash
nmap -sC -sV -A 192.168.1.1 -p- -oA ctf_scan
nmap --script all 192.168.1.1 -p- -oG ctf_services.txt
nmap --script http-title,http-robots.txt,http-headers,ssl-cert 192.168.1.1 -p 80,443
\`\`\`

### Vulnerability Assessment

\`\`\`bash
nmap --script vuln 192.168.1.1 -oX vulns.xml
grep "VULNERABLE\\|Exploitable" vulns.xml
nmap --script default-accounts 192.168.1.1
\`\`\`

---

## QUICK COMMAND REFERENCE

\`\`\`bash
# Host discovery
nmap -sn 192.168.1.0/24

# Quick service scan
nmap -sV -p- 192.168.1.1

# Full aggressive scan
nmap -A -T4 192.168.1.1

# Stealth scan
sudo nmap -sS -T0 -D 192.168.1.5 192.168.1.1

# UDP scan
sudo nmap -sU 192.168.1.1

# OS fingerprint
sudo nmap -O 192.168.1.1

# Find web vulnerabilities
nmap --script http-* 192.168.1.1 -p 80,443

# Export results
nmap -oA results 192.168.1.1

# Comprehensive scan
nmap -sS -p- -sV -O -sC --script=vuln -oA comprehensive 192.168.1.1
\`\`\`

---

## LEGAL AND ETHICAL CONSIDERATIONS

⚠️ **IMPORTANT:**
- Only scan networks you have permission to scan
- Unauthorized network scanning is illegal
- Always get written approval before penetration testing
- Keep detailed logs of all scanning activities
- Use Nmap responsibly in authorized security assessments
- Follow responsible disclosure practices
- Respect privacy laws (GDPR, HIPAA, etc.)

---

## RESOURCES

- Official Nmap Book: https://nmap.org/book/
- NSE Documentation: https://nmap.org/nsedoc/
- Nmap Reference Guide: https://linux.die.net/man/1/nmap
- Zenmap GUI: https://nmap.org/zenmap/
- Nmap Community: https://nmap.org/community/
`;

const NMAP_COMPLETE_TR = `# Nmap - Network Mapper: Tam Kapsamlı Rehber (Başlangıç  Uzmanl)

## BÖLÜM 1: BAŞLANGÇ TEMELLERI

### Nmap Nedir?

Nmap (Network Mapper), ağ keşfi ve güvenlik denetimi için ücretsiz ve açık kaynaklı bir yardımcı programdır.

### Kurulum

**Linux (Debian/Ubuntu):**
\`\`\`bash
sudo apt update
sudo apt install nmap
\`\`\`

**macOS:**
\`\`\`bash
brew install nmap
\`\`\`

**Kurulumu Doğrula:**
\`\`\`bash
nmap --version
\`\`\`

---

## BÖLÜM 2: TEMEL TARAMA TÜRLERİ

### TCP Connect Taraması (-sT)
\`\`\`bash
nmap -sT 192.168.1.0/24
\`\`\`

### TCP SYN Taraması (-sS)
\`\`\`bash
sudo nmap -sS 192.168.1.0/24
\`\`\`

### UDP Taraması (-sU)
\`\`\`bash
sudo nmap -sU 192.168.1.0/24
\`\`\`

### ACK Taraması (-sA)
\`\`\`bash
nmap -sA 192.168.1.0/24
\`\`\`

---

## BÖLÜM 3: ANA BİLGİSAYAR KEŞFİ

### Ping Sweep
\`\`\`bash
nmap -sn 192.168.1.0/24
\`\`\`

### Ping Atla
\`\`\`bash
nmap -Pn 192.168.1.1
\`\`\`

### TCP SYN Ping
\`\`\`bash
nmap -PS80,443 192.168.1.0/24
\`\`\`

---

## BÖLÜM 4: PORT SEÇİMİ

### Spesifik Portlar
\`\`\`bash
nmap -p 22,80,443 192.168.1.1
\`\`\`

### Port Aralığı
\`\`\`bash
nmap -p 1-1000 192.168.1.1
\`\`\`

### Tüm Portlar
\`\`\`bash
nmap -p- 192.168.1.1
\`\`\`

---

## BÖLÜM 5: HİZMET VE SÜRÜM ALGLAMASI

### Hizmet Sürümlerini Algıla (-sV)
\`\`\`bash
nmap -sV 192.168.1.1
\`\`\`

### İşletim Sistemi Algıla (-O)
\`\`\`bash
sudo nmap -O 192.168.1.1
\`\`\`

### Tüm Algılamalar (-A)
\`\`\`bash
nmap -A 192.168.1.1
\`\`\`

---

## BÖLÜM 6: NSE (TEMEL)

### Varsayılan Scriptler
\`\`\`bash
nmap -sC 192.168.1.1
\`\`\`

### Belirli Script
\`\`\`bash
nmap --script ssh-hostkey 192.168.1.1
\`\`\`

### Zafiyet Algılama
\`\`\`bash
nmap --script vuln 192.168.1.1
\`\`\`

---

## BÖLÜM 7: ZAMANLAMA & PERFORMANS

### Zamanlama Şablonları
\`\`\`bash
nmap -T0 192.168.1.1    # Paranoid
nmap -T3 192.168.1.1    # Normal
nmap -T5 192.168.1.1    # Hızlı
\`\`\`

---

## BÖLÜM 8: ÇIKTI FORMATLARI

### Normal Çıktı
\`\`\`bash
nmap 192.168.1.1
\`\`\`

### XML'e Kaydet
\`\`\`bash
nmap -oX output.xml 192.168.1.1
\`\`\`

### Tüm Formatlar
\`\`\`bash
nmap -oA output 192.168.1.1
\`\`\`

---

## BÖLÜM 9: GERÇEK DÜNYA SENARYOLARI

### Ana Bilgisayar Keşfi
\`\`\`bash
nmap -sn 192.168.1.0/24 -oN alive_hosts.txt
\`\`\`

### Tam Hizmet Denetimi
\`\`\`bash
sudo nmap -sS -p- -sV -O -sC --script=vuln 192.168.1.10 -oA server_scan
\`\`\`

### Web Sunucusu Zafiyetleri
\`\`\`bash
nmap -p 80,443,8080,8443 --script=http-* --script=ssl-* 192.168.1.1
\`\`\`

### Veritabanı Taraması
\`\`\`bash
nmap -p 3306,5432,1433 --script db-* 192.168.1.1
\`\`\`

### SMB/Windows Taraması
\`\`\`bash
nmap -p 139,445 --script smb-* 192.168.1.1
\`\`\`

---

## BÖLÜM 10: YAYGIN PORT BAŞVURUSU

| Port | Hizmet | Protokol |
|------|--------|----------|
| 21 | FTP | TCP |
| 22 | SSH | TCP |
| 80 | HTTP | TCP |
| 443 | HTTPS | TCP |
| 3306 | MySQL | TCP |
| 5432 | PostgreSQL | TCP |

---

## BÖLÜM 11: GELİŞMİŞ TEKNİKLER

### Parçalanma ve Aldatma
\`\`\`bash
nmap -f -f 192.168.1.1
nmap -D RND:5 192.168.1.1
\`\`\`

### Paralel Tarama
\`\`\`bash
BASE_NET="192.168.0"
for i in {0..255}; do
  nmap -sn \${BASE_NET}.\${i}.0/24 -oG results/subnet_\${i}.txt &
done
wait
\`\`\`

### Ultra-Gizli Tarama
\`\`\`bash
nmap -T0 -f --scan-delay 30 -D RND:10 -g 53 192.168.1.1
\`\`\`

---

## HİZLİ KOMUT BAŞVURUSU

\`\`\`bash
nmap -sn 192.168.1.0/24          # Ana bilgisayar keşfi
nmap -sV -p- 192.168.1.1         # Hizmet taraması
nmap -A -T4 192.168.1.1          # Agresif tarama
nmap -oA results 192.168.1.1     # Sonuçları dışa aktar
\`\`\`

---

## YASAL VE ETİK HUSUSLAR

⚠️ **ÖNEMLİ:**
- Yaln  izniniz olan ağları tarayın
- Yetkisiz tarama yasadışıdır
- Tüm etkinlikleri belgeyin
- Sorumlu açıklama uygulamalarını takip edin

---

## KAYNAKLAR

- Resmi Nmap Rehberi: https://nmap.org/book/
- NSE Belgeleri: https://nmap.org/nsedoc/
- Zenmap: https://nmap.org/zenmap/
`;

async function mergeAndUpdateNmap() {
  try {
    const cheatsheet = await prisma.cheatsheet.update({
      where: { id: 235 },
      data: {
        descEn: NMAP_COMPLETE_EN,
        descTr: NMAP_COMPLETE_TR,
        tags: [
          'nmap',
          'network-scanning',
          'security-audit',
          'reconnaissance',
          'port-scanning',
          'service-detection',
          'beginner',
          'intermediate',
          'advanced',
          'expert-level',
          'evasion',
          'exploitation',
          'complete-guide'
        ]
      }
    });

    console.log('✓ Nmap cheatsheet merged with complete content!');
    console.log(`  ID: ${cheatsheet.id}`);
    console.log(`  Total Content Length EN: ${cheatsheet.descEn.length} characters`);
    console.log(`  Total Content Length TR: ${cheatsheet.descTr.length} characters`);
    console.log(`  Total Tags: ${cheatsheet.tags.length}`);
    console.log(`  Learning Path: Beginner → Intermediate → Advanced → Expert`);
  } catch (error) {
    console.error('✗ Error merging Nmap content:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

mergeAndUpdateNmap();
