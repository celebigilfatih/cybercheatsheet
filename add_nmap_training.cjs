const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const NMAP_EN = `# Nmap - Network Mapper: Complete Training Guide

## What is Nmap?

Nmap (Network Mapper) is a free and open-source utility for network discovery and security auditing. It uses raw IP packets to determine:
- What hosts are available on the network
- What services (application name and version) those hosts are offering
- What operating systems they are running
- What type of packet filters/firewalls are in use
- And dozens of other characteristics

## Installation

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
\`\`\`powershell
choco install nmap
\`\`\`

**Verify Installation:**
\`\`\`bash
nmap --version
\`\`\`

---

## Basic Concepts

### Scan Types

**TCP Connect Scan (-sT):**
- Completes full three-way handshake
- Slower but most reliable
- Leaves logs on target systems
\`\`\`bash
nmap -sT 192.168.1.0/24
\`\`\`

**TCP SYN Scan (-sS) [Stealth Scan]:**
- Default for root users
- Sends SYN, receives SYN-ACK, sends RST (never completes handshake)
- Faster, less logged
- Requires raw socket privileges
\`\`\`bash
sudo nmap -sS 192.168.1.0/24
\`\`\`

**UDP Scan (-sU):**
- Scans UDP ports
- Slower than TCP scans
- Many services use UDP (DNS, SNMP, DHCP)
\`\`\`bash
sudo nmap -sU 192.168.1.0/24
\`\`\`

**ACK Scan (-sA):**
- Used to map firewall rule sets
- Determines if ports are filtered or unfiltered
- Can't determine if ports are open
\`\`\`bash
nmap -sA 192.168.1.0/24
\`\`\`

**NULL, FIN, Xmas Scans (-sN, -sF, -sX):**
- Advanced scans that exploit TCP RFC compliance
- Useful against old systems
- Modern systems often don't respond properly
\`\`\`bash
nmap -sN 192.168.1.1
nmap -sF 192.168.1.1
nmap -sX 192.168.1.1
\`\`\`

---

## Common Scan Options

### Host Discovery

**Ping Sweep (Find alive hosts):**
\`\`\`bash
nmap -sn 192.168.1.0/24
\`\`\`

**Skip ping (assume hosts are alive):**
\`\`\`bash
nmap -Pn 192.168.1.1
\`\`\`

**ICMP Echo Request:**
\`\`\`bash
nmap -PE 192.168.1.0/24
\`\`\`

**TCP SYN Ping:**
\`\`\`bash
nmap -PS80,443 192.168.1.0/24
\`\`\`

**TCP ACK Ping:**
\`\`\`bash
nmap -PA80,443 192.168.1.0/24
\`\`\`

---

### Port Selection

**Scan common ports:**
\`\`\`bash
nmap 192.168.1.1
\`\`\`

**Scan specific ports:**
\`\`\`bash
nmap -p 22,80,443 192.168.1.1
\`\`\`

**Scan port range:**
\`\`\`bash
nmap -p 1-1000 192.168.1.1
\`\`\`

**Scan all 65535 ports:**
\`\`\`bash
nmap -p- 192.168.1.1
\`\`\`

**Scan all ports except specific:**
\`\`\`bash
nmap -p- --exclude-ports 22 192.168.1.1
\`\`\`

**Scan by service name:**
\`\`\`bash
nmap -p http,https,ssh 192.168.1.1
\`\`\`

---

### Service and Version Detection

**Detect service versions (-sV):**
\`\`\`bash
nmap -sV 192.168.1.1
\`\`\`

**Aggressive detection (combines multiple methods):**
\`\`\`bash
nmap -sV --version-intensity 9 192.168.1.1
\`\`\`

**Detect OS (-O):**
\`\`\`bash
sudo nmap -O 192.168.1.1
\`\`\`

**All detection combined (-A):**
\`\`\`bash
nmap -A 192.168.1.1
# Combines: -sV (version), -O (OS), -sC (scripts), --traceroute
\`\`\`

---

### NSE (Nmap Scripting Engine)

**Default scripts (-sC):**
\`\`\`bash
nmap -sC 192.168.1.1
\`\`\`

**Specific script:**
\`\`\`bash
nmap --script ssh-hostkey 192.168.1.1
\`\`\`

**Multiple scripts:**
\`\`\`bash
nmap --script=http-title,http-robots.txt 192.168.1.1
\`\`\`

**Script category:**
\`\`\`bash
nmap --script default 192.168.1.1
nmap --script vuln 192.168.1.1
nmap --script exploit 192.168.1.1
\`\`\`

**Script with arguments:**
\`\`\`bash
nmap --script http-header --script-args http.useragent="Mozilla/5.0" 192.168.1.1
\`\`\`

**Find available scripts:**
\`\`\`bash
ls /usr/share/nmap/scripts/
nmap --script-help=ssl-cert
\`\`\`

---

### Timing and Performance

**Timing templates (-T0 to -T5):**
\`\`\`bash
nmap -T0 192.168.1.1    # Paranoid (slowest, stealthiest)
nmap -T1 192.168.1.1    # Sneaky
nmap -T2 192.168.1.1    # Polite
nmap -T3 192.168.1.1    # Normal (default)
nmap -T4 192.168.1.1    # Aggressive
nmap -T5 192.168.1.1    # Insane (fastest, most aggressive)
\`\`\`

**Manual timing control:**
\`\`\`bash
nmap --scan-delay 5s 192.168.1.1
nmap --max-scan-delay 60s 192.168.1.1
nmap --min-rate 50 192.168.1.1
nmap --max-rate 100 192.168.1.1
\`\`\`

**Parallel threads:**
\`\`\`bash
nmap -p- --max-parallelism 100 192.168.1.1
\`\`\`

---

### Output Formats

**Normal output:**
\`\`\`bash
nmap 192.168.1.1
\`\`\`

**Verbosity (-v for more details, -vv for extra verbose):**
\`\`\`bash
nmap -v 192.168.1.1
nmap -vv 192.168.1.1
\`\`\`

**Debug output:**
\`\`\`bash
nmap -d 192.168.1.1
\`\`\`

**Save to file (normal format):**
\`\`\`bash
nmap -oN output.txt 192.168.1.1
\`\`\`

**Save to XML (for parsing):**
\`\`\`bash
nmap -oX output.xml 192.168.1.1
\`\`\`

**Save to grepable format:**
\`\`\`bash
nmap -oG output.gnmap 192.168.1.1
\`\`\`

**Save all formats:**
\`\`\`bash
nmap -oA output 192.168.1.1
\`\`\`

---

## Real-World Scenarios

### Scenario 1: Quick host discovery on network

**Objective:** Find all alive hosts on a subnet

\`\`\`bash
nmap -sn 192.168.1.0/24 -oN alive_hosts.txt
\`\`\`

**Output analysis:**
- Lists all responds to ping
- Fast and non-intrusive
- Good for network mapping

---

### Scenario 2: Full service audit of critical server

**Objective:** Comprehensive scan with service versions, OS detection, and vulnerability checks

\`\`\`bash
sudo nmap -sS -p- -sV -O -sC --script=vuln,version 192.168.1.10 -oA critical_server_scan
\`\`\`

**Breakdown:**
- \`-sS\`: Stealth SYN scan
- \`-p-\`: All 65535 ports
- \`-sV\`: Service version detection
- \`-O\`: OS detection
- \`-sC\`: Default safe scripts
- \`--script=vuln\`: Vulnerability checks
- \`-oA\`: Output all formats

---

### Scenario 3: Detect web server vulnerabilities

**Objective:** Find web vulnerabilities on a web server

\`\`\`bash
nmap -p 80,443,8080,8443 --script=http-* --script=ssl-* 192.168.1.1
\`\`\`

**Specific checks:**
\`\`\`bash
nmap --script=http-title,http-robots.txt,http-headers,ssl-cert 192.168.1.1 -p 443
\`\`\`

---

### Scenario 4: Firewall evasion and stealth

**Objective:** Scan while minimizing detection

\`\`\`bash
# Ultra-stealthy scan
nmap -T0 -f --scan-delay 5 -D 192.168.1.5,192.168.1.6 192.168.1.1

# -T0: Paranoid timing
# -f: Fragment packets
# --scan-delay: 5 second delay between probes
# -D: Decoy scan (spoof source IP)
\`\`\`

**More options:**
\`\`\`bash
nmap -g 53 192.168.1.1         # Use source port 53 (DNS)
nmap --source-ip 192.168.1.5 192.168.1.1    # Spoof source IP
nmap -e eth1 192.168.1.1       # Use specific interface
\`\`\`

---

### Scenario 5: NMAP + Advanced parsing

**Find all open ports and create report:**
\`\`\`bash
#!/bin/bash
TARGET=192.168.1.1
TIMESTAMP=\$(date +%Y%m%d_%H%M%S)

# Scan
nmap -sS -p- -sV -O -oX \${TIMESTAMP}_scan.xml \$TARGET

# Parse XML for open ports
grep "state state=\"open\"" \${TIMESTAMP}_scan.xml | wc -l

# Export to CSV
echo "Port,Service,Version" > \${TIMESTAMP}_services.csv
nmap -sV -oX - \$TARGET | grep "portid" | awk -F'\"' '{print \$2 "," \$4 "," \$6}' >> \${TIMESTAMP}_services.csv
\`\`\`

---

## Practical Tips

### Performance Optimization

**For large networks:**
\`\`\`bash
# Use fast timing and parallel
nmap -T4 -p- --max-parallelism 256 192.168.1.0/24

# Split workload
nmap -p 1-16384 192.168.1.0/24 &
nmap -p 16385-32768 192.168.1.0/24 &
nmap -p 32769-65535 192.168.1.0/24 &
\`\`\`

### Reduce false positives

\`\`\`bash
# Increase retries for unreliable networks
nmap --max-retries 5 192.168.1.1

# Use UDP with increased timeout
nmap -sU --max-retries 3 192.168.1.1
\`\`\`

### Working with Proxies

\`\`\`bash
# Use Proxychains
proxychains nmap 192.168.1.1
\`\`\`

---

## Common Port Reference

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

## Legal and Ethical Considerations

⚠️ **IMPORTANT:**
- Only scan networks you have permission to scan
- Unauthorized network scanning is illegal
- Always get written approval before penetration testing
- Use Nmap responsibly in authorized security assessments
- Keep detailed logs of all scanning activities

---

## Useful Resources

- **Official Nmap Book:** https://nmap.org/book/
- **NSE Documentation:** https://nmap.org/nsedoc/
- **Nmap Reference Guide:** https://linux.die.net/man/1/nmap
- **Common Scripts:** https://nmap.org/nsedoc/scripts/

---

## Quick Command Reference

\`\`\`bash
# Host alive check
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

# Find web vulns
nmap --script http-* 192.168.1.1 -p 80,443

# Export results
nmap -oA results 192.168.1.1
\`\`\`
`;

const NMAP_TR = `# Nmap - Network Mapper: Kapsamlı Eğitim Rehberi

## Nmap Nedir?

Nmap (Network Mapper), ağ keşfi ve güvenlik denetimi için ücretsiz ve açık kaynaklı bir yardımcı programdır. Ham IP paketleri kullanarak şunları belirler:
- Ağda hangi ana bilgisayarlar (host) mevcuttur
- Bu ana bilgisayarlar hangi hizmetleri (uygulama adı ve sürümü) sunmaktadır
- Hangi işletim sistemlerini çalıştırmaktadırlar
- Ne tür paket filtreleri/güvenlik duvarı kullanmaktadırlar
- Ve daha birçok özellik

## Kurulum

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
https://nmap.org/download.html adresinden indirin veya:
\`\`\`powershell
choco install nmap
\`\`\`

**Kurulumu Doğrula:**
\`\`\`bash
nmap --version
\`\`\`

---

## Temel Kavramlar

### Tarama Türleri

**TCP Connect Taraması (-sT):**
- Tam üç yollu el sıkışmayı tamamlar
- Daha yavaş ama en güvenilir
- Hedef sistemlerde günlükler bırakır
\`\`\`bash
nmap -sT 192.168.1.0/24
\`\`\`

**TCP SYN Taraması (-sS) [Gizli Tarama]:**
- Root kullanıcılar için varsayılan
- SYN gönderir, SYN-ACK alır, RST gönderir (asla el sıkışmayı tamamlamaz)
- Daha hızlı, daha az kaydedilir
- Ham soket ayrıcalıkları gerektirir
\`\`\`bash
sudo nmap -sS 192.168.1.0/24
\`\`\`

**UDP Taraması (-sU):**
- UDP portlarını tarar
- TCP taramalarından daha yavaş
- Birçok hizmet UDP kullanır (DNS, SNMP, DHCP)
\`\`\`bash
sudo nmap -sU 192.168.1.0/24
\`\`\`

**ACK Taraması (-sA):**
- Güvenlik duvarı kural setlerini eşlemek için kullanılır
- Portların filtrelenip filtrelenmediğini belirler
- Portların açık olup olmadığını belirleyemez
\`\`\`bash
nmap -sA 192.168.1.0/24
\`\`\`

**NULL, FIN, Xmas Taramaları (-sN, -sF, -sX):**
- TCP RFC uyumluluğundan yararlanan gelişmiş taramalar
- Eski sistemlere karşı kullanışlı
- Modern sistemler çoğu zaman düzgün yanıt vermez
\`\`\`bash
nmap -sN 192.168.1.1
nmap -sF 192.168.1.1
nmap -sX 192.168.1.1
\`\`\`

---

## Yaygın Tarama Seçenekleri

### Ana Bilgisayar Keşfi

**Ping Sweep (Canlı ana bilgisayarları bul):**
\`\`\`bash
nmap -sn 192.168.1.0/24
\`\`\`

**Ping atla (ana bilgisayarların canlı olduğunu varsay):**
\`\`\`bash
nmap -Pn 192.168.1.1
\`\`\`

**ICMP Echo İsteği:**
\`\`\`bash
nmap -PE 192.168.1.0/24
\`\`\`

**TCP SYN Ping:**
\`\`\`bash
nmap -PS80,443 192.168.1.0/24
\`\`\`

**TCP ACK Ping:**
\`\`\`bash
nmap -PA80,443 192.168.1.0/24
\`\`\`

---

### Port Seçimi

**Yaygın portları tara:**
\`\`\`bash
nmap 192.168.1.1
\`\`\`

**Belirli portları tara:**
\`\`\`bash
nmap -p 22,80,443 192.168.1.1
\`\`\`

**Port aralığını tara:**
\`\`\`bash
nmap -p 1-1000 192.168.1.1
\`\`\`

**Tüm 65535 portu tara:**
\`\`\`bash
nmap -p- 192.168.1.1
\`\`\`

**Belirli portlar hariç tüm portları tara:**
\`\`\`bash
nmap -p- --exclude-ports 22 192.168.1.1
\`\`\`

**Hizmet adına göre tara:**
\`\`\`bash
nmap -p http,https,ssh 192.168.1.1
\`\`\`

---

### Hizmet ve Sürüm Algılama

**Hizmet sürümlerini algıla (-sV):**
\`\`\`bash
nmap -sV 192.168.1.1
\`\`\`

**Agresif algılama (birden fazla yöntemi birleştirir):**
\`\`\`bash
nmap -sV --version-intensity 9 192.168.1.1
\`\`\`

**İşletim Sistemi Algıla (-O):**
\`\`\`bash
sudo nmap -O 192.168.1.1
\`\`\`

**Tüm algılamaları birleştir (-A):**
\`\`\`bash
nmap -A 192.168.1.1
# Birleştirme: -sV (sürüm), -O (İS), -sC (scriptler), --traceroute
\`\`\`

---

### NSE (Nmap Scripting Engine)

**Varsayılan scriptler (-sC):**
\`\`\`bash
nmap -sC 192.168.1.1
\`\`\`

**Belirli script:**
\`\`\`bash
nmap --script ssh-hostkey 192.168.1.1
\`\`\`

**Birden fazla script:**
\`\`\`bash
nmap --script=http-title,http-robots.txt 192.168.1.1
\`\`\`

**Script kategorisi:**
\`\`\`bash
nmap --script default 192.168.1.1
nmap --script vuln 192.168.1.1
nmap --script exploit 192.168.1.1
\`\`\`

**Script argümanları ile:**
\`\`\`bash
nmap --script http-header --script-args http.useragent="Mozilla/5.0" 192.168.1.1
\`\`\`

**Kullanılabilir scriptleri bul:**
\`\`\`bash
ls /usr/share/nmap/scripts/
nmap --script-help=ssl-cert
\`\`\`

---

### Zamanlama ve Performans

**Zamanlama şablonları (-T0 to -T5):**
\`\`\`bash
nmap -T0 192.168.1.1    # Paranoid (en yavaş, en gizli)
nmap -T1 192.168.1.1    # Sneaky
nmap -T2 192.168.1.1    # Polite
nmap -T3 192.168.1.1    # Normal (varsayılan)
nmap -T4 192.168.1.1    # Aggressive
nmap -T5 192.168.1.1    # Insane (en hızlı, en agresif)
\`\`\`

**Manuel zamanlama kontrolü:**
\`\`\`bash
nmap --scan-delay 5s 192.168.1.1
nmap --max-scan-delay 60s 192.168.1.1
nmap --min-rate 50 192.168.1.1
nmap --max-rate 100 192.168.1.1
\`\`\`

**Paralel threadler:**
\`\`\`bash
nmap -p- --max-parallelism 100 192.168.1.1
\`\`\`

---

### Çıktı Formatları

**Normal çıktı:**
\`\`\`bash
nmap 192.168.1.1
\`\`\`

**Ayrıntılılık (-v daha fazla detay için, -vv ekstra ayrıntılı için):**
\`\`\`bash
nmap -v 192.168.1.1
nmap -vv 192.168.1.1
\`\`\`

**Hata Ayıklama çıktısı:**
\`\`\`bash
nmap -d 192.168.1.1
\`\`\`

**Dosyaya kaydet (normal format):**
\`\`\`bash
nmap -oN output.txt 192.168.1.1
\`\`\`

**XML'e kaydet (ayrıştırma için):**
\`\`\`bash
nmap -oX output.xml 192.168.1.1
\`\`\`

**Grep yapılabilir formata kaydet:**
\`\`\`bash
nmap -oG output.gnmap 192.168.1.1
\`\`\`

**Tüm formatları kaydet:**
\`\`\`bash
nmap -oA output 192.168.1.1
\`\`\`

---

## Gerçek Dünya Senaryoları

### Senaryo 1: Ağda hızlı ana bilgisayar keşfi

**Hedef:** Subnet'teki tüm canlı ana bilgisayarları bul

\`\`\`bash
nmap -sn 192.168.1.0/24 -oN alive_hosts.txt
\`\`\`

**Çıktı analizi:**
- Ping'e yanıt veren tüm ana bilgisayarları listeler
- Hızlı ve az müdahaleci
- Ağ haritalaması için iyi

---

### Senaryo 2: Kritik sunucunun tam hizmet denetimi

**Hedef:** Hizmet sürümleri, İS algılama ve zafiyet kontrolleri ile kapsamlı tarama

\`\`\`bash
sudo nmap -sS -p- -sV -O -sC --script=vuln,version 192.168.1.10 -oA critical_server_scan
\`\`\`

**Detaylı Açıklama:**
- \`-sS\`: Gizli SYN taraması
- \`-p-\`: Tüm 65535 port
- \`-sV\`: Hizmet sürümü algılama
- \`-O\`: İS algılama
- \`-sC\`: Varsayılan güvenli scriptler
- \`--script=vuln\`: Zafiyet kontrolleri
- \`-oA\`: Tüm formatları çıkart

---

### Senaryo 3: Web sunucusu zafiyetlerini algıla

**Hedef:** Bir web sunucusunda web zafiyetlerini bul

\`\`\`bash
nmap -p 80,443,8080,8443 --script=http-* --script=ssl-* 192.168.1.1
\`\`\`

**Belirli kontroller:**
\`\`\`bash
nmap --script=http-title,http-robots.txt,http-headers,ssl-cert 192.168.1.1 -p 443
\`\`\`

---

### Senaryo 4: Güvenlik duvarı kaçışı ve gizlilik

**Hedef:** Algılanmayı en aza indirerek tarama yapın

\`\`\`bash
# Ultra-gizli tarama
nmap -T0 -f --scan-delay 5 -D 192.168.1.5,192.168.1.6 192.168.1.1

# -T0: Paranoid zamanlama
# -f: Paketleri parçala
# --scan-delay: Araştırmalar arasında 5 saniye gecikmesi
# -D: Decoy taraması (kaynak IP'yi taklit et)
\`\`\`

**Daha Fazla Seçenek:**
\`\`\`bash
nmap -g 53 192.168.1.1         # Kaynak port 53 (DNS) kullan
nmap --source-ip 192.168.1.5 192.168.1.1    # Kaynak IP'yi taklit et
nmap -e eth1 192.168.1.1       # Belirli arayüz kullan
\`\`\`

---

### Senaryo 5: NMAP + Gelişmiş Ayrıştırma

**Tüm açık portları bul ve rapor oluştur:**
\`\`\`bash
#!/bin/bash
TARGET=192.168.1.1
TIMESTAMP=\$(date +%Y%m%d_%H%M%S)

# Tara
nmap -sS -p- -sV -O -oX \${TIMESTAMP}_scan.xml \$TARGET

# Açık portlar için XML'i ayrıştır
grep "state state=\\"open\\"" \${TIMESTAMP}_scan.xml | wc -l

# CSV'ye aktar
echo "Port,Service,Version" > \${TIMESTAMP}_services.csv
nmap -sV -oX - \$TARGET | grep "portid" | awk -F'\"' '{print \$2 "," \$4 "," \$6}' >> \${TIMESTAMP}_services.csv
\`\`\`

---

## Pratik İpuçları

### Performans Optimizasyonu

**Büyük ağlar için:**
\`\`\`bash
# Hızlı zamanlama ve paralel kullan
nmap -T4 -p- --max-parallelism 256 192.168.1.0/24

# İş yükünü böl
nmap -p 1-16384 192.168.1.0/24 &
nmap -p 16385-32768 192.168.1.0/24 &
nmap -p 32769-65535 192.168.1.0/24 &
\`\`\`

### Yanlış pozitifleri azalt

\`\`\`bash
# Güvenilmez ağlar için yeniden deneme sayısını artır
nmap --max-retries 5 192.168.1.1

# UDP ile artırılmış zaman aşımı
nmap -sU --max-retries 3 192.168.1.1
\`\`\`

### Proxy'lerle Çalışma

\`\`\`bash
# Proxychains kullan
proxychains nmap 192.168.1.1
\`\`\`

---

## Yaygın Port Referansı

| Port | Hizmet | Protokol |
|------|--------|----------|
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

## Yasal ve Etik Hususlar

⚠️ **ÖNEMLİ:**
- Yalnızca tarama yapma izniniz olan ağları tarayın
- Yetkisiz ağ taraması yasadışıdır
- Penetrasyon testinden önce daima yazılı onay alın
- Nmap'i yetkili güvenlik değerlendirmelerinde sorumlu bir şekilde kullanın
- Tüm tarama faaliyetlerinin ayrıntılı günlüğünü tutun

---

## Kullanışlı Kaynaklar

- **Resmi Nmap Kitabı:** https://nmap.org/book/
- **NSE Belgelendirmesi:** https://nmap.org/nsedoc/
- **Nmap Referans Rehberi:** https://linux.die.net/man/1/nmap
- **Yaygın Scriptler:** https://nmap.org/nsedoc/scripts/

---

## Hızlı Komut Referansı

\`\`\`bash
# Ana bilgisayar canlılık kontrolü
nmap -sn 192.168.1.0/24

# Hızlı hizmet taraması
nmap -sV -p- 192.168.1.1

# Tam agresif tarama
nmap -A -T4 192.168.1.1

# Gizli tarama
sudo nmap -sS -T0 -D 192.168.1.5 192.168.1.1

# UDP taraması
sudo nmap -sU 192.168.1.1

# İS parmak izi
sudo nmap -O 192.168.1.1

# Web zafiyetlerini bul
nmap --script http-* 192.168.1.1 -p 80,443

# Sonuçları dışa aktar
nmap -oA results 192.168.1.1
\`\`\`
`;

async function addNmapCheatsheet() {
  try {
    // Check if Nmap cheatsheet already exists
    const existing = await prisma.cheatsheet.findFirst({
      where: {
        titleEn: 'Nmap - Network Mapper: Complete Training Guide'
      }
    });

    if (existing) {
      console.log('✓ Nmap cheatsheet already exists');
      return;
    }

    const cheatsheet = await prisma.cheatsheet.create({
      data: {
        titleEn: 'Nmap - Network Mapper: Complete Training Guide',
        titleTr: 'Nmap - Network Mapper: Kapsamlı Eğitim Rehberi',
        descEn: NMAP_EN,
        descTr: NMAP_TR,
        tags: ['nmap', 'network-scanning', 'security-audit', 'reconnaissance', 'port-scanning', 'service-detection'],
        links: [
          'https://nmap.org/',
          'https://nmap.org/book/',
          'https://nmap.org/nsedoc/',
          'https://linux.die.net/man/1/nmap'
        ],
        categoryId: 64 // Network Scanning
      }
    });

    console.log('✓ Nmap cheatsheet added successfully!');
    console.log(`  ID: ${cheatsheet.id}`);
    console.log(`  Title EN: ${cheatsheet.titleEn}`);
    console.log(`  Title TR: ${cheatsheet.titleTr}`);
    console.log(`  Content Length EN: ${cheatsheet.descEn.length} characters`);
    console.log(`  Content Length TR: ${cheatsheet.descTr.length} characters`);
  } catch (error) {
    console.error('✗ Error adding Nmap cheatsheet:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

addNmapCheatsheet();
