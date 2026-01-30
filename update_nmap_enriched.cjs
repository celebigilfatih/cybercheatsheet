const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const NMAP_ENRICHED_EN = `# Nmap - Network Mapper: Ultimate Comprehensive Training Guide

## 🟢 PART 1: THE BASICS (FOR BEGINNERS)

### What is Nmap?
Nmap (Network Mapper) is a free and open-source utility for network discovery and security auditing. It is used to discover hosts and services on a computer network by sending packets and analyzing the responses.

### 💿 Installation
- **Debian/Ubuntu**: \`sudo apt install nmap -y\`
- **MacOS**: \`brew install nmap\`
- **Windows**: [nmap.org/download.html](https://nmap.org/download.html)

### 🚀 Quick Start Examples
\`\`\`bash
nmap 192.168.1.1              # Scan a single IP
nmap scanme.nmap.org          # Scan a hostname
nmap 192.168.1.1-50           # Scan a range of IPs
nmap 192.168.1.0/24           # Scan an entire subnet
nmap -iL targets.txt          # Scan targets from a file
\`\`\`

---

## 🟡 PART 2: CORE SCANNING TECHNIQUES

### TCP SYN Scan (Stealth Scan)
The default and most popular scan. It's fast and relatively stealthy as it never completes TCP connections.
\`\`\`bash
sudo nmap -sS 192.168.1.1
\`\`\`

### TCP Connect Scan
Used when the user does not have raw packet privileges (non-root).
\`\`\`bash
nmap -sT 192.168.1.1
\`\`\`

### UDP Scan
UDP is often overlooked. Use this to find DNS, SNMP, and DHCP services.
\`\`\`bash
sudo nmap -sU 192.168.1.1
\`\`\`

### Aggressive Scan (-A)
Enables OS detection, version detection, script scanning, and traceroute.
\`\`\`bash
nmap -A 192.168.1.1
\`\`\`

---

## 🟠 PART 3: PORT SPECIFICATION & SERVICE DETECTION

### Specific Ports
\`\`\`bash
nmap -p 80,443 192.168.1.1        # Scan specific ports
nmap -p 1-65535 192.168.1.1       # Scan all ports
nmap -p- 192.168.1.1              # Shortcut for all ports
nmap -F 192.168.1.1               # Fast scan (top 100 ports)
nmap --top-ports 20 192.168.1.1   # Scan top 20 most common ports
\`\`\`

### Service/Version Detection
Determine what service is running on the port and its version.
\`\`\`bash
nmap -sV 192.168.1.1
nmap -sV --version-intensity 5 192.168.1.1 # Max intensity
\`\`\`

---

## 🔴 PART 4: NSE (NMAP SCRIPTING ENGINE) - THE POWERHOUSE

### Using Default Scripts
\`\`\`bash
nmap -sC 192.168.1.1
\`\`\`

### Vulnerability Scanning
One of the most useful script categories.
\`\`\`bash
nmap --script vuln 192.168.1.1
\`\`\`

### Bruteforce Attacks
\`\`\`bash
nmap --script ssh-brute 192.168.1.1
nmap --script ftp-brute 192.168.1.1
nmap --script http-form-brute 192.168.1.1
\`\`\`

### HTTP Discovery
\`\`\`bash
nmap --script http-enum 192.168.1.1
nmap --script http-title 192.168.1.1
nmap --script http-robots.txt 192.168.1.1
\`\`\`

---

## 🟣 PART 5: ADVANCED EVASION & STEALTH

### Fragmentation
Split packets into smaller pieces to bypass simple firewalls/IDS.
\`\`\`bash
nmap -f 192.168.1.1
\`\`\`

### Decoys
Make it look like the scan is coming from multiple sources.
\`\`\`bash
nmap -D 192.168.1.5,192.168.1.10,ME 192.168.1.1
\`\`\`

### Spoofing
\`\`\`bash
nmap -S 1.2.3.4 192.168.1.1      # Spoof Source IP
nmap -g 53 192.168.1.1           # Spoof Source Port (DNS)
nmap --proxies http://1.2.3.4:8080 192.168.1.1
\`\`\`

---

## 🔥 PART 6: EXPERT-LEVEL SCENARIOS (REAL WORLD)

### Scenario A: Full Infrastructure Audit
\`\`\`bash
sudo nmap -sS -p- -sV -O -sC --script=vuln,auth,default -T4 -oA full_audit 10.0.0.0/24
\`\`\`

### Scenario B: Web Server Deep Dive
\`\`\`bash
nmap -p 80,443 --script http-methods,http-headers,http-enum,http-sql-injection,http-shellshock 192.168.1.1
\`\`\`

### Scenario C: Finding Active Hosts without Port Scanning
\`\`\`bash
nmap -sn 192.168.1.0/24
\`\`\`

### Scenario D: Detect WAF (Web Application Firewall)
\`\`\`bash
nmap -p 80,443 --script http-waf-detect,http-waf-fingerprint 192.168.1.1
\`\`\`

---

## 📊 PART 7: OUTPUT & REPORTING

### Format Options
- **Normal**: \`-oN scan.txt\`
- **XML**: \`-oX scan.xml\` (Best for automation)
- **Grepable**: \`-oG scan.grep\`
- **All Formats**: \`-oA my_scan\`

### Quick Analysis with Grep
\`\`\`bash
grep "open" scan.grep | cut -d" " -f2     # List only active IPs
\`\`\`

---

## ⚠️ LEGAL & ETHICAL WARNING
- Unauthorized scanning is illegal.
- Always obtain written permission.
- Be careful with timing (-T5 can crash older systems).

---

## 📖 RESOURCES
- [nmap.org](https://nmap.org)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [NSE Script Database](https://nmap.org/nsedoc/)
`;

const NMAP_ENRICHED_TR = `# Nmap - Network Mapper: Nihai Kapsamlı Eğitim Rehberi

## 🟢 BÖLÜM 1: TEMELLER (YENİ BAŞLAYANLAR İÇİN)

### Nmap Nedir?
Nmap (Network Mapper), ağ keşfi ve güvenlik denetimi için kullanılan ücretsiz ve açık kaynaklı bir araçtır.

### 💿 Kurulum
- **Debian/Ubuntu**: \`sudo apt install nmap -y\`
- **MacOS**: \`brew install nmap\`
- **Windows**: [nmap.org/download.html](https://nmap.org/download.html)

### 🚀 Hızlı Başlangıç Örnekleri
\`\`\`bash
nmap 192.168.1.1              # Tek bir IP tarama
nmap scanme.nmap.org          # Hostname tarama
nmap 192.168.1.1-50           # IP aralığı tarama
nmap 192.168.1.0/24           # Tüm alt ağı tarama
nmap -iL hedefler.txt         # Dosyadan hedef okuma
\`\`\`

---

## 🟡 BÖLÜM 2: TEMEL TARAMA TEKNİKLERİ

### TCP SYN Taraması (Gizli Tarama)
Varsayılan ve en popüler tarama türüdür. Hızlıdır ve tam bir TCP bağlantısı kurmadığı için daha az iz bırakır.
\`\`\`bash
sudo nmap -sS 192.168.1.1
\`\`\`

### TCP Connect Taraması
Kullanıcı ham paket ayrıcalıklarına (root olmayan kullanıcılar) sahip olmadığında kullanılır.
\`\`\`bash
nmap -sT 192.168.1.1
\`\`\`

### UDP Taraması
Genellikle göz ardı edilen UDP portlarını tarar (DNS, SNMP, DHCP gibi).
\`\`\`bash
sudo nmap -sU 192.168.1.1
\`\`\`

### Agresif Tarama (-A)
İşletim sistemi algılama, versiyon tespiti ve script taramasını etkinleştirir.
\`\`\`bash
nmap -A 192.168.1.1
\`\`\`

---

## 🟠 BÖLÜM 3: PORT BELİRLEME VE SERVİS TESPİTİ

### Belirli Portlar
\`\`\`bash
nmap -p 80,443 192.168.1.1        # Belirli portları tara
nmap -p- 192.168.1.1              # Tüm portları (65535) tara
nmap -F 192.168.1.1               # Hızlı tarama (en yaygın 100 port)
nmap --top-ports 20 192.168.1.1   # En yaygın 20 portu tara
\`\`\`

### Servis/Versiyon Tespiti
Hangi servisin ve hangi versiyonun çalıştığını belirler.
\`\`\`bash
nmap -sV 192.168.1.1
\`\`\`

---

## 🔴 BÖLÜM 4: NSE (NMAP SCRIPTING ENGINE) - GÜÇ MERKEZİ

### Varsayılan Scriptleri Kullanma
\`\`\`bash
nmap -sC 192.168.1.1
\`\`\`

### Zafiyet Taraması
En faydalı script kategorilerinden biridir.
\`\`\`bash
nmap --script vuln 192.168.1.1
\`\`\`

### Bruteforce (Kaba Kuvvet) Saldırıları
\`\`\`bash
nmap --script ssh-brute 192.168.1.1
nmap --script ftp-brute 192.168.1.1
\`\`\`

---

## 🟣 BÖLÜM 5: GELİŞMİŞ ATLATMA VE GİZLİLİK

### Parçalanma (Fragmentation)
Paketleri küçük parçalara bölerek basit güvenlik duvarlarını atlatmayı dener.
\`\`\`bash
nmap -f 192.168.1.1
\`\`\`

### Sahte Kaynaklar (Decoys)
Taramayı birden fazla kaynaktan geliyormuş gibi gösterir.
\`\`\`bash
nmap -D sahte1,sahte2,ME 192.168.1.1
\`\`\`

---

## 🔥 BÖLÜM 6: UZMAN SEVİYE SENARYOLAR (GERÇEK DÜNYA)

### Senaryo A: Tam Altyapı Denetimi
\`\`\`bash
sudo nmap -sS -p- -sV -O -sC --script=vuln,auth,default -T4 -oA full_audit 10.0.0.0/24
\`\`\`

### Senaryo B: Web Sunucusu Derinlemesine İnceleme
\`\`\`bash
nmap -p 80,443 --script http-methods,http-headers,http-enum,http-sql-injection 192.168.1.1
\`\`\`

---

## 📊 BÖLÜM 7: ÇIKTI VE RAPORLAMA

### Format Seçenekleri
- **Normal**: \`-oN tarama.txt\`
- **XML**: \`-oX tarama.xml\`
- **Tüm Formatlar**: \`-oA taramam\`

---

## ⚠️ YASAL VE ETİK UYARI
- Yetkisiz tarama yapmak yasadışıdır.
- Her zaman yazılı izin alın.
- Zamanlama ayarlarında dikkatli olun (-T5 sistemleri çökertebilir).
`;

async function updateEnrichedNmap() {
  try {
    const cheatsheet = await prisma.cheatsheet.update({
      where: { id: 264 },
      data: {
        titleEn: 'Nmap - Network Mapper: Ultimate Training Guide (2026)',
        titleTr: 'Nmap - Network Mapper: Nihai Eğitim Rehberi (2026)',
        descEn: NMAP_ENRICHED_EN,
        descTr: NMAP_ENRICHED_TR,
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
          'complete-guide'
        ]
      }
    });

    console.log('✓ Nmap cheatsheet updated with enriched content!');
    console.log(`  ID: ${cheatsheet.id}`);
    console.log(`  Content Length EN: ${cheatsheet.descEn.length} characters`);
    console.log(`  Content Length TR: ${cheatsheet.descTr.length} characters`);
  } catch (error) {
    console.error('✗ Error updating Nmap content:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

updateEnrichedNmap();
