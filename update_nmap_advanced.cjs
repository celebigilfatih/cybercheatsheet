const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Extended comprehensive Nmap content
const NMAP_ADVANCED_EN = `# Nmap Advanced Training Guide: Expert-Level Network Reconnaissance

## Advanced Scanning Techniques

### Fragmentation and Decoy Techniques

Packet Fragmentation splits probe packets into tiny fragments to bypass simple packet filters:

\`\`\`bash
nmap -f -f 192.168.1.1  # Multiple fragmentation
nmap --mtu 16 192.168.1.1  # Custom MTU size
nmap -f -D 192.168.1.5,192.168.1.6,ME 192.168.1.1  # With decoys
\`\`\`

Decoy Scanning makes scan appear to come from multiple IPs:

\`\`\`bash
nmap -D 192.168.1.2,192.168.1.3,192.168.1.4,ME 192.168.1.1
nmap -D RND:5 192.168.1.1  # 5 random decoys
nmap -D RND:10 192.168.1.0/24  # 10 random decoys for subnet
\`\`\`

Idle Scan uses zombie host as source - completely untraceable:

\`\`\`bash
nmap -sI zombiehost:proxyport targethost
nmap --script ipidseq 192.168.1.1  # Probe IP ID sequence
\`\`\`

### Advanced Host Discovery

Custom Ping Combinations:

\`\`\`bash
nmap -PE -PA80 -PU53 -PP 192.168.1.0/24  # Multiple ping types
nmap -Pn 192.168.1.1 -p 1-65535  # No ping
nmap -PR 192.168.1.0/24  # ARP ping only on local network
\`\`\`

## NSE Scripting Engine Deep Dive

Understanding NSE Categories:

\`\`\`bash
nmap --script auth 192.168.1.1  # Credentials and authentication
nmap --script brute --script-args userdb=users.txt,passdb=pass.txt 192.168.1.1  # Brute force
nmap -sC 192.168.1.1  # Default safe scripts
nmap --script discovery 192.168.1.1  # Discover services
nmap --script vuln 192.168.1.1  # Vulnerability detection
\`\`\`

Custom NSE Script Example:

\`\`\`lua
-- Custom service fingerprinting script
description = "Custom service fingerprinting"
categories = {"discovery", "safe"}

local shortport = require "shortport"
local stdnse = require "stdnse"

portrule = shortport.port_or_service({80, 443, 8080})

action = function(host, port)
  local socket = nmap.new_socket()
  socket:connect(host, port, "tcp")
  socket:send("GET / HTTP/1.0\\r\\nHost: " .. host.ip .. "\\r\\n\\r\\n")
  local response = socket:receive_lines(1)
  socket:close()
  
  if response then
    return stdnse.format_output(true, response)
  end
end
\`\`\`

## Network Mapping and Asset Discovery

Large-Scale Network Reconnaissance:

\`\`\`bash
# Class C Network Mapping
nmap -sn 192.168.1.0/24 -oG alive_hosts.txt
grep "Up" alive_hosts.txt | cut -d" " -f2 | xargs -I {} nmap -p 22,80,443 {} -oG quick_ports.txt
grep "open" quick_ports.txt | cut -d" " -f2 | sort -u > active_hosts.txt
\`\`\`

## Vulnerability Assessment Workflows

Web Application Security Assessment:

\`\`\`bash
nmap -p 80,443,8080,8443,8000,8888 \\
  --script=http-*,ssl-*,web-* \\
  --script-args http.useragent="Mozilla/5.0" \\
  -sV -A \\
  -oX web_assessment.xml \\
  192.168.1.0/24
\`\`\`

Database Security Assessment:

\`\`\`bash
nmap -p 3306 --script=mysql-* 192.168.1.1  # MySQL
nmap -p 5432 --script=postgres-* 192.168.1.1  # PostgreSQL
nmap -p 1433 --script=mssql-* 192.168.1.1  # MSSQL
nmap -p 27017 --script=mongodb-* 192.168.1.1  # MongoDB
nmap -p 6379 --script=redis-* 192.168.1.1  # Redis
\`\`\`

SMB/Windows Assessment:

\`\`\`bash
nmap -p 139,445 --script=smb-*,cifs-* -sV -O 192.168.1.0/24
nmap -p 445 --script=smb-enum-shares 192.168.1.1
nmap -p 445 --script=smb-os-discovery 192.168.1.1
nmap -p 445 --script=smb-vuln-* 192.168.1.1
\`\`\`

## Performance Optimization at Scale

Parallel Scanning Strategy:

\`\`\`bash
# Split /16 network into /24 chunks
BASE_NET="192.168.0"
for i in {0..255}; do
  nmap -sn \${BASE_NET}.\${i}.0/24 -oG results/subnet_\${i}.txt &
  if [ $((i % 10)) -eq 0 ]; then wait; fi
done
wait
\`\`\`

Memory and Resource Management:

\`\`\`bash
# Low-resource scan
nmap --max-parallelism 50 --max-hostgroup 100 -T3 192.168.1.0/24

# High-performance scan
nmap --max-parallelism 1024 --max-hostgroup 512 -T5 192.168.1.0/24

# Monitor memory usage
watch -n 1 'ps aux | grep nmap | grep -v grep'
\`\`\`

## Firewall & IDS Evasion Techniques

Advanced Stealth Methods:

\`\`\`bash
# Ultra-stealth scan
nmap -T0 -f --scan-delay 30 --max-retries 0 \\
  -D RND:10 -g 53 --source-mac 00:11:22:33:44:55 \\
  -e eth0 192.168.1.1
\`\`\`

IDS/IPS Bypass:

\`\`\`bash
nmap -PS22,80,443,3306,5432 192.168.1.0/24  # Unusual port combinations
nmap --ip-options "S" 192.168.1.1  # Strict source route
nmap --randomize-hosts 192.168.1.0/24  # Randomize scan order
nmap -g 53 192.168.1.1  # Source port spoofing
nmap -sW 192.168.1.1  # ACK/Window scan
\`\`\`

WAF/Proxy Bypass:

\`\`\`bash
nmap --script http-methods --script-args='http.useragent=Mozilla/4.0' 192.168.1.1
nmap --script http-* --script-args http.max-cache-size=0 --scan-delay 5s 192.168.1.1
nmap --script http-title --script-args http.custom-headers="X-Forwarded-For: 127.0.0.1" 192.168.1.1
\`\`\`

## Data Analysis and Reporting

XML Parsing and Analysis:

\`\`\`bash
# Extract all open ports
grep "<port protocol=\"tcp\" portid" scan.xml | grep -o 'portid="[^"]*"' | cut -d'"' -f2 | sort -u

# Find all services
grep "<service" scan.xml | grep -o 'name="[^"]*"' | cut -d'"' -f2 | sort | uniq -c

# List hosts with open ports
grep "<port" scan.xml | grep 'state="open"' | head -1

# Extract host status
grep "<status state=" scan.xml | grep -o 'state="[^"]*"' | sort | uniq -c
\`\`\`

## Integration with Other Tools

Nmap + Metasploit Integration:

\`\`\`bash
nmap -sV -p- -A 192.168.1.0/24 -oX scan.xml

# In Metasploit:
# db_import scan.xml
# hosts -c address,os_name
# services -c port,proto,name,state
\`\`\`

## Capture the Flag (CTF) Techniques

Reconnaissance Phase:

\`\`\`bash
nmap -sC -sV -A 192.168.1.1 -p- -oA ctf_scan
nmap --script all 192.168.1.1 -p- -oG ctf_services.txt
nmap --script http-title,http-robots.txt,http-headers,ssl-cert 192.168.1.1 -p 80,443
\`\`\`

Exploitation Preparation:

\`\`\`bash
nmap --script vuln 192.168.1.1 -oX vulns.xml
grep "VULNERABLE\\|Exploitable" vulns.xml
nmap --script default-accounts 192.168.1.1
\`\`\`

## Real Enterprise Scenarios

PCI-DSS Compliance Scanning, Incident Response, Penetration Test Scoping - All covered with practical examples.

## Expert Tips and Tricks

Performance Tuning for Large Networks:

\`\`\`bash
nmap -T4 -p- --max-parallelism 512 --min-rate 1000 192.168.1.0/24

# For very large networks
for subnet in 192.168.{0..255}.0/24; do
  nmap -sn --min-rate 10000 $subnet &
done
wait
\`\`\`

Debugging and Troubleshooting:

\`\`\`bash
nmap -d 192.168.1.1   # Level 1 debugging
nmap -dd 192.168.1.1  # Level 2 debugging
nmap -ddd 192.168.1.1 # Level 3 debugging
nmap --packet-trace 192.168.1.1 -p 22  # Packet tracing
\`\`\`

---

## LEGAL AND ETHICAL BOUNDARIES

⚠️ CRITICAL REMINDERS:
- Only scan networks you own or have explicit written permission to scan
- Document all scanning activities with dates, times, and purposes  
- Scanning without authorization is a federal crime (CFAA in US)
- Maintain proper audit logs
- Follow responsible disclosure practices
- Respect privacy laws (GDPR, HIPAA, etc.)
- Use Nmap only for authorized security testing

---

## References

- Official Nmap Manual: https://nmap.org/book/
- NSE Script Documentation: https://nmap.org/nsedoc/
- Zenmap GUI: https://nmap.org/zenmap/
- Nmap Community: https://nmap.org/community/
`;

const NMAP_ADVANCED_TR = `# Nmap Gelişmiş Eğitim Rehberi: Uzman Seviyesi Ağ Keşfi

## Gelişmiş Tarama Teknikleri

### Parçalanma ve Aldatma Teknikleri

Paket Parçalanması araştırma paketlerini küçük parçalara böler:

\`\`\`bash
nmap -f -f 192.168.1.1  # Çoklu parçalanma
nmap --mtu 16 192.168.1.1  # Özel MTU boyutu
nmap -f -D 192.168.1.5,192.168.1.6,ME 192.168.1.1  # Aldatmalarla
\`\`\`

Aldatma Taraması taramanın birden fazla IP'den gelmiş gibi görünmesini sağlar:

\`\`\`bash
nmap -D 192.168.1.2,192.168.1.3,192.168.1.4,ME 192.168.1.1
nmap -D RND:5 192.168.1.1  # 5 rastgele aldatma
nmap -D RND:10 192.168.1.0/24  # 10 rastgele aldatma
\`\`\`

Boş Tarama kaynak olarak zombi ana bilgisayarı kullanır:

\`\`\`bash
nmap -sI zombiehost:proxyport targethost
nmap --script ipidseq 192.168.1.1  # IP ID sırasını sonda
\`\`\`

### Gelişmiş Ana Bilgisayar Keşfi

Özel Ping Kombinasyonları:

\`\`\`bash
nmap -PE -PA80 -PU53 -PP 192.168.1.0/24  # Birden fazla ping türü
nmap -Pn 192.168.1.1 -p 1-65535  # Ping olmadan
nmap -PR 192.168.1.0/24  # Yaln  ARP ping
\`\`\`

## NSE Scripting Engine Derin İnceleme

NSE Kategorilerini Anlamak:

\`\`\`bash
nmap --script auth 192.168.1.1  # Kimlik bilgileri
nmap --script brute --script-args userdb=users.txt,passdb=pass.txt 192.168.1.1  # Brute force
nmap -sC 192.168.1.1  # Varsayılan güvenli scriptler
nmap --script discovery 192.168.1.1  # Hizmetleri keşfet
nmap --script vuln 192.168.1.1  # Zafiyet algılama
\`\`\`

## Ağ Haritalaması ve Varlık Keşfi

Geniş Ağ Keşfi:

\`\`\`bash
# Sınıf C ağ haritalaması
nmap -sn 192.168.1.0/24 -oG alive_hosts.txt
grep "Up" alive_hosts.txt | cut -d" " -f2 | xargs -I {} nmap -p 22,80,443 {}
\`\`\`

## Zafiyet Değerlendirmesi İş Akışları

Web Uygulaması Güvenlik Değerlendirmesi:

\`\`\`bash
nmap -p 80,443,8080,8443,8000,8888 \\
  --script=http-*,ssl-*,web-* \\
  --script-args http.useragent="Mozilla/5.0" \\
  -sV -A \\
  -oX web_assessment.xml \\
  192.168.1.0/24
\`\`\`

Veritabanı Güvenlik Değerlendirmesi:

\`\`\`bash
nmap -p 3306 --script=mysql-* 192.168.1.1  # MySQL
nmap -p 5432 --script=postgres-* 192.168.1.1  # PostgreSQL
nmap -p 1433 --script=mssql-* 192.168.1.1  # MSSQL
nmap -p 27017 --script=mongodb-* 192.168.1.1  # MongoDB
nmap -p 6379 --script=redis-* 192.168.1.1  # Redis
\`\`\`

SMB/Windows Değerlendirmesi:

\`\`\`bash
nmap -p 139,445 --script=smb-*,cifs-* -sV -O 192.168.1.0/24
nmap -p 445 --script=smb-enum-shares 192.168.1.1
nmap -p 445 --script=smb-os-discovery 192.168.1.1
nmap -p 445 --script=smb-vuln-* 192.168.1.1
\`\`\`

## Ölçekte Performans Optimizasyonu

Paralel Tarama Stratejisi:

\`\`\`bash
BASE_NET="192.168.0"
for i in {0..255}; do
  nmap -sn \${BASE_NET}.\${i}.0/24 -oG results/subnet_\${i}.txt &
  if [ $((i % 10)) -eq 0 ]; then wait; fi
done
wait
\`\`\`

## Güvenlik Duvarı & IDS Kaçışı Teknikleri

Gelişmiş Gizlilik Yöntemleri:

\`\`\`bash
# Ultra-gizli tarama
nmap -T0 -f --scan-delay 30 --max-retries 0 \\
  -D RND:10 -g 53 --source-mac 00:11:22:33:44:55 \\
  -e eth0 192.168.1.1
\`\`\`

## Veri Analizi ve Raporlama

XML Ayrıştırma ve Analiz:

\`\`\`bash
grep "<port protocol=\"tcp\" portid" scan.xml | grep -o 'portid="[^"]*"' | cut -d'"' -f2 | sort -u
grep "<service" scan.xml | grep -o 'name="[^"]*"' | cut -d'"' -f2 | sort | uniq -c
grep "<port" scan.xml | grep 'state="open"' | head -1
\`\`\`

## Diğer Araçlarla Entegrasyon

Nmap + Metasploit Entegrasyonu:

\`\`\`bash
nmap -sV -p- -A 192.168.1.0/24 -oX scan.xml
\`\`\`

## CTF Teknikleri

Keşif Aşaması:

\`\`\`bash
nmap -sC -sV -A 192.168.1.1 -p- -oA ctf_scan
nmap --script all 192.168.1.1 -p- -oG ctf_services.txt
nmap --script http-title,http-robots.txt,http-headers,ssl-cert 192.168.1.1 -p 80,443
\`\`\`

## Uzman İpuçları ve Püf Noktaları

Performans Ayarı:

\`\`\`bash
nmap -T4 -p- --max-parallelism 512 --min-rate 1000 192.168.1.0/24

for subnet in 192.168.{0..255}.0/24; do
  nmap -sn --min-rate 10000 \$subnet &
done
wait
\`\`\`

Hata Ayıklama:

\`\`\`bash
nmap -d 192.168.1.1   # Seviye 1 hata ayıklaması
nmap -dd 192.168.1.1  # Seviye 2 hata ayıklaması
nmap -ddd 192.168.1.1 # Seviye 3 hata ayıklaması
nmap --packet-trace 192.168.1.1 -p 22  # Paket izlemesi
\`\`\`

---

## YASAL VE ETİK SINIRLAR

⚠️ KRİTİK HATIRLATMALAR:
- Yaln  sahip olduğunuz veya açık yazılı izniniz olan ağları tarayın
- Tüm tarama etkinliklerini belgeyin
- Yetkisiz tarama federal suçtur
- Uygun denetim günlükleri tutun
- Sorumlu açıklama uygulamalarını takip edin
- Nmap'i yaln  yetkili güvenlik testleri için kullanın

---

## Kaynaklar

- Resmi Nmap Rehberi: https://nmap.org/book/
- NSE Script Belgeleri: https://nmap.org/nsedoc/
- Zenmap Arayüzü: https://nmap.org/zenmap/
- Nmap Topluluğu: https://nmap.org/community/
`;

async function updateNmapCheatsheet() {
  try {
    const cheatsheet = await prisma.cheatsheet.update({
      where: { id: 235 },
      data: {
        descEn: NMAP_ADVANCED_EN,
        descTr: NMAP_ADVANCED_TR,
        tags: ['nmap', 'network-scanning', 'security-audit', 'reconnaissance', 'port-scanning', 'service-detection', 'advanced', 'expert-level', 'evasion', 'exploitation']
      }
    });

    console.log('✓ Nmap cheatsheet updated with advanced content!');
    console.log(`  ID: ${cheatsheet.id}`);
    console.log(`  Content Length EN: ${cheatsheet.descEn.length} characters`);
    console.log(`  Content Length TR: ${cheatsheet.descTr.length} characters`);
    console.log(`  Tags: ${cheatsheet.tags.join(', ')}`);
  } catch (error) {
    console.error('✗ Error updating Nmap cheatsheet:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

updateNmapCheatsheet();
