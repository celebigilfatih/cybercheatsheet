import dbConnect from '../lib/dbConnect.js';
import Cheatsheet from '../models/Cheatsheet.js';
import Category from '../models/Category.js';
import mongoose from 'mongoose';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env.local
const envPath = path.join(__dirname, '..', '.env.local');
if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, 'utf-8').split(/\r?\n/);
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const idx = trimmed.indexOf('=');
        if (idx === -1) continue;
        const key = trimmed.slice(0, idx).trim();
        const val = trimmed.slice(idx + 1).trim();
        if (key && !(key in process.env)) process.env[key] = val;
    }
}

const contentTR = `# Nmap - Network Mapper

## 3. Temel Kullanım

**Temel Taramalar:**
\`\`\`bash
nmap 192.168.1.1
\`\`\`
Varsayılan olarak en popüler 1000 TCP portunu tarar.

**SYN Scan (Stealth):**
\`\`\`bash
nmap -sS 192.168.1.1
\`\`\`
→ **-sS**: TCP bağlantısını tamamlamaz (half-open), loglarda daha az iz bırakır.

**Versiyon Tespiti:**
\`\`\`bash
nmap -sV 192.168.1.1
\`\`\`
→ **-sV**: Açık portlarda çalışan servislerin versiyonlarını belirler.

**OS Detection:**
\`\`\`bash
nmap -O 192.168.1.1
\`\`\`
→ **-O**: İşletim sistemini tahmin etmeye çalışır.

**Agresif Tarama:**
\`\`\`bash
nmap -A 192.168.1.1
\`\`\`
→ **-A**: OS detection, version detection, script scanning ve traceroute'u aynı anda çalıştırır.

**Tüm Portları Tarama:**
\`\`\`bash
nmap -p- 192.168.1.1
\`\`\`
→ **-p-**: 1'den 65535'e kadar tüm portları tarar.

## 4. İleri Seviye Kullanım

### Stealth Scanning Teknikleri
*   **SYN Scan (-sS)**: Standart ve en hızlı yöntemdir.
*   **FIN/NULL/XMAS Scan (-sF, -sN, -sX)**: TCP bayraklarını manipüle ederek bazı firewall'ları atlatabilir (Windows'ta çalışmaz).

### IDS/IPS Atlatma Taktikleri
*   **Fragmentation (-f)**: Paketleri parçalayarak IDS'in içeriği analiz etmesini zorlaştırır.
*   **Decoy Kullanımı (-D)**: Taramayı başka IP'lerden yapılıyormuş gibi göstererek gerçek kaynağı gizler (\`-D RND:10\`).
*   **Source Port Spoofing (--source-port)**: Kaynak portu 53 veya 80 yaparak firewall kurallarını test eder.

### Zamanlama Profilleri (-T0–T5)
*   **-T0 (Paranoid)**: Çok yavaş, IDS atlatmak için.
*   **-T3 (Normal)**: Varsayılan.
*   **-T4 (Aggressive)**: Hızlı ve güvenilir ağlar için önerilen.
*   **-T5 (Insane)**: Çok hızlı, paket kaybı riski yüksek.

### NSE (Nmap Scripting Engine)
*   **Script Kategorileri**: \`auth\`, \`brute\`, \`vuln\`, \`discovery\`, \`intrusive\`.
*   **Özel Script Yürütme**:
    \`\`\`bash
    nmap --script http-title 192.168.1.1
    \`\`\`
*   **Script Argümanları**:
    \`\`\`bash
    nmap --script http-brute --script-args userdb=users.txt 192.168.1.1
    \`\`\`

### Ağ Haritalama Stratejileri
*   **Host Discovery (-sn)**: Port taraması yapmadan sadece ayakta olan cihazları bulur (Ping sweep).
*   **ARP Ping (-PR)**: Yerel ağda en hızlı keşif yöntemidir.

### Büyük Ölçekli Ağ Taramalarında Optimizasyon
*   **--min-rate**: Paket gönderim hızını zorlar (örn: \`--min-rate 1000\`).
*   **--max-retries**: Tekrar deneme sayısını sınırlar (hız kazandırır).

### Firewall Arkasını Keşfetme
*   **TCP ACK Scan (-sA)**: Portların açık/kapalı durumunu değil, firewall tarafından filtrelenip filtrelenmediğini (filtered/unfiltered) gösterir.
*   **IP Protocol Scan (-sO)**: Hangi IP protokollerinin (TCP, UDP, ICMP) desteklendiğini bulur.

### IPv6 Tarama
*   **-6**: IPv6 taramasını etkinleştirir.
    \`\`\`bash
    nmap -6 fe80::1
    \`\`\`

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

**Komut:**
\`\`\`bash
nmap -sS -sV -p- --min-rate 5000 -oA full_scan 192.168.1.10
\`\`\`
**Açıklama:**
Hedefin tüm portlarını SYN scan ile hızlıca tarar, versiyon tespiti yapar ve sonuçları tüm formatlarda kaydeder.

**Argüman Açıklamaları:**
*   **-sS**: SYN scan (gizli/hızlı).
*   **-sV**: Versiyon tespiti.
*   **-p-**: Tüm portlar (1-65535).
*   **--min-rate**: Minimum paket hızı (5000 pps).
*   **-oA**: Tüm formatlarda çıktı (xml, nmap, gnmap).

**Temel Argümanlar:**
*   **-sS**: SYN scan (root yetkisi gerekir).
*   **-sT**: TCP connect scan (yetkisiz kullanıcılar için).
*   **-sU**: UDP scan (yavaştır).
*   **-p**: Port seçimi (örn: \`-p22,80\`, \`-p1-100\`).
*   **-p-**: Tüm 65535 portu tara.
*   **-sV**: Servis/versiyon tespiti.
*   **-O**: İşletim sistemi tespiti.
*   **-A**: Agresif tarama (OS + Version + Script + Traceroute).
*   **-Pn**: Ping atma, host'u ayakta varsay (firewall varsa).
*   **--reason**: Portun neden o durumda olduğunu gösterir (örn: syn-ack).

**Zamanlama / Performans:**
*   **-T0–T5**: Zamanlama şablonları (0: çok yavaş, 5: çok hızlı).
*   **--max-rtt-timeout**: Paket yanıtı için maksimum bekleme süresi.
*   **--max-retries**: Yanıt gelmeyen portu tekrar deneme sayısı.
*   **--host-timeout**: Bir hedef için harcanacak maksimum süre.
*   **--min-rate**: Saniyede gönderilecek minimum paket sayısı.
*   **--max-rate**: Saniyede gönderilecek maksimum paket sayısı.

**IDS/IPS Atlatma & Obfuscation:**
*   **-f**: Paketleri parçalar (fragmentation).
*   **--mtu**: Özel MTU değeri belirler (8'in katı olmalı).
*   **-D**: Decoy (yem) IP listesi (örn: \`-D 10.0.0.1,10.0.0.2,ME\`).
*   **-S**: Kaynak IP adresini spoof eder (yanıtlar o IP'ye gider).
*   **--source-port**: Kaynak portu değiştirir (örn: 53, 80).
*   **--data-length**: Paketlere rastgele veri ekler (boyutu değiştirir).
*   **--randomize-hosts**: Hedef IP sırasını karıştırır.
*   **--spoof-mac**: MAC adresini spoof eder.

**Host Keşfi:**
*   **-sn**: Port taraması yapma (Ping Scan).
*   **-PR**: ARP Ping (yerel ağ).
*   **-PE**: ICMP Echo Ping.
*   **-PP**: ICMP Timestamp Ping.
*   **-PM**: ICMP Netmask Ping.
*   **-PS/PA/PU/PY**: TCP SYN/ACK, UDP, SCTP paketleri ile keşif.

**NSE (Script Engine):**
*   **-sC**: Varsayılan script setini çalıştırır (güvenli scriptler).
*   **--script**: Çalıştırılacak script veya kategori (örn: \`vuln\`).
*   **--script-args**: Scriptlere argüman verir.
*   **--script-trace**: Scriptlerin gönderdiği/aldığı veriyi gösterir.
*   **--script-help**: Script hakkında bilgi verir.

**Çıktı ve Loglama:**
*   **-oN**: Normal metin çıktısı.
*   **-oG**: Grepable (tek satır) çıktı.
*   **-oX**: XML çıktısı (otomasyon için).
*   **-oA**: Üç formatı da kaydeder.
*   **--append-output**: Varolan dosyanın sonuna ekler.
*   **--stylesheet**: XML çıktısı için XSL stil dosyası belirtir.

## 6. Gerçek Pentest Senaryoları

**Kurumsal Ağ Keşfi:**
\`\`\`bash
nmap -sn 10.0.0.0/16 -oG live_hosts.txt
\`\`\`
Geniş bir ağda sadece ayakta olan cihazları listeler.

**Servis Tespiti + Versiyon Zafiyeti Analizi:**
\`\`\`bash
nmap -sV --script vuln 192.168.1.10
\`\`\`
Servis versiyonlarını bulur ve bilinen zafiyetleri (CVE) tarar.

**Firewall Arkasını Keşfetme:**
\`\`\`bash
nmap -sA -Pn 192.168.1.1
\`\`\`
ACK scan ile firewall kurallarını (stateful inspection) analiz eder.

**IDS/IPS Atlatma Testleri:**
\`\`\`bash
nmap -sS -f -D RND:10 --data-length 20 192.168.1.10
\`\`\`
Parçalanmış paketler, rastgele decoy'lar ve ek veri ile IDS'i atlatmayı dener.

**Passive/Stealth Reconnaissance:**
\`\`\`bash
nmap -sS -T1 -p80,443 --randomize-hosts 192.168.1.0/24
\`\`\`
Çok yavaş ve rastgele tarama ile dikkat çekmeden bilgi toplar.

**VLAN Segmentation Testleri:**
\`\`\`bash
nmap --script broadcast-dhcp-discover
\`\`\`
DHCP sunucularını ve VLAN bilgilerini broadcast ile keşfeder.

**Büyük Network Taramaları için Optimizasyon:**
\`\`\`bash
nmap -sS -p- --min-rate 1000 --max-retries 1 10.0.0.0/16
\`\`\`
Hızlandırılmış ayarlar ile büyük ağları tarar.

**IPv6 Keşif:**
\`\`\`bash
nmap -6 -sS -p80 fe80::/64
\`\`\`
IPv6 ağındaki web sunucularını tarar.

**WordPress/Joomla NSE Taraması:**
\`\`\`bash
nmap --script http-wordpress-enum,http-joomla-brute 192.168.1.10
\`\`\`
CMS'e özel scriptler ile zafiyet ve kullanıcı arar.

**SSL/TLS Zafiyet Analizi:**
\`\`\`bash
nmap --script ssl-enum-ciphers,ssl-heartbleed -p 443 192.168.1.10
\`\`\`
Zayıf şifreleme algoritmalarını ve Heartbleed gibi açıkları kontrol eder.

**Active Directory Discovery:**
\`\`\`bash
nmap --script smb-os-discovery,smb-enum-users 192.168.1.10
\`\`\`
SMB üzerinden işletim sistemi ve kullanıcı bilgilerini çeker.

**IoT Cihaz Keşfi:**
\`\`\`bash
nmap -sU -p 161,1900 --script snmp-info,upnp-info 192.168.1.0/24
\`\`\`
SNMP ve UPnP ile IoT cihazlarını tanımlar.

**UDP Servis Brute-force Tespiti:**
\`\`\`bash
nmap -sU -p 161 --script snmp-brute 192.168.1.10
\`\`\`
SNMP topluluk dizelerine (community string) kaba kuvvet uygular.

## 8. Best Practices (Uzman Seviye)

*   **Büyük Ağlarda Zaman Profili:** \`-T4\` genellikle en iyi dengedir. \`-T5\` paket kaybına neden olabilir.
*   **UDP Taramalarını Hızlandırma:** Sadece bilinen UDP portlarını tarayın (\`-sU --top-ports 100\`) ve \`--min-rate\` kullanın.
*   **Script Kategorileri:** \`--script default,safe\` ile güvenli tarama yapın, \`intrusive\` üretim ortamını bozabilir.
*   **IDS Atlatma:** Fragmentation (\`-f\`) ve Decoy (\`-D\`) kombinasyonu etkilidir ancak modern NGFW'lar birleştirebilir.
*   **Reverse DNS:** \`-n\` (no DNS resolution) kullanarak taramayı hızlandırın, gerekmiyorsa DNS çözmeyin.
*   **XML Output:** Sonuçları veritabanına aktarmak veya raporlamak için daima \`-oX\` kullanın.
*   **Firewall Evasion:** Paket boyutunu (\`--data-length\`) değiştirerek statik imza tabanlı kuralları atlatın.
*   **Version Detection:** \`--version-intensity\` ayarı ile doğruluğu artırın (0-9 arası).
*   **OS Detection:** En az bir açık ve bir kapalı port bulunması OS tespit başarısını artırır.
*   **IPv6:** Dual-stack ağlarda IPv6 taramasını asla atlamayın, firewall kuralları genellikle daha gevşektir.

## 9. Sık Yapılan Hatalar

*   **Tüm Portları Taramayı Unutmak:** Varsayılan tarama sadece 1000 portu kapsar, kritik servisler yüksek portlarda olabilir (\`-p-\` kullanın).
*   **-A Kullanıp Gereksiz Gürültü Oluşturmak:** \`-A\` çok gürültülüdür ve IDS alarmlarını tetikler.
*   **Yanlış Decoy Sırası:** Kendi IP'nizi decoy listesine karıştırmazsanız (\`ME\`), bazı sistemler sizi filtreleyebilir.
*   **UDP Taramalarında Yanlış Timeout:** UDP yanıt vermezse Nmap bekler, \`--host-timeout\` kullanmazsanız tarama bitmez.
*   **Script Flood:** \`--script all\` gibi komutlar ağı kilitleyebilir.
*   **Büyük Network Taramalarında Yanlış T Profili:** \`-T3\` ile /16 ağ taramak günler sürer.
*   **Output Dosyası Belirtmeyi Unutmak:** Uzun süren taramanın sonucu ekranda kaybolabilir.
*   **Firewall Arkasında ICMP Ping'e Güvenmek:** Firewall ICMP'yi engelliyorsa host kapalı sanılır, \`-Pn\` kullanın.
*   **IPv6 Host Discovery'i Atlamak:** Sadece IPv4 taramak modern ağlarda yetersizdir.
`;

const contentEN = `# Nmap - Network Mapper

## 3. Basic Usage

**Basic Scans:**
\`\`\`bash
nmap 192.168.1.1
\`\`\`
Scans the most popular 1000 TCP ports by default.

**SYN Scan (Stealth):**
\`\`\`bash
nmap -sS 192.168.1.1
\`\`\`
→ **-sS**: Does not complete TCP connection (half-open), leaves fewer traces in logs.

**Version Detection:**
\`\`\`bash
nmap -sV 192.168.1.1
\`\`\`
→ **-sV**: Determines versions of services running on open ports.

**OS Detection:**
\`\`\`bash
nmap -O 192.168.1.1
\`\`\`
→ **-O**: Attempts to guess the operating system.

**Aggressive Scan:**
\`\`\`bash
nmap -A 192.168.1.1
\`\`\`
→ **-A**: Runs OS detection, version detection, script scanning, and traceroute simultaneously.

**Scanning All Ports:**
\`\`\`bash
nmap -p- 192.168.1.1
\`\`\`
→ **-p-**: Scans all ports from 1 to 65535.

## 4. Advanced Usage

### Stealth Scanning Techniques
*   **SYN Scan (-sS)**: Standard and fastest method.
*   **FIN/NULL/XMAS Scan (-sF, -sN, -sX)**: Can bypass some firewalls by manipulating TCP flags (does not work on Windows).

### IDS/IPS Evasion Tactics
*   **Fragmentation (-f)**: Fragments packets to make content analysis harder for IDS.
*   **Decoy Usage (-D)**: Hides the real source by making the scan appear to come from other IPs (\`-D RND:10\`).
*   **Source Port Spoofing (--source-port)**: Sets source port to 53 or 80 to test firewall rules.

### Timing Profiles (-T0–T5)
*   **-T0 (Paranoid)**: Very slow, for IDS evasion.
*   **-T3 (Normal)**: Default.
*   **-T4 (Aggressive)**: Recommended for fast and reliable networks.
*   **-T5 (Insane)**: Very fast, high risk of packet loss.

### NSE (Nmap Scripting Engine)
*   **Script Categories**: \`auth\`, \`brute\`, \`vuln\`, \`discovery\`, \`intrusive\`.
*   **Executing Specific Scripts**:
    \`\`\`bash
    nmap --script http-title 192.168.1.1
    \`\`\`
*   **Script Arguments**:
    \`\`\`bash
    nmap --script http-brute --script-args userdb=users.txt 192.168.1.1
    \`\`\`

### Network Mapping Strategies
*   **Host Discovery (-sn)**: Finds live hosts without port scanning (Ping sweep).
*   **ARP Ping (-PR)**: Fastest discovery method on local networks.

### Optimization for Large Scale Scans
*   **--min-rate**: Forces minimum packet sending rate (e.g., \`--min-rate 1000\`).
*   **--max-retries**: Limits number of retries (saves time).

### Discovering Behind Firewall
*   **TCP ACK Scan (-sA)**: Shows if ports are filtered/unfiltered by firewall, not open/closed status.
*   **IP Protocol Scan (-sO)**: Finds supported IP protocols (TCP, UDP, ICMP).

### IPv6 Scanning
*   **-6**: Enables IPv6 scanning.
    \`\`\`bash
    nmap -6 fe80::1
    \`\`\`

## 5. Annotated Commands (EXTENDED LIST)

**Command:**
\`\`\`bash
nmap -sS -sV -p- --min-rate 5000 -oA full_scan 192.168.1.10
\`\`\`
**Description:**
Quickly scans all ports of the target using SYN scan, performs version detection, and saves results in all formats.

**Argument Explanations:**
*   **-sS**: SYN scan (stealth/fast).
*   **-sV**: Version detection.
*   **-p-**: All ports (1-65535).
*   **--min-rate**: Minimum packet rate (5000 pps).
*   **-oA**: Output in all formats (xml, nmap, gnmap).

**Basic Arguments:**
*   **-sS**: SYN scan (requires root).
*   **-sT**: TCP connect scan (for unprivileged users).
*   **-sU**: UDP scan (slow).
*   **-p**: Port selection (e.g., \`-p22,80\`, \`-p1-100\`).
*   **-p-**: Scan all 65535 ports.
*   **-sV**: Service/version detection.
*   **-O**: Operating system detection.
*   **-A**: Aggressive scan (OS + Version + Script + Traceroute).
*   **-Pn**: No ping, assume host is up (if firewall exists).
*   **--reason**: Shows why a port is in that state (e.g., syn-ack).

**Timing / Performance:**
*   **-T0–T5**: Timing templates (0: very slow, 5: very fast).
*   **--max-rtt-timeout**: Max time to wait for packet response.
*   **--max-retries**: Max retries for unresponsive ports.
*   **--host-timeout**: Max time to spend on a target.
*   **--min-rate**: Min packets per second.
*   **--max-rate**: Max packets per second.

**IDS/IPS Evasion & Obfuscation:**
*   **-f**: Fragments packets.
*   **--mtu**: Sets custom MTU (must be multiple of 8).
*   **-D**: Decoy IP list (e.g., \`-D 10.0.0.1,10.0.0.2,ME\`).
*   **-S**: Spoofs source IP address.
*   **--source-port**: Changes source port (e.g., 53, 80).
*   **--data-length**: Appends random data to packets.
*   **--randomize-hosts**: Randomizes target IP order.
*   **--spoof-mac**: Spoofs MAC address.

**Host Discovery:**
*   **-sn**: No port scan (Ping Scan).
*   **-PR**: ARP Ping (local network).
*   **-PE**: ICMP Echo Ping.
*   **-PP**: ICMP Timestamp Ping.
*   **-PM**: ICMP Netmask Ping.
*   **-PS/PA/PU/PY**: Discovery via TCP SYN/ACK, UDP, SCTP packets.

**NSE (Script Engine):**
*   **-sC**: Runs default script set (safe scripts).
*   **--script**: Script or category to run (e.g., \`vuln\`).
*   **--script-args**: Arguments for scripts.
*   **--script-trace**: Shows communication data of scripts.
*   **--script-help**: Shows help for a script.

**Output and Logging:**
*   **-oN**: Normal text output.
*   **-oG**: Grepable (one line) output.
*   **-oX**: XML output (for automation).
*   **-oA**: Saves in all three formats.
*   **--append-output**: Appends to existing file.
*   **--stylesheet**: Specifies XSL stylesheet for XML output.

## 6. Real Pentest Scenarios

**Corporate Network Discovery:**
\`\`\`bash
nmap -sn 10.0.0.0/16 -oG live_hosts.txt
\`\`\`
Lists only live hosts in a large network.

**Service Detection + Version Vulnerability Analysis:**
\`\`\`bash
nmap -sV --script vuln 192.168.1.10
\`\`\`
Finds service versions and scans for known vulnerabilities (CVE).

**Discovering Behind Firewall:**
\`\`\`bash
nmap -sA -Pn 192.168.1.1
\`\`\`
Analyzes firewall rules (stateful inspection) using ACK scan.

**IDS/IPS Evasion Tests:**
\`\`\`bash
nmap -sS -f -D RND:10 --data-length 20 192.168.1.10
\`\`\`
Attempts to bypass IDS using fragmented packets, random decoys, and extra data.

**Passive/Stealth Reconnaissance:**
\`\`\`bash
nmap -sS -T1 -p80,443 --randomize-hosts 192.168.1.0/24
\`\`\`
Gathers info without attracting attention using very slow and random scanning.

**VLAN Segmentation Tests:**
\`\`\`bash
nmap --script broadcast-dhcp-discover
\`\`\`
Discovers DHCP servers and VLAN info via broadcast.

**Optimization for Large Network Scans:**
\`\`\`bash
nmap -sS -p- --min-rate 1000 --max-retries 1 10.0.0.0/16
\`\`\`
Scans large networks with accelerated settings.

**IPv6 Discovery:**
\`\`\`bash
nmap -6 -sS -p80 fe80::/64
\`\`\`
Scans web servers on IPv6 network.

**WordPress/Joomla NSE Scan:**
\`\`\`bash
nmap --script http-wordpress-enum,http-joomla-brute 192.168.1.10
\`\`\`
Searches for vulnerabilities and users using CMS-specific scripts.

**SSL/TLS Vulnerability Analysis:**
\`\`\`bash
nmap --script ssl-enum-ciphers,ssl-heartbleed -p 443 192.168.1.10
\`\`\`
Checks for weak encryption algorithms and flaws like Heartbleed.

**Active Directory Discovery:**
\`\`\`bash
nmap --script smb-os-discovery,smb-enum-users 192.168.1.10
\`\`\`
Extracts OS and user info via SMB.

**IoT Device Discovery:**
\`\`\`bash
nmap -sU -p 161,1900 --script snmp-info,upnp-info 192.168.1.0/24
\`\`\`
Identifies IoT devices via SNMP and UPnP.

**UDP Service Brute-force Detection:**
\`\`\`bash
nmap -sU -p 161 --script snmp-brute 192.168.1.10
\`\`\`
Brute-forces SNMP community strings.

## 8. Best Practices (Expert Level)

*   **Timing Profile in Large Networks:** \`-T4\` is usually the best balance. \`-T5\` can cause packet loss.
*   **Speeding Up UDP Scans:** Only scan known UDP ports (\`-sU --top-ports 100\`) and use \`--min-rate\`.
*   **Script Categories:** Use \`--script default,safe\` for safe scanning, \`intrusive\` can disrupt production.
*   **IDS Evasion:** Combination of Fragmentation (\`-f\`) and Decoy (\`-D\`) is effective but modern NGFWs might reassemble.
*   **Reverse DNS:** Use \`-n\` (no DNS resolution) to speed up scanning if DNS is not needed.
*   **XML Output:** Always use \`-oX\` for importing results into databases or reporting.
*   **Firewall Evasion:** Change packet size (\`--data-length\`) to bypass static signature-based rules.
*   **Version Detection:** Increase accuracy with \`--version-intensity\` (0-9).
*   **OS Detection:** Finding at least one open and one closed port increases OS detection success.
*   **IPv6:** Never skip IPv6 scanning in dual-stack networks, firewall rules are often looser.

## 9. Common Mistakes

*   **Forgetting to Scan All Ports:** Default scan covers only 1000 ports, critical services might be on high ports (use \`-p-\`).
*   **Creating Unnecessary Noise with -A:** \`-A\` is very noisy and triggers IDS alarms.
*   **Wrong Decoy Order:** If you don't mix your IP (\`ME\`) into the decoy list, some systems might filter you out.
*   **Wrong Timeout in UDP Scans:** Nmap waits if UDP doesn't respond, scan won't finish without \`--host-timeout\`.
*   **Script Flood:** Commands like \`--script all\` can lock up the network.
*   **Wrong T Profile in Large Scans:** Scanning a /16 network with \`-T3\` takes days.
*   **Forgetting Output File:** Results of a long scan can be lost in the terminal.
*   **Relying on ICMP Ping Behind Firewall:** If firewall blocks ICMP, host appears down, use \`-Pn\`.
*   **Skipping IPv6 Host Discovery:** Scanning only IPv4 is insufficient in modern networks.
`;

async function addNmap() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Nmap cheatsheet...');

        // 1. Find or create the category
        let category = await Category.findOne({ 'name.en': 'Network Scanning' });
        if (!category) {
            console.log('Category "Network Scanning" not found, creating...');
            category = await Category.create({
                name: { tr: 'Ağ Taraması', en: 'Network Scanning' },
                description: { tr: 'Ağ keşif ve port tarama araçları', en: 'Network discovery and port scanning tools' },
                slug: 'network-scanning',
                icon: 'Radar'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Nmap Cheat Sheet',
                en: 'Nmap Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['nmap', 'network', 'scanning', 'port', 'discovery', 'nse']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Nmap Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Nmap cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addNmap();
