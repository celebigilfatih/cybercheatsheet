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

const contentTR = `# Masscan - Internet Scale Port Scanner

## 3. Temel Kullanım

**Hedef IP/Port Taraması:**
\`\`\`bash
masscan 192.168.1.10 -p80,443
\`\`\`
→ **-p**: Taranacak portları belirtir (virgül ile ayrılmış).

**Aralık Taraması:**
\`\`\`bash
masscan 192.168.1.0/24 -p0-65535
\`\`\`
→ **CIDR**: IP aralığı (subnet) belirtimi.
→ **-p0-65535**: Tüm portları tarar.

**Interface Seçimi:**
\`\`\`bash
masscan 10.0.0.0/8 -p80 -e eth0
\`\`\`
→ **-e**: Kullanılacak ağ arayüzünü (interface) seçer.

**Hız Ayarı (Rate):**
\`\`\`bash
masscan 10.0.0.0/8 -p80 --rate 10000
\`\`\`
→ **--rate**: Saniyede gönderilecek paket sayısı (pps).

**Output Kayıt Formatları:**
\`\`\`bash
masscan 10.0.0.0/8 -p80 -oX scan.xml
\`\`\`
→ **-oX**: Sonuçları XML formatında kaydeder.

**Basic SYN Scan Mantığı:**
Masscan varsayılan olarak SYN scan yapar (stateless). Bağlantı kurmaz, sadece SYN-ACK bekler.

**Top Ports Tarama:**
\`\`\`bash
masscan 192.168.1.1 --top-ports 100
\`\`\`
→ **--top-ports**: En popüler N portu tarar.

**Tek Port / Port Range:**
\`\`\`bash
masscan 192.168.1.1 -p80
masscan 192.168.1.1 -p1-1024
\`\`\`

**Zamanlama:**
Masscan asenkron çalıştığı için Nmap gibi agresif zamanlama şablonlarına (T4, T5) ihtiyaç duymaz, hız \`--rate\` ile belirlenir.

**Pcap Çıktısı Alma:**
\`\`\`bash
masscan 192.168.1.1 -p80 --pcap capture.pcap
\`\`\`
→ **--pcap**: Gönderilen ve alınan paketleri pcap dosyasına yazar.

## 4. İleri Seviye Kullanım

### Masscan Motoru & Mimari
*   **Asynchronous Stateless Scanning**: Masscan, her bağlantı için durum (state) tutmaz. Bu sayede milyonlarca paketi aynı anda yönetebilir.
*   **Raw Packet Injection**: İşletim sistemi ağ yığınını (TCP/IP stack) atlayarak doğrudan sürücü seviyesinde paket üretir ve gönderir.
*   **TCP SYN Flood Tekniği**: Taramayı bir DoS saldırısı gibi yönetir ancak yanıtları dinleyerek açık portları tespit eder.
*   **Kernel-stack yerine Userland Packet Forge**: Paketler kernel yerine kullanıcı alanında (userland) oluşturulur, bu da performansı artırır.
*   **Gerçek Zamanlı Paket İşleme**: Gelen yanıtlar (SYN-ACK, RST) ayrı bir thread ile anlık işlenir.

### İleri Tarama Teknikleri
*   **Çoklu Target-Input**:
    \`\`\`bash
    masscan -iL targets.txt --exclude-file exclude.txt
    \`\`\`
*   **Tamamen Stateless Scan Avantajları**: Bağlantı zaman aşımı beklemez, paket gönderir ve unutur.
*   **Spoofing (Source IP)**:
    \`\`\`bash
    masscan ... --source-ip 192.168.1.200
    \`\`\`
    Kaynak IP adresini değiştirerek firewall atlatma veya gizlenme sağlar.
*   **Port-Bounce (--banners)**: Servis banner'larını toplamak için TCP bağlantısını tamamlamaya çalışır (stateful davranış gerektirir).
*   **Firewall Evasion**: Parçalanmış paketler veya özel TCP bayrakları ile firewall kurallarını test eder.
*   **Packet Rate Tuning**: Ağ bant genişliğine göre \`--rate\` ayarı kritiktir. Çok yüksek hız paket kaybına (packet loss) neden olur.
*   **Randomize Host/Port Ordering**: Taramayı doğrusal değil rastgele yaparak IDS/IPS tespitini zorlaştırır (varsayılan davranıştır).

### Performans & Tuning
*   **--rate Detaylı Optimizasyon**: Upload hızınıza göre ayarlayın. 1 Gbps hat için ~1.5 milyon pps mümkündür.
*   **NIC Offloading**: Performans için ağ kartının offloading özelliklerini devre dışı bırakmak gerekebilir.
*   **CPU Affinity**: Masscan tek çekirdekte çok verimlidir, ancak çoklu instance ile ölçeklenebilir.
*   **Packet Loss Azaltma**: Hızı düşürmek veya \`--retries\` artırmak paket kaybını azaltır.

### Masscan → Nmap Workflow
1.  **Masscan ile Hızlı Keşif**: Geniş ağı tarayıp açık portları bulun.
2.  **Only-Open-Ports**: Çıktıyı parse edip sadece açık IP:Port listesini alın.
3.  **Nmap ile Service/Version Tarama**:
    \`\`\`bash
    nmap -sV -sC -iL open_ports.txt
    \`\`\`
    Bu yöntem, tüm ağı Nmap ile taramaktan çok daha hızlıdır.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

**Komut:**
\`\`\`bash
masscan -p1-65535 10.0.0.0/8 --rate 100000 -oG output.grep --exclude 10.0.0.1
\`\`\`
**Açıklama:**
10.0.0.0/8 ağındaki tüm portları saniyede 100.000 paket hızında tarar, 10.0.0.1'i hariç tutar ve grepable formatta kaydeder.

**Argüman Açıklamaları:**
*   **-p**: Port aralığı (1-65535).
*   **CIDR**: Hedef ağ (10.0.0.0/8).
*   **--rate**: Paket hızı.
*   **-oG**: Grepable çıktı formatı.
*   **--exclude**: Hariç tutulacak IP.

**Temel Argümanlar:**
*   **-p**: Port veya port aralığı.
*   **-iL**: Hedef listesi dosyası.
*   **--exclude**: Hariç tutulacak hedefler.
*   **--exclude-file**: Hariç tutulacaklar listesi dosyası.
*   **--interactive**: Etkileşimli kullanım (klavye komutları aktif).
*   **--wait**: Tarama bittikten sonra yanıt bekleme süresi (saniye).
*   **--ping**: ICMP echo request ile host discovery (port taraması yapmaz).

**Ağ & Interface Argümanları:**
*   **-e**: Interface seçimi (eth0, tun0 vb.).
*   **--source-ip**: Spoofed (sahte) kaynak IP.
*   **--source-port**: Kaynak port veya port aralığı.
*   **--router-mac**: Gateway MAC adresi (manuel belirtmek gerekirse).
*   **--adapter-ip**: Dinleme yapılacak adapter IP'si.
*   **--adapter-port**: Raw paket gönderimi için bind portu.

**Performans Argümanları:**
*   **--rate**: Saniyede gönderilecek paket sayısı (pps).
*   **--max-rate**: Otomatik ayarlamada üst limit.
*   **--min-rate**: Otomatik ayarlamada alt limit.
*   **--retries**: Yanıt gelmezse paketi tekrar gönderme sayısı.
*   **--connection-timeout**: TCP bağlantı zaman aşımı.
*   **--sendq**: Gönderim kuyruğu (send queue) boyutu.

**Output Argümanları:**
*   **-oL**: Liste formatında çıktı.
*   **-oJ**: JSON formatında çıktı.
*   **-oX**: XML formatında çıktı.
*   **-oG**: Grepable (grep uyumlu) çıktı.
*   **--packet-trace**: Gönderilen/alınan her paketi ekrana basar.
*   **--pcap**: Trafiği pcap dosyasına kaydeder.
*   **--banner**: Servis bannerlarını (HTTP server, SSH version vb.) toplar.

**Firewall Evasion / Stealth Argümanları:**
*   **--badsum**: Geçersiz TCP checksum'lı paket gönderir (bazı firewall'ları şaşırtmak için).
*   **--ttl**: IP Time-To-Live değerini ayarlar.
*   **--flags**: Özel TCP bayrakları (SYN, ACK, PSH vb.) ayarlar.
*   **--fragment**: Paketleri parçalar (firewall atlatma).
*   **--randomize-hosts**: Taranacak host sırasını karıştırır.
*   **--randomize-ports**: Taranacak port sırasını karıştırır.

## 6. Gerçek Pentest Senaryoları

**Çok Geniş IP Aralığında Hızlı Port Keşfi:**
\`\`\`bash
masscan 0.0.0.0/0 -p80,443 --rate 10000000 --exclude-file exclude.conf
\`\`\`
Tüm interneti (veya çok geniş bir aralığı) HTTP/HTTPS için tarar.

**Firewall Arkasındaki Açık Portları Tespit:**
\`\`\`bash
masscan 192.168.1.1 -p0-65535 --source-port 53
\`\`\`
Kaynak portu 53 (DNS) yaparak firewall kurallarını atlatmayı dener.

**Datacenter Taraması (10+ Milyon IP):**
\`\`\`bash
masscan -iL datacenter_ips.txt -p80,8080,443 --rate 200000 -oB binary.scan
\`\`\`
Büyük ölçekli taramayı binary formatta (-oB) kaydederek disk I/O darboğazını önler.

**UDP-Based Service Keşfi:**
\`\`\`bash
masscan 192.168.1.0/24 -pU:53,U:161,U:123 --rate 1000
\`\`\`
DNS, SNMP ve NTP servislerini UDP üzerinden tarar.

**Internal Network Reconnaissance:**
\`\`\`bash
masscan 10.0.0.0/8 -p22,445,3389 --rate 5000 --open
\`\`\`
İç ağda SSH, SMB ve RDP servislerini hızlıca bulur.

**ICS/SCADA Port Scanning:**
\`\`\`bash
masscan 192.168.1.0/24 -p502,102,47808 --rate 100
\`\`\`
Modbus, S7 ve BACnet portlarını düşük hızda tarar (cihazları düşürmemek için).

**Erişim Kısıtlı Ağlarda Stealth Tarama:**
\`\`\`bash
masscan 192.168.1.0/24 -p80 --rate 10 --wait 10
\`\`\`
Çok yavaş tarama yaparak IDS eşiklerinin altında kalmaya çalışır.

**Time-based Throttling ile DDoS Oluşturmadan Tarama:**
\`\`\`bash
masscan targets.txt -p80 --rate 500
\`\`\`
Hızı sınırlayarak hedef ağda tıkanıklık yaratmaz.

**ISP Seviyesinde Geniş Subnet Analizi:**
\`\`\`bash
masscan 203.0.113.0/24 -p0-65535 --banners
\`\`\`
Bir ISP bloğundaki tüm servisleri ve bannerlarını toplar.

**Spoofing + Distributed Scan Kombinasyonu:**
\`\`\`bash
masscan 192.168.1.1 -p80 --source-ip 10.0.0.5
\`\`\`
Paketleri başka bir IP'den geliyormuş gibi gösterir (yanıtlar o IP'ye gider).

**IoT Cihaz Port Analizi:**
\`\`\`bash
masscan 192.168.1.0/24 -p23,80,8080,554 --rate 1000
\`\`\`
Telnet, Web ve RTSP portlarını tarayarak IoT cihazlarını belirler.

**Honeypot Tespiti:**
\`\`\`bash
masscan 192.168.1.1 -p1-65535 --rate 1000 --banners
\`\`\`
Tüm portların açık görünmesi veya standart dışı bannerlar honeypot işaretidir.

**Cloud Asset Discovery (AWS, Azure, GCP):**
\`\`\`bash
masscan -iL cloud_ranges.txt -p80,443,22 --rate 50000
\`\`\`
Bulut IP aralıklarında aktif varlıkları tespit eder.

## 8. Best Practices (Uzman Seviye)

*   **Rate Ayarı:** Bant genişliğinizi test edin ve %80'ini geçmeyin. Ev bağlantısında 1000-5000 pps güvenlidir.
*   **Bandwidth Aşımı:** Router'ınızı kilitleyebilir veya ISS tarafından engellenebilirsiniz.
*   **Packet-Loss Threshold:** Paket kaybı artarsa hızı düşürün. Masscan çıkışta ne kadar kaybettiğini raporlar.
*   **Firewall Alarm:** SYN flood benzeri trafik ürettiği için IDS/IPS alarmlarını tetikler.
*   **Combine (Masscan → Nmap):** Masscan ile "nerede kapı var"ı bulun, Nmap ile "içeride ne var"ı öğrenin.
*   **Otomasyon:** Çıktıları JSON/XML alıp Python scriptleri ile işleyin.
*   **TTL/Fragment:** Firewall atlatmak için TTL değerlerini ve fragmentasyon seçeneklerini kullanın.
*   **Stateless Taktikleri:** Yanıt beklemediği için bağlantı kopmaları taramayı durdurmaz.

## 9. Sık Yapılan Hatalar

*   **Rate Çok Yüksek:** Paket kaybına neden olur, sonuçlar eksik çıkar.
*   **Yanlış Interface Seçimi:** VPN veya yanlış adaptör üzerinden tarama yapmak (hiç sonuç dönmez).
*   **Source-IP Spoofing ile Routing Uyumsuzluğu:** Spoof edilen IP'ye dönen yanıtları alamazsanız tarama boşa gider (sadece blind attack için işe yarar).
*   **Packet-Wait Süresinin Yanlış Ayarlanması:** Tarama biter bitmez kapatırsanız, geciken yanıtları kaçırırsınız (\`--wait\` kullanın).
*   **Banner Scan'ın Gereksiz Çalıştırılması:** Banner toplamak TCP handshake gerektirir, hızı düşürür ve stateless avantajını azaltır.
*   **Exclude-List Kullanmadan Büyük Subnet Taramak:** Kendi IP'nizi, gateway'i veya kritik sunucuları yanlışlıkla tarayabilirsiniz.
*   **Packet Fragmentation:** Bazı firewall'lar parçalanmış paketleri doğrudan düşürür (drop).
*   **Output Formatı Yanlış Seçmek:** Büyük taramalarda düz metin yerine binary (-oB) kullanın, sonra convert edin.
`;

const contentEN = `# Masscan - Internet Scale Port Scanner

## 3. Basic Usage

**Target IP/Port Scanning:**
\`\`\`bash
masscan 192.168.1.10 -p80,443
\`\`\`
→ **-p**: Specifies ports to scan (comma-separated).

**Range Scanning:**
\`\`\`bash
masscan 192.168.1.0/24 -p0-65535
\`\`\`
→ **CIDR**: IP range (subnet) specification.
→ **-p0-65535**: Scans all ports.

**Interface Selection:**
\`\`\`bash
masscan 10.0.0.0/8 -p80 -e eth0
\`\`\`
→ **-e**: Selects the network interface to use.

**Rate Setting:**
\`\`\`bash
masscan 10.0.0.0/8 -p80 --rate 10000
\`\`\`
→ **--rate**: Packets per second (pps) to transmit.

**Output Formats:**
\`\`\`bash
masscan 10.0.0.0/8 -p80 -oX scan.xml
\`\`\`
→ **-oX**: Saves results in XML format.

**Basic SYN Scan Logic:**
Masscan performs SYN scan by default (stateless). It doesn't establish a connection, just waits for SYN-ACK.

**Top Ports Scanning:**
\`\`\`bash
masscan 192.168.1.1 --top-ports 100
\`\`\`
→ **--top-ports**: Scans the most popular N ports.

**Single Port / Port Range:**
\`\`\`bash
masscan 192.168.1.1 -p80
masscan 192.168.1.1 -p1-1024
\`\`\`

**Timing:**
Since Masscan is asynchronous, it doesn't need aggressive timing templates (T4, T5) like Nmap; speed is determined by \`--rate\`.

**Pcap Output:**
\`\`\`bash
masscan 192.168.1.1 -p80 --pcap capture.pcap
\`\`\`
→ **--pcap**: Writes sent and received packets to a pcap file.

## 4. Advanced Usage

### Masscan Engine & Architecture
*   **Asynchronous Stateless Scanning**: Masscan doesn't keep state for each connection. This allows managing millions of packets simultaneously.
*   **Raw Packet Injection**: Bypasses the OS network stack (TCP/IP stack) to generate and send packets directly at the driver level.
*   **TCP SYN Flood Technique**: Manages the scan like a DoS attack but listens for responses to detect open ports.
*   **Userland Packet Forge**: Packets are created in userland instead of kernel, increasing performance.
*   **Real-time Packet Processing**: Incoming responses (SYN-ACK, RST) are processed instantly by a separate thread.

### Advanced Scanning Techniques
*   **Multiple Target-Input**:
    \`\`\`bash
    masscan -iL targets.txt --exclude-file exclude.txt
    \`\`\`
*   **Purely Stateless Scan Advantages**: Doesn't wait for connection timeouts, fires packets and forgets.
*   **Spoofing (Source IP)**:
    \`\`\`bash
    masscan ... --source-ip 192.168.1.200
    \`\`\`
    Changes source IP address for firewall evasion or stealth.
*   **Port-Bounce (--banners)**: Attempts to complete TCP connection to collect service banners (requires stateful behavior).
*   **Firewall Evasion**: Tests firewall rules with fragmented packets or custom TCP flags.
*   **Packet Rate Tuning**: \`--rate\` setting is critical based on network bandwidth. Too high speed causes packet loss.
*   **Randomize Host/Port Ordering**: Scans randomly instead of linearly to make IDS/IPS detection harder (default behavior).

### Performance & Tuning
*   **--rate Detailed Optimization**: Adjust according to your upload speed. ~1.5 million pps is possible on a 1 Gbps line.
*   **NIC Offloading**: May need to disable network card offloading features for performance.
*   **CPU Affinity**: Masscan is very efficient on a single core, but scalable with multiple instances.
*   **Packet Loss Reduction**: Lowering speed or increasing \`--retries\` reduces packet loss.

### Masscan → Nmap Workflow
1.  **Fast Discovery with Masscan**: Scan large network to find open ports.
2.  **Only-Open-Ports**: Parse output to get only open IP:Port list.
3.  **Service/Version Scan with Nmap**:
    \`\`\`bash
    nmap -sV -sC -iL open_ports.txt
    \`\`\`
    This method is much faster than scanning the entire network with Nmap.

## 5. Annotated Commands (EXTENDED LIST)

**Command:**
\`\`\`bash
masscan -p1-65535 10.0.0.0/8 --rate 100000 -oG output.grep --exclude 10.0.0.1
\`\`\`
**Description:**
Scans all ports on 10.0.0.0/8 network at 100,000 packets per second, excluding 10.0.0.1, and saves in grepable format.

**Argument Explanations:**
*   **-p**: Port range (1-65535).
*   **CIDR**: Target network (10.0.0.0/8).
*   **--rate**: Packet rate.
*   **-oG**: Grepable output format.
*   **--exclude**: IP to exclude.

**Basic Arguments:**
*   **-p**: Port or port range.
*   **-iL**: Target list file.
*   **--exclude**: Targets to exclude.
*   **--exclude-file**: File containing exclude list.
*   **--interactive**: Interactive mode (keyboard commands active).
*   **--wait**: Time to wait for responses after scan finishes (seconds).
*   **--ping**: Host discovery with ICMP echo request (no port scan).

**Network & Interface Arguments:**
*   **-e**: Interface selection (eth0, tun0 etc.).
*   **--source-ip**: Spoofed source IP.
*   **--source-port**: Source port or port range.
*   **--router-mac**: Gateway MAC address (if manual specification needed).
*   **--adapter-ip**: Adapter IP to listen on.
*   **--adapter-port**: Bind port for raw packet sending.

**Performance Arguments:**
*   **--rate**: Packets per second (pps).
*   **--max-rate**: Upper limit for auto-adjustment.
*   **--min-rate**: Lower limit for auto-adjustment.
*   **--retries**: Number of packet resends if no response.
*   **--connection-timeout**: TCP connection timeout.
*   **--sendq**: Send queue size.

**Output Arguments:**
*   **-oL**: List format output.
*   **-oJ**: JSON format output.
*   **-oX**: XML format output.
*   **-oG**: Grepable output.
*   **--packet-trace**: Prints every sent/received packet.
*   **--pcap**: Saves traffic to pcap file.
*   **--banner**: Collects service banners (HTTP server, SSH version etc.).

**Firewall Evasion / Stealth Arguments:**
*   **--badsum**: Sends packets with invalid TCP checksum (to confuse some firewalls).
*   **--ttl**: Sets IP Time-To-Live value.
*   **--flags**: Sets custom TCP flags (SYN, ACK, PSH etc.).
*   **--fragment**: Fragments packets (firewall evasion).
*   **--randomize-hosts**: Randomizes host scan order.
*   **--randomize-ports**: Randomizes port scan order.

## 6. Real Pentest Scenarios

**Fast Port Discovery on Very Large IP Range:**
\`\`\`bash
masscan 0.0.0.0/0 -p80,443 --rate 10000000 --exclude-file exclude.conf
\`\`\`
Scans the entire internet (or very large range) for HTTP/HTTPS.

**Detecting Open Ports Behind Firewall:**
\`\`\`bash
masscan 192.168.1.1 -p0-65535 --source-port 53
\`\`\`
Sets source port to 53 (DNS) to attempt bypassing firewall rules.

**Datacenter Scanning (10+ Million IPs):**
\`\`\`bash
masscan -iL datacenter_ips.txt -p80,8080,443 --rate 200000 -oB binary.scan
\`\`\`
Saves large scale scan in binary format (-oB) to prevent disk I/O bottleneck.

**UDP-Based Service Discovery:**
\`\`\`bash
masscan 192.168.1.0/24 -pU:53,U:161,U:123 --rate 1000
\`\`\`
Scans DNS, SNMP, and NTP services over UDP.

**Internal Network Reconnaissance:**
\`\`\`bash
masscan 10.0.0.0/8 -p22,445,3389 --rate 5000 --open
\`\`\`
Quickly finds SSH, SMB, and RDP services on internal network.

**ICS/SCADA Port Scanning:**
\`\`\`bash
masscan 192.168.1.0/24 -p502,102,47808 --rate 100
\`\`\`
Scans Modbus, S7, and BACnet ports at low speed (to avoid crashing devices).

**Stealth Scanning on Restricted Networks:**
\`\`\`bash
masscan 192.168.1.0/24 -p80 --rate 10 --wait 10
\`\`\`
Scans very slowly to stay under IDS thresholds.

**Scanning Without DDoS via Time-based Throttling:**
\`\`\`bash
masscan targets.txt -p80 --rate 500
\`\`\`
Limits speed to avoid creating congestion on target network.

**Broad Subnet Analysis at ISP Level:**
\`\`\`bash
masscan 203.0.113.0/24 -p0-65535 --banners
\`\`\`
Collects all services and banners in an ISP block.

**Spoofing + Distributed Scan Combination:**
\`\`\`bash
masscan 192.168.1.1 -p80 --source-ip 10.0.0.5
\`\`\`
Makes packets appear to come from another IP (responses go to that IP).

**IoT Device Port Analysis:**
\`\`\`bash
masscan 192.168.1.0/24 -p23,80,8080,554 --rate 1000
\`\`\`
Identifies IoT devices by scanning Telnet, Web, and RTSP ports.

**Honeypot Detection:**
\`\`\`bash
masscan 192.168.1.1 -p1-65535 --rate 1000 --banners
\`\`\`
All ports appearing open or non-standard banners are signs of a honeypot.

**Cloud Asset Discovery (AWS, Azure, GCP):**
\`\`\`bash
masscan -iL cloud_ranges.txt -p80,443,22 --rate 50000
\`\`\`
Detects active assets in cloud IP ranges.

## 8. Best Practices (Expert Level)

*   **Rate Setting:** Test your bandwidth and don't exceed 80%. 1000-5000 pps is safe for home connections.
*   **Bandwidth Overflow:** Can lock up your router or get you blocked by ISP.
*   **Packet-Loss Threshold:** Reduce speed if packet loss increases. Masscan reports loss on exit.
*   **Firewall Alarm:** Triggers IDS/IPS alarms as it generates SYN flood-like traffic.
*   **Combine (Masscan → Nmap):** Find "where the door is" with Masscan, learn "what's inside" with Nmap.
*   **Automation:** Get outputs in JSON/XML and process with Python scripts.
*   **TTL/Fragment:** Use TTL values and fragmentation options to bypass firewalls.
*   **Stateless Tactics:** Connection drops don't stop the scan since it doesn't wait for responses.

## 9. Common Mistakes

*   **Rate Too High:** Causes packet loss, results will be incomplete.
*   **Wrong Interface Selection:** Scanning over VPN or wrong adapter (returns no results).
*   **Routing Mismatch with Source-IP Spoofing:** If you can't receive responses sent to the spoofed IP, the scan is wasted (useful only for blind attacks).
*   **Wrong Packet-Wait Setting:** If you close immediately after scan finishes, you miss delayed responses (use \`--wait\`).
*   **Unnecessary Banner Scan:** Collecting banners requires TCP handshake, slows down speed, and reduces stateless advantage.
*   **Scanning Large Subnets Without Exclude-List:** You might accidentally scan your own IP, gateway, or critical servers.
*   **Packet Fragmentation:** Some firewalls drop fragmented packets directly.
*   **Wrong Output Format:** Use binary (-oB) for large scans instead of plain text, then convert.
`;

async function addMasscan() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Masscan cheatsheet...');

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
                tr: 'Masscan Cheat Sheet',
                en: 'Masscan Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['network', 'scanning', 'port', 'fast', 'stateless']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Masscan Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Masscan cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addMasscan();
