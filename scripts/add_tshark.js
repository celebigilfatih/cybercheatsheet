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

const contentTR = `# TShark - Network Protocol Analyzer

## 1. Araç Tanımı
**TShark**, Wireshark'ın komut satırı (CLI) versiyonudur. Ağ trafiğini yakalamak, analiz etmek, protokolleri çözümlemek (dissect) ve pcap dosyalarını işlemek için kullanılır. Özellikle otomasyon, sunucu tabanlı analiz ve büyük pcap dosyalarının işlenmesi (pipeline) süreçlerinde tercih edilir.

## 2. Kurulum
*   **Linux (Debian/Kali)**: \`sudo apt install tshark\`
*   **Windows**: Wireshark kurulumu ile birlikte gelir.
*   **macOS**: \`brew install wireshark\`

## 3. Temel Kullanım

**Basit Paket Yakalama:**
\`\`\`bash
tshark -i eth0
\`\`\`
**Açıklama:**
eth0 arayüzündeki trafiği canlı olarak yakalar ve ekrana basar.
**Argümanlar:**
*   **-i**: Interface seçimi.

**Display Filter Kullanımı:**
\`\`\`bash
tshark -r capture.pcap -Y "http.request.method == GET"
\`\`\`
**Açıklama:**
Pcap dosyasını okur ve sadece HTTP GET isteklerini gösterir.
**Argümanlar:**
*   **-r**: Pcap dosyasından okuma.
*   **-Y**: Display filter.

**Capture Filter Kullanımı:**
\`\`\`bash
tshark -i eth0 -f "port 80"
\`\`\`
**Açıklama:**
Sadece 80. port trafiğini yakalar (Kernel seviyesinde filtreleme).
**Argümanlar:**
*   **-f**: Capture filter (BPF syntax).

**Field Extraction:**
\`\`\`bash
tshark -r traffic.pcap -T fields -e ip.src -e ip.dst
\`\`\`
**Açıklama:**
Sadece kaynak ve hedef IP adreslerini çıkarır.
**Argümanlar:**
*   **-T fields**: Sadece belirtilen alanları bas.
*   **-e**: Çıkarılacak alan (field).

## 4. İleri Seviye Kullanım

### Wireshark Display Filters
*   Derinlemesine analiz için Wireshark'ın güçlü filtreleme motorunu kullanır (örn: \`tcp.analysis.flags\`, \`tls.handshake.type\`).
*   **Capture Filter vs Display Filter**: Capture filter (-f) yakalama anında çalışır ve performansı artırır. Display filter (-Y) analiz anında çalışır ve esnektir.

### Protocol Dissection
*   **Desteklenen Protokoller**: TCP, TLS, DNS, HTTP, SIP, SMB, Kerberos, QUIC ve yüzlercesi.
*   **TLS Handshake**: \`tls.handshake.type == 1\` (Client Hello) ile şifreli trafiğin başlangıcı analiz edilebilir.
*   **DNS**: \`dns.qry.name\` ve \`dns.a\` ile sorgu ve yanıtlar ayrıştırılır.

### Output Formats & Pipeline
*   **JSON/PDML**: \`-T json\` veya \`-T pdml\` ile çıktıyı programatik olarak işlenebilir formatta üretir.
*   **Pipeline**: \`tshark ... | grep ... | awk ...\` zinciri ile çok hızlı log analizi yapılabilir.
*   **Large Pcap Splitting**: \`editcap\` veya TShark'ın \`-c\` (count) parametresi ile devasa dosyalar bölünebilir.

### Statistics & Stream Analysis
*   **Statistics**: \`-z io,stat\` ile I/O grafikleri, \`-z conv,tcp\` ile TCP konuşmaları listelenir.
*   **Follow Stream**: \`-z follow,tcp,ascii,0\` ile 0 numaralı TCP akışının içeriği (payload) okunabilir.

### Decryption
*   **TLS**: \`-o tls.keylog_file:keys.log\` ile SSL/TLS trafiği çözülebilir.
*   **WPA**: \`-o wlan.enable_decryption:TRUE\` ile kablosuz ağ trafiği çözülebilir.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

**Komut:**
\`\`\`bash
tshark -i eth0 -w capture.pcap -c 1000
\`\`\`
**Açıklama:**
eth0 üzerinden 1000 paket yakalar ve dosyaya yazar.
**Argümanlar:**
*   **-w**: Yazılacak dosya.
*   **-c**: Paket limiti.

**Komut:**
\`\`\`bash
tshark -r traffic.pcap -T fields -e http.host -e http.request.uri -Y "http.request"
\`\`\`
**Açıklama:**
HTTP isteklerinden Host ve URI bilgilerini çıkarır.
**Argümanlar:**
*   **-T fields**: Field modu.
*   **-e**: İstenen alanlar.
*   **-Y**: Sadece HTTP isteklerini filtrele.

**Komut:**
\`\`\`bash
tshark -i wlan0 -f "host 192.168.1.5" -p
\`\`\`
**Açıklama:**
Promiscuous mod kapalı olarak (-p) sadece belirli bir hostun trafiğini dinler.
**Argümanlar:**
*   **-p**: No promiscuous mode.
*   **-f**: Capture filter.

**Komut:**
\`\`\`bash
tshark -r ssl.pcap -o tls.keylog_file:session.keys -Y "http"
\`\`\`
**Açıklama:**
Keylog dosyası kullanarak şifreli pcap içindeki HTTP trafiğini çözer ve gösterir.
**Argümanlar:**
*   **-o**: Opsiyon ayarı (TLS keylog).

**Komut:**
\`\`\`bash
tshark -r dns.pcap -T json > dns_log.json
\`\`\`
**Açıklama:**
DNS trafiğini JSON formatına çevirir.
**Argümanlar:**
*   **-T json**: JSON çıktısı.

**Komut:**
\`\`\`bash
tshark -i eth0 -b filesize:100 -b files:5 -w ring.pcap
\`\`\`
**Açıklama:**
Ring buffer modunda, her biri 100MB olan en fazla 5 dosya tutarak sürekli kayıt yapar.
**Argümanlar:**
*   **-b filesize**: Dosya boyutu (KB).
*   **-b files**: Dosya adedi.

**Komut:**
\`\`\`bash
tshark -r smb.pcap -z smb,srt
\`\`\`
**Açıklama:**
SMB protokolü için Servis Yanıt Süresi (SRT) istatistiklerini hesaplar.
**Argümanlar:**
*   **-z**: İstatistik modülü.

**Komut:**
\`\`\`bash
tshark -r traffic.pcap -q -z io,phs
\`\`\`
**Açıklama:**
Paketleri ekrana basmadan (-q) protokol hiyerarşisi istatistiklerini gösterir.
**Argümanlar:**
*   **-q**: Quiet (sessiz) mod.
*   **-z io,phs**: Protocol Hierarchy Statistics.

**Komut:**
\`\`\`bash
tshark -r voip.pcap -z sip,stat
\`\`\`
**Açıklama:**
SIP (VoIP) trafiği istatistiklerini gösterir.

**Komut:**
\`\`\`bash
tshark -r traffic.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0"
\`\`\`
**Açıklama:**
Sadece TCP SYN paketlerini (yeni bağlantı istekleri) filtreler.

**Komut:**
\`\`\`bash
tshark -r traffic.pcap -T fields -e frame.time -e ip.src -E header=y -E separator=,
\`\`\`
**Açıklama:**
Zaman damgası ve kaynak IP'yi CSV formatında (başlıklı ve virgül ayraçlı) basar.
**Argümanlar:**
*   **-E header=y**: Başlık ekle.
*   **-E separator=,**: Virgül ile ayır.

**Komut:**
\`\`\`bash
tshark -r traffic.pcap -x -Y "dns"
\`\`\`
**Açıklama:**
DNS paketlerinin Hex ve ASCII dökümünü (-x) gösterir.
**Argümanlar:**
*   **-x**: Hex/ASCII dump.

**Komut:**
\`\`\`bash
tshark -n -r traffic.pcap
\`\`\`
**Açıklama:**
DNS çözümlemesi yapmadan (-n) pcap dosyasını okur (Hızlandırır).
**Argümanlar:**
*   **-n**: No name resolution.

**Komut:**
\`\`\`bash
tshark -r traffic.pcap -Y "ip.addr == 192.168.1.10" -w filtered.pcap
\`\`\`
**Açıklama:**
Mevcut pcap dosyasından belirli bir IP'yi filtreleyip yeni bir pcap dosyasına kaydeder.

**Komut:**
\`\`\`bash
tshark -D
\`\`\`
**Açıklama:**
Mevcut ağ arayüzlerini listeler.

## 6. Gerçek Pentest ve DFIR Senaryoları

**Senaryo: SYN Flood Tespiti**
*   **Komut**: \`tshark -r ddos.pcap -q -z io,stat,1,"COUNT(tcp.flags.syn==1 && tcp.flags.ack==0)tcp.flags.syn"\`
*   **Açıklama**: Saniyedeki SYN paketi sayısını analiz eder. Anormal artışlar SYN Flood saldırısını gösterir.

**Senaryo: DNS Exfiltration Analizi**
*   **Komut**: \`tshark -r dns.pcap -T fields -e dns.qry.name -Y "dns.flags.response == 0" | sort | uniq -c | sort -nr\`
*   **Açıklama**: En çok sorgulanan domainleri listeler. Uzun ve anlamsız subdomainler (örn: \`base64.attacker.com\`) veri kaçırma işaretidir.

**Senaryo: HTTP Credential Leak**
*   **Komut**: \`tshark -r http.pcap -Y "http.request.method == POST" -T fields -e http.file_data\`
*   **Açıklama**: HTTP POST isteklerinin gövdesini (body) basar. Şifrelenmemiş login formlarındaki kullanıcı adı ve parolaları ifşa eder.

**Senaryo: TLS Handshake Analizi (JA3 Fingerprinting)**
*   **Komut**: \`tshark -r tls.pcap -T fields -e tls.handshake.ciphersuites -Y "tls.handshake.type == 1"\`
*   **Açıklama**: Client Hello paketlerindeki cipher suite listesini çıkarır. Malware veya spesifik istemcilerin parmak izini (fingerprint) belirlemek için kullanılır.

**Senaryo: SMB Brute-Force İzleri**
*   **Komut**: \`tshark -r smb.pcap -Y "smb2.nt_status == 0xc000006d"\`
*   **Açıklama**: "STATUS_LOGON_FAILURE" hatası dönen SMB paketlerini filtreler. Çok sayıda başarısız giriş denemesi brute-force göstergesidir.

## 8. Best Practices (Uzman Seviye)

*   **Capture Filter Kullanımı**: Canlı trafikte her zaman \`-f\` kullanın. \`-Y\` (Display filter) sadece analiz içindir, yakalama yükünü azaltmaz.
*   **Pipeline**: TShark çıktısını doğrudan dosyaya yazmak yerine \`grep\` veya \`awk\` ile işleyerek sadece ilgilendiğiniz veriyi saklayın.
*   **Minimal Verbose**: \`-V\` parametresini sadece tekil paket analizi için kullanın, tüm pcap üzerinde kullanmak çıktıyı okunmaz hale getirir.
*   **Name Resolution**: \`-n\` parametresi ile DNS çözümlemesini kapatmak analizi ciddi oranda hızlandırır.
*   **Ring Buffer**: Uzun süreli izlemelerde diski doldurmamak için \`-b files:N\` ile döngüsel kayıt yapın.

## 9. Sık Yapılan Hatalar

*   **Filter Karışıklığı**: Capture filter (-f) yerine Display filter (-Y) syntax'ını kullanmaya çalışmak (örn: \`-f "ip.addr==..."\` yanlıştır, \`-f "host ..."\` doğrudur).
*   **Snaplen**: Varsayılan snaplen bazen payload'ı kesebilir. Tam paket analizi için \`-s 0\` (unlimited) kullanın.
*   **Root Yetkisi**: Canlı yakalama için root/admin yetkisi gerekir, ancak pcap okumak için gerekmez. Güvenlik için pcap analizini normal kullanıcı ile yapın.
*   **Buffer Overflow**: Yüksek trafikli ağlarda varsayılan buffer yetersiz kalabilir, \`-B\` ile artırın.
`;

const contentEN = `# TShark - Network Protocol Analyzer

## 1. Tool Definition
**TShark** is the command-line (CLI) version of Wireshark. It is used to capture network traffic, analyze packets, dissect protocols, and process pcap files. It is especially preferred for automation, server-based analysis, and processing large pcap files (pipeline).

## 2. Installation
*   **Linux (Debian/Kali)**: \`sudo apt install tshark\`
*   **Windows**: Comes with Wireshark installation.
*   **macOS**: \`brew install wireshark\`

## 3. Basic Usage

**Simple Packet Capture:**
\`\`\`bash
tshark -i eth0
\`\`\`
**Description:**
Captures live traffic on interface eth0 and prints to screen.
**Arguments:**
*   **-i**: Interface selection.

**Using Display Filters:**
\`\`\`bash
tshark -r capture.pcap -Y "http.request.method == GET"
\`\`\`
**Description:**
Reads pcap file and shows only HTTP GET requests.
**Arguments:**
*   **-r**: Read from pcap file.
*   **-Y**: Display filter.

**Using Capture Filters:**
\`\`\`bash
tshark -i eth0 -f "port 80"
\`\`\`
**Description:**
Captures only port 80 traffic (Kernel level filtering).
**Arguments:**
*   **-f**: Capture filter (BPF syntax).

**Field Extraction:**
\`\`\`bash
tshark -r traffic.pcap -T fields -e ip.src -e ip.dst
\`\`\`
**Description:**
Extracts only source and destination IP addresses.
**Arguments:**
*   **-T fields**: Print only specified fields.
*   **-e**: Field to extract.

## 4. Advanced Usage

### Wireshark Display Filters
*   Uses Wireshark's powerful filtering engine for deep analysis (e.g., \`tcp.analysis.flags\`, \`tls.handshake.type\`).
*   **Capture vs Display Filter**: Capture filter (-f) works during capture and improves performance. Display filter (-Y) works during analysis and is flexible.

### Protocol Dissection
*   **Supported Protocols**: TCP, TLS, DNS, HTTP, SIP, SMB, Kerberos, QUIC, and hundreds more.
*   **TLS Handshake**: Analyze start of encrypted traffic with \`tls.handshake.type == 1\` (Client Hello).
*   **DNS**: Separate queries and responses with \`dns.qry.name\` and \`dns.a\`.

### Output Formats & Pipeline
*   **JSON/PDML**: Generate programmatically processable output with \`-T json\` or \`-T pdml\`.
*   **Pipeline**: Fast log analysis chain with \`tshark ... | grep ... | awk ...\`.
*   **Large Pcap Splitting**: Split huge files using \`editcap\` or TShark's \`-c\` (count) parameter.

### Statistics & Stream Analysis
*   **Statistics**: I/O graphs with \`-z io,stat\`, TCP conversations with \`-z conv,tcp\`.
*   **Follow Stream**: Read payload of TCP stream 0 with \`-z follow,tcp,ascii,0\`.

### Decryption
*   **TLS**: Decrypt SSL/TLS traffic with \`-o tls.keylog_file:keys.log\`.
*   **WPA**: Decrypt wireless traffic with \`-o wlan.enable_decryption:TRUE\`.

## 5. Annotated Commands (Extended List)

**Command:**
\`\`\`bash
tshark -i eth0 -w capture.pcap -c 1000
\`\`\`
**Description:**
Captures 1000 packets on eth0 and writes to file.
**Arguments:**
*   **-w**: Write to file.
*   **-c**: Packet count limit.

**Command:**
\`\`\`bash
tshark -r traffic.pcap -T fields -e http.host -e http.request.uri -Y "http.request"
\`\`\`
**Description:**
Extracts Host and URI info from HTTP requests.
**Arguments:**
*   **-T fields**: Field mode.
*   **-e**: Desired fields.
*   **-Y**: Filter only HTTP requests.

**Command:**
\`\`\`bash
tshark -i wlan0 -f "host 192.168.1.5" -p
\`\`\`
**Description:**
Listens to traffic of a specific host with promiscuous mode disabled (-p).
**Arguments:**
*   **-p**: No promiscuous mode.
*   **-f**: Capture filter.

**Command:**
\`\`\`bash
tshark -r ssl.pcap -o tls.keylog_file:session.keys -Y "http"
\`\`\`
**Description:**
Decrypts and shows HTTP traffic inside encrypted pcap using keylog file.
**Arguments:**
*   **-o**: Option setting (TLS keylog).

**Command:**
\`\`\`bash
tshark -r dns.pcap -T json > dns_log.json
\`\`\`
**Description:**
Converts DNS traffic to JSON format.
**Arguments:**
*   **-T json**: JSON output.

**Command:**
\`\`\`bash
tshark -i eth0 -b filesize:100 -b files:5 -w ring.pcap
\`\`\`
**Description:**
Continuous recording in ring buffer mode, keeping max 5 files of 100MB each.
**Arguments:**
*   **-b filesize**: File size (KB).
*   **-b files**: File count.

**Command:**
\`\`\`bash
tshark -r smb.pcap -z smb,srt
\`\`\`
**Description:**
Calculates Service Response Time (SRT) statistics for SMB protocol.
**Arguments:**
*   **-z**: Statistics module.

**Command:**
\`\`\`bash
tshark -r traffic.pcap -q -z io,phs
\`\`\`
**Description:**
Shows protocol hierarchy statistics without printing packets (-q).
**Arguments:**
*   **-q**: Quiet mode.
*   **-z io,phs**: Protocol Hierarchy Statistics.

**Command:**
\`\`\`bash
tshark -r voip.pcap -z sip,stat
\`\`\`
**Description:**
Shows SIP (VoIP) traffic statistics.

**Command:**
\`\`\`bash
tshark -r traffic.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0"
\`\`\`
**Description:**
Filters only TCP SYN packets (new connection requests).

**Command:**
\`\`\`bash
tshark -r traffic.pcap -T fields -e frame.time -e ip.src -E header=y -E separator=,
\`\`\`
**Description:**
Prints timestamp and source IP in CSV format (with header and comma separator).
**Arguments:**
*   **-E header=y**: Add header.
*   **-E separator=,**: Separate with comma.

**Command:**
\`\`\`bash
tshark -r traffic.pcap -x -Y "dns"
\`\`\`
**Description:**
Shows Hex and ASCII dump (-x) of DNS packets.
**Arguments:**
*   **-x**: Hex/ASCII dump.

**Command:**
\`\`\`bash
tshark -n -r traffic.pcap
\`\`\`
**Description:**
Reads pcap file without DNS resolution (-n) (Faster).
**Arguments:**
*   **-n**: No name resolution.

**Command:**
\`\`\`bash
tshark -r traffic.pcap -Y "ip.addr == 192.168.1.10" -w filtered.pcap
\`\`\`
**Description:**
Filters a specific IP from existing pcap and saves to a new pcap file.

**Command:**
\`\`\`bash
tshark -D
\`\`\`
**Description:**
Lists available network interfaces.

## 6. Real Pentest and DFIR Scenarios

**Scenario: SYN Flood Detection**
*   **Command**: \`tshark -r ddos.pcap -q -z io,stat,1,"COUNT(tcp.flags.syn==1 && tcp.flags.ack==0)tcp.flags.syn"\`
*   **Description**: Analyzes SYN packet count per second. Abnormal spikes indicate SYN Flood attack.

**Scenario: DNS Exfiltration Analysis**
*   **Command**: \`tshark -r dns.pcap -T fields -e dns.qry.name -Y "dns.flags.response == 0" | sort | uniq -c | sort -nr\`
*   **Description**: Lists most queried domains. Long and nonsensical subdomains (e.g., \`base64.attacker.com\`) are signs of data exfiltration.

**Scenario: HTTP Credential Leak**
*   **Command**: \`tshark -r http.pcap -Y "http.request.method == POST" -T fields -e http.file_data\`
*   **Description**: Prints body of HTTP POST requests. Reveals usernames and passwords in unencrypted login forms.

**Scenario: TLS Handshake Analysis (JA3 Fingerprinting)**
*   **Command**: \`tshark -r tls.pcap -T fields -e tls.handshake.ciphersuites -Y "tls.handshake.type == 1"\`
*   **Description**: Extracts cipher suite list from Client Hello packets. Used to fingerprint malware or specific clients.

**Scenario: SMB Brute-Force Traces**
*   **Command**: \`tshark -r smb.pcap -Y "smb2.nt_status == 0xc000006d"\`
*   **Description**: Filters SMB packets returning "STATUS_LOGON_FAILURE". High volume indicates brute-force attempts.

## 8. Best Practices (Expert Level)

*   **Use Capture Filters**: Always use \`-f\` for live capture. \`-Y\` (Display filter) is for analysis only and doesn't reduce capture load.
*   **Pipeline**: Instead of writing TShark output directly to file, process with \`grep\` or \`awk\` to store only relevant data.
*   **Minimal Verbose**: Use \`-V\` only for single packet analysis; using it on full pcap makes output unreadable.
*   **Name Resolution**: Turning off DNS resolution with \`-n\` significantly speeds up analysis.
*   **Ring Buffer**: Use \`-b files:N\` for circular recording to avoid filling up disk during long-term monitoring.

## 9. Common Mistakes

*   **Filter Confusion**: Trying to use Display filter (-Y) syntax in Capture filter (-f) (e.g., \`-f "ip.addr==..."\` is wrong, \`-f "host ..."\` is correct).
*   **Snaplen**: Default snaplen might cut payload. Use \`-s 0\` (unlimited) for full packet analysis.
*   **Root Privileges**: Root/admin is needed for live capture, but not for reading pcaps. Analyze pcaps as normal user for security.
*   **Buffer Overflow**: Default buffer might be insufficient for high traffic networks, increase with \`-B\`.
`;

async function addTshark() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding TShark cheatsheet...');

        // 1. Find or create the category
        let category = await Category.findOne({ 'name.en': 'Traffic Analysis' });
        if (!category) {
            console.log('Category "Traffic Analysis" not found, creating...');
            category = await Category.create({
                name: { tr: 'Trafik Analizi', en: 'Traffic Analysis' },
                description: { tr: 'Ağ trafiği izleme ve analiz araçları', en: 'Network traffic monitoring and analysis tools' },
                slug: 'traffic-analysis',
                icon: 'Activity'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'TShark Cheat Sheet',
                en: 'TShark Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['tshark', 'wireshark', 'pcap', 'network', 'analysis', 'packet']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'TShark Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('TShark cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addTshark();
