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

const contentTR = `# Wireshark - Network Protocol Analyzer

## 3. Temel Kullanım

**Display Filter Mantığı:**
Ekran filtresi, yakalanmış paketler arasında sadece ilgilendiğiniz paketleri görmenizi sağlar. Arama çubuğuna yazılır (örn: \`ip.addr == 192.168.1.1\`).

**Capture Filter Mantığı:**
Yakalama filtresi, sadece belirli kriterlere uyan paketlerin diske kaydedilmesini sağlar. Trafik yoğunluğunu azaltmak için kullanılır (BPF syntax: \`host 192.168.1.1\`).

**Interface Seçimi:**
Başlangıç ekranında trafiğin aktığı ağ kartını (Wi-Fi, Ethernet, Loopback) seçin. Dalgalı çizgi trafiğin varlığını gösterir.

**Pcap Kayıt Açma/Kaydetme:**
*   **File > Open**: Varolan .pcap/.pcapng dosyasını açar.
*   **File > Save As**: Analiz edilen paketleri kaydeder.

**Paket Detay Penceresi:**
*   **Frame**: Fiziksel katman ve zaman bilgisi.
*   **Ethernet**: MAC adresleri.
*   **IP**: Kaynak/Hedef IP, TTL.
*   **TCP/UDP**: Portlar, bayraklar, sequence numaraları.

**Temel TCP & UDP Analiz Ekranları:**
*   **Analyze > Follow > TCP Stream**: Bir TCP bağlantısının tüm içeriğini (ASCII/Hex) tek pencerede gösterir.
*   **Statistics > Conversations**: IP çiftleri arasındaki veri alışverişini özetler.

**Export Objects:**
*   **File > Export Objects > HTTP**: HTTP trafiği üzerinden indirilen dosyaları (resim, exe, html) dışarı aktarır.

**Basit Protokol Arama:**
Filtre çubuğuna sadece protokol adını yazın: \`dns\`, \`http\`, \`arp\`, \`icmp\`, \`ssh\`.

**Renk Kuralları (Coloring Rules):**
*   **Siyah arka plan / Kırmızı yazı**: Genellikle hatalı paketler (TCP Retransmission, Checksum Error).
*   **Yeşil**: HTTP trafiği.
*   **Mavi**: DNS trafiği.

**Name Resolution:**
IP adreslerini hostname'e çevirir. Performans için bazen kapatılması önerilir (\`View > Name Resolution\`).

**Timestamps ve Paket Zaman Analizi:**
*   **View > Time Display Format**: Zamanı "Capture Start"tan itibaren saniye olarak veya tarih/saat olarak gösterir.
*   **Delta Time**: Bir önceki paketten bu yana geçen süre (gecikme analizi için).

## 4. İleri Seviye Kullanım

### Display Filter Gelişmiş Kullanım
*   **Boolean Operatörler**: \`and (&&)\`, \`or (||)\`, \`xor (^^)\`, \`not (!)\`.
    *   Örn: \`http and ip.src == 192.168.1.5\`
*   **Field-based Filter**:
    *   \`tcp.flags.syn == 1\`: Sadece SYN paketleri.
    *   \`tls.handshake.type == 1\`: Client Hello.
*   **Regex Filtreleri**: \`http.host matches "google\\.(com|net)"\`
*   **Length/Size Bazlı**: \`frame.len > 1000\` (Büyük paketler).
*   **Layer-7 Filtreleme**: \`http.request.method == "POST"\`.
*   **Entropy Tespiti**: Şifreli veya sıkıştırılmış veriyi bulmak için veri rastgeleliğini analiz eder (Statistics menüsünde).

### Capture Filter Gelişmiş Kullanım (BPF)
*   **IP/Port/Protokol**: \`host 10.0.0.1 and port 80\`.
*   **VLAN**: \`vlan\`.
*   **MAC Adres**: \`ether host 00:11:22:33:44:55\`.
*   **Fragmented Packet**: \`ip[6:2] & 0x1fff != 0\`.
*   **SYN Scanning Tespiti**: \`tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0\`.
*   **Gateway Filtresi**: \`gateway host 192.168.1.1\`.

### SSL/TLS Analizi
*   **Handshake Analizi**: Server Hello, Certificate, Key Exchange adımlarını \`tls.handshake\` filtresiyle inceleyin.
*   **JA3 Fingerprinting**: İstemcinin TLS parametrelerine (cipher suites, extensions) göre parmak izini çıkarır (Malware tespiti için).
*   **Decryption**: Tarayıcıdan \`SSLKEYLOGFILE\` ortam değişkenini ayarlayıp Wireshark'a (Preferences > Protocols > TLS) ekleyerek HTTPS trafiğini çözebilirsiniz.
*   **DoH/DoT**: DNS over HTTPS/TLS trafiğini port 443 veya 853 üzerinde analiz edin.

### Wi-Fi Analizi
*   **Monitor Mode**: Wi-Fi kartının havada uçuşan tüm paketleri (sadece size gelenleri değil) yakalaması gerekir.
*   **EAPOL Handshake**: WPA/WPA2 şifresini kırmak için gereken 4-way handshake (\`eapol\`).
*   **Deauth Saldırısı**: \`wlan.fc.type_subtype == 0x0c\`.
*   **Beacon Frames**: SSID ve ağ özelliklerini yayınlayan paketler.

### VoIP / SIP / RTP Analizi
*   **SIP**: \`sip.Method == "INVITE"\` veya \`sip.Status-Code == 200\`.
*   **RTP Stream**: \`Telephony > RTP > Stream Analysis\` ile ses kalitesini (Jitter, Loss) ölçün ve sesi dinleyin (\`Play Streams\`).

### ICS/SCADA Protokol Analizi
*   **Modbus**: \`modbus.func_code\`.
*   **S7Comm**: Siemens PLC iletişimi.
*   **DNP3**: Enerji sektörü protokolü.
*   **Anomaly Detection**: Normal dışı function code'lar veya bilinmeyen IP'lerden gelen yazma komutları.

### Ağ Adli Analizi (Network Forensics)
*   **File Carving**: HTTP veya SMB üzerinden taşınan dosyaları \`Export Objects\` veya TCP stream'den \`Save as raw\` ile çıkarın.
*   **Malware C2**: Düzenli aralıklarla (beaconing) yapılan küçük HTTP/DNS isteklerini tespit edin.
*   **DNS Exfiltration**: \`dns.qry.name\` uzunluğu anormal olan veya hex-encoded subdomain'leri inceleyin.

### Performans ve Debugging
*   **TCP Retransmission**: \`tcp.analysis.retransmission\`. Ağda paket kaybı olduğunu gösterir.
*   **TCP Window Full**: Alıcının buffer'ı dolmuş, gönderimi yavaşlatıyor.
*   **Throughput**: \`Statistics > I/O Graphs\` ile bant genişliği kullanımını zaman çizelgesinde görün.

## 5. Açıklamalı Filtreler (GENİŞ LİSTE)

**Filtre:**
\`\`\`
ip.addr == 192.168.1.10 && tcp.flags.syn == 1 && tcp.flags.ack == 0
\`\`\`
**Açıklama:**
192.168.1.10 adresinden veya adresine giden TCP SYN paketlerini (bağlantı başlatma) gösterir.

**Filter Breakdown:**
*   **ip.addr**: Kaynak veya hedef IP.
*   **tcp.flags.syn == 1**: SYN bayrağı aktif.
*   **tcp.flags.ack == 0**: ACK bayrağı pasif (sadece SYN, SYN-ACK değil).

**IP / TCP / UDP:**
*   \`ip.src == x.x.x.x\`: Kaynak IP.
*   \`ip.dst == x.x.x.x\`: Hedef IP.
*   \`tcp.port == 80\`: TCP port 80.
*   \`udp.port == 53\`: UDP port 53.
*   \`tcp.analysis.retransmission\`: Tekrar gönderilen paketler.
*   \`tcp.analysis.lost_segment\`: Kayıp segmentler.

**DNS:**
*   \`dns.qry.name == "example.com"\`: Belirli bir domain sorgusu.
*   \`dns.flags.response == 1\`: DNS yanıtları.
*   \`dns.flags.rcode != 0\`: Hatalı DNS yanıtları (NXDOMAIN vs.).

**HTTP:**
*   \`http.request.method == "POST"\`: POST istekleri (veri gönderimi).
*   \`http.response.code == 404\`: Bulunamadı hataları.
*   \`http contains "password"\`: İçeriğinde "password" geçen paketler.
*   \`http.user_agent contains "Nmap"\`: Nmap taraması tespiti.

**TLS:**
*   \`tls.handshake.type == 1\`: Client Hello.
*   \`tls.handshake.ciphersuite\`: Kullanılan şifreleme algoritmaları.
*   \`tls.record.version == 0x0303\`: TLS 1.2.

**ARP:**
*   \`arp.opcode == 1\`: ARP Request (Kimde bu IP?).
*   \`arp.opcode == 2\`: ARP Reply (IP bende).
*   \`arp.src.hw_mac == 00:11:22:33:44:55\`: Belirli bir MAC adresinden gelen ARP'lar.

**ICMP:**
*   \`icmp.type == 8\`: Echo Request (Ping).
*   \`icmp.type == 0\`: Echo Reply (Pong).
*   \`icmp.type == 3\`: Destination Unreachable (Erişilemez).

**DHCP:**
*   \`bootp.option.type == 53\`: DHCP mesaj tipi.
*   \`bootp.hw.mac == ...\`: İstemci MAC adresi.

**Wi-Fi:**
*   \`wlan.fc.type_subtype == 0x08\`: Beacon frame.
*   \`wlan.fc.type_subtype == 0x0c\`: Deauthentication frame.
*   \`wlan.sa == ff:ff:ff:ff:ff:ff\`: Broadcast kaynaklı.

## 6. Gerçek Pentest Senaryoları + Filtreleri

**Port Scanning Tespiti:**
\`\`\`
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size <= 1024
\`\`\`
Kısa sürede çok sayıda farklı porta giden küçük pencereli SYN paketleri tarama işaretidir.

**SYN Flood Analizi:**
\`\`\`
tcp.flags.syn == 1 && tcp.analysis.retransmission
\`\`\`
Çok sayıda SYN gönderiliyor ancak ACK gelmediği için retransmission yapılıyorsa flood saldırısı olabilir.

**DNS Exfiltration Tespiti:**
\`\`\`
dns.qry.name.len > 50
\`\`\`
Çok uzun subdomain sorguları (örn: \`base64veri.hacker.com\`) veri kaçırma işaretidir.

**HTTP Credential Leak Analizi:**
\`\`\`
http.request.method == "POST" && (http contains "user" || http contains "pass")
\`\`\`
Cleartext HTTP üzerinden gönderilen kullanıcı adı ve şifreleri yakalar.

**Rogue DHCP Saldırısı Tespiti:**
\`\`\`
bootp.type == 2 && ip.src != 192.168.1.1
\`\`\`
Yetkili DHCP sunucusu (192.168.1.1) dışındaki bir IP'den gelen DHCP Offer/Ack paketlerini bulur.

**MITM (ARP Spoofing) Tespiti:**
\`\`\`
arp.duplicate-address-detected
\`\`\`
Aynı IP için farklı MAC adresleri görüldüğünde Wireshark bu uyarıyı verir.

**TLS Negotiation Failure:**
\`\`\`
tls.alert_message.level == 2
\`\`\`
Fatal TLS hatalarını (handshake başarısızlığı, sertifika hatası) gösterir.

**Malware C2 İletişimi:**
\`\`\`
http.request.uri matches "\\.(php|jsp|asp)$" && frame.len < 500
\`\`\`
Kısa aralıklarla belirli bir komuta dosyasına yapılan küçük istekler C2 heartbeat olabilir.

**ICMP Tunnel Tespiti:**
\`\`\`
icmp.type == 8 && data.len > 100
\`\`\`
Ping paketlerinin veri kısmı (payload) normalden büyükse içinde veri taşınıyor olabilir.

**IoT Cihaz Anomalisi:**
\`\`\`
mqtt || coap
\`\`\`
IoT protokollerini filtreleyip beklenmedik IP'lerle iletişimi kontrol edin.

**WPA/WPA2 Handshake Yakalama:**
\`\`\`
eapol
\`\`\`
Wi-Fi şifresini kırmak için gereken 4 paketlik el sıkışmayı gösterir.

## 8. Best Practices (Uzman Seviye)

*   **Capture vs Display Filter:** Mümkünse *Capture Filter* kullanın. Diske yazılan veri azaldıkça analiz hızlanır ve disk dolmaz.
*   **Snaplen Ayarı:** Sadece başlıkları (headers) inceleyecekseniz Snaplen'i (örn: 96 bytes) düşürün. Dosya boyutu çok azalır.
*   **Name Resolution:** DNS çözümlemeyi kapatın. Wireshark her IP için DNS sorgusu yaparsa analiz yavaşlar ve ağda gürültü oluşturur.
*   **Ring Buffer:** Uzun süreli yakalamalarda "Multiple Files" ve "Ring Buffer" kullanın (örn: her biri 100MB olan 10 dosya, eskiler silinir).
*   **Coloring Rules:** Kendi renk kurallarınızı oluşturun (örn: SYN paketleri turuncu, RST paketleri kırmızı).
*   **TLS Decryption:** Sunucu private key'ine sahipseniz Wireshark'a yükleyerek trafiği açabilirsiniz.
*   **Tshark:** GUI (Wireshark) yavaşladığında veya otomasyon için komut satırı versiyonu \`tshark\` kullanın.

## 9. Sık Yapılan Hatalar

*   **Capture Filter Yerine Display Filter Yazmak:** Capture filter BPF formatındadır (\`host 1.1.1.1\`), Display filter Wireshark formatındadır (\`ip.addr == 1.1.1.1\`). Karıştırmak hata verir.
*   **Snaplen Küçük Bırakmak:** Payload analizi yapacaksanız (HTTP body, SMB file) snaplen'i sınırlamayın, veri kesilir.
*   **Monitor Mode Açmamak:** Wi-Fi analizinde monitor mode yoksa sadece kendi trafiğinizi görürsünüz.
*   **DNS Resolution Açık Bırakmak:** Binlerce paket için DNS sorgusu yapmak Wireshark'ı kilitler.
*   **Timezone Farkları:** Logları sunucu loglarıyla karşılaştırırken saat dilimi farkına (UTC vs Local) dikkat edin.
*   **TCP Reassembly Kapalı:** HTTP gibi protokolleri analiz ederken TCP Reassembly açık olmalıdır, yoksa stream bütünlüğü bozulur.
*   **VLAN Tagged Paketleri Kaçırmak:** Bazı kartlar VLAN etiketlerini siler (strip). Driver ayarlarını kontrol edin.
*   **Only-TCP:** \`tcp\` filtresi uygularsanız UDP (DNS, DHCP) trafiğini kaçırırsınız ve sorunun kök nedenini bulamayabilirsiniz.
`;

const contentEN = `# Wireshark - Network Protocol Analyzer

## 3. Basic Usage

**Display Filter Logic:**
Allows you to see only the packets you are interested in among captured packets. Typed in the search bar (e.g., \`ip.addr == 192.168.1.1\`).

**Capture Filter Logic:**
Ensures only packets matching specific criteria are saved to disk. Used to reduce traffic volume (BPF syntax: \`host 192.168.1.1\`).

**Interface Selection:**
Select the network card where traffic flows (Wi-Fi, Ethernet, Loopback) on the start screen. The wavy line indicates traffic presence.

**Pcap Open/Save:**
*   **File > Open**: Opens an existing .pcap/.pcapng file.
*   **File > Save As**: Saves the analyzed packets.

**Packet Details Pane:**
*   **Frame**: Physical layer and timing info.
*   **Ethernet**: MAC addresses.
*   **IP**: Source/Dest IP, TTL.
*   **TCP/UDP**: Ports, flags, sequence numbers.

**Basic TCP & UDP Analysis Screens:**
*   **Analyze > Follow > TCP Stream**: Shows the entire content (ASCII/Hex) of a TCP connection in a single window.
*   **Statistics > Conversations**: Summarizes data exchange between IP pairs.

**Export Objects:**
*   **File > Export Objects > HTTP**: Exports files (images, exe, html) downloaded via HTTP traffic.

**Basic Protocol Search:**
Type protocol name in filter bar: \`dns\`, \`http\`, \`arp\`, \`icmp\`, \`ssh\`.

**Coloring Rules:**
*   **Black background / Red text**: Usually malformed packets (TCP Retransmission, Checksum Error).
*   **Green**: HTTP traffic.
*   **Blue**: DNS traffic.

**Name Resolution:**
Resolves IP addresses to hostnames. Recommended to turn off for performance (\`View > Name Resolution\`).

**Timestamps and Packet Time Analysis:**
*   **View > Time Display Format**: Shows time as seconds since "Capture Start" or as date/time.
*   **Delta Time**: Time elapsed since the previous packet (for latency analysis).

## 4. Advanced Usage

### Advanced Display Filters
*   **Boolean Operators**: \`and (&&)\`, \`or (||)\`, \`xor (^^)\`, \`not (!)\`.
    *   Ex: \`http and ip.src == 192.168.1.5\`
*   **Field-based Filter**:
    *   \`tcp.flags.syn == 1\`: Only SYN packets.
    *   \`tls.handshake.type == 1\`: Client Hello.
*   **Regex Filters**: \`http.host matches "google\\.(com|net)"\`
*   **Length/Size Based**: \`frame.len > 1000\` (Large packets).
*   **Layer-7 Filtering**: \`http.request.method == "POST"\`.
*   **Entropy Detection**: Analyzes data randomness to find encrypted or compressed data (in Statistics menu).

### Advanced Capture Filters (BPF)
*   **IP/Port/Protocol**: \`host 10.0.0.1 and port 80\`.
*   **VLAN**: \`vlan\`.
*   **MAC Address**: \`ether host 00:11:22:33:44:55\`.
*   **Fragmented Packet**: \`ip[6:2] & 0x1fff != 0\`.
*   **SYN Scanning Detection**: \`tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0\`.
*   **Gateway Filter**: \`gateway host 192.168.1.1\`.

### SSL/TLS Analysis
*   **Handshake Analysis**: Inspect Server Hello, Certificate, Key Exchange steps with \`tls.handshake\` filter.
*   **JA3 Fingerprinting**: Fingerprints client based on TLS parameters (cipher suites, extensions) (for Malware detection).
*   **Decryption**: Decrypt HTTPS traffic by setting \`SSLKEYLOGFILE\` env variable from browser and adding to Wireshark (Preferences > Protocols > TLS).
*   **DoH/DoT**: Analyze DNS over HTTPS/TLS traffic on port 443 or 853.

### Wi-Fi Analysis
*   **Monitor Mode**: Wi-Fi card must capture all airborne packets (not just those for you).
*   **EAPOL Handshake**: 4-way handshake required to crack WPA/WPA2 password (\`eapol\`).
*   **Deauth Attack**: \`wlan.fc.type_subtype == 0x0c\`.
*   **Beacon Frames**: Packets broadcasting SSID and network properties.

### VoIP / SIP / RTP Analysis
*   **SIP**: \`sip.Method == "INVITE"\` or \`sip.Status-Code == 200\`.
*   **RTP Stream**: Measure voice quality (Jitter, Loss) and listen to audio with \`Telephony > RTP > Stream Analysis\` (\`Play Streams\`).

### ICS/SCADA Protocol Analysis
*   **Modbus**: \`modbus.func_code\`.
*   **S7Comm**: Siemens PLC communication.
*   **DNP3**: Energy sector protocol.
*   **Anomaly Detection**: Abnormal function codes or write commands from unknown IPs.

### Network Forensics
*   **File Carving**: Extract files transferred over HTTP or SMB via \`Export Objects\` or \`Save as raw\` from TCP stream.
*   **Malware C2**: Detect small HTTP/DNS requests made at regular intervals (beaconing).
*   **DNS Exfiltration**: Inspect \`dns.qry.name\` for abnormal lengths or hex-encoded subdomains.

### Performance and Debugging
*   **TCP Retransmission**: \`tcp.analysis.retransmission\`. Indicates packet loss on the network.
*   **TCP Window Full**: Receiver buffer is full, slowing down transmission.
*   **Throughput**: See bandwidth usage on timeline with \`Statistics > I/O Graphs\`.

## 5. Annotated Filters (EXTENDED LIST)

**Filter:**
\`\`\`
ip.addr == 192.168.1.10 && tcp.flags.syn == 1 && tcp.flags.ack == 0
\`\`\`
**Description:**
Shows TCP SYN packets (connection initiation) coming from or going to 192.168.1.10.

**Filter Breakdown:**
*   **ip.addr**: Source or destination IP.
*   **tcp.flags.syn == 1**: SYN flag active.
*   **tcp.flags.ack == 0**: ACK flag passive (SYN only, not SYN-ACK).

**IP / TCP / UDP:**
*   \`ip.src == x.x.x.x\`: Source IP.
*   \`ip.dst == x.x.x.x\`: Destination IP.
*   \`tcp.port == 80\`: TCP port 80.
*   \`udp.port == 53\`: UDP port 53.
*   \`tcp.analysis.retransmission\`: Retransmitted packets.
*   \`tcp.analysis.lost_segment\`: Lost segments.

**DNS:**
*   \`dns.qry.name == "example.com"\`: Specific domain query.
*   \`dns.flags.response == 1\`: DNS responses.
*   \`dns.flags.rcode != 0\`: Erroneous DNS responses (NXDOMAIN etc.).

**HTTP:**
*   \`http.request.method == "POST"\`: POST requests (data submission).
*   \`http.response.code == 404\`: Not Found errors.
*   \`http contains "password"\`: Packets containing "password".
*   \`http.user_agent contains "Nmap"\`: Nmap scan detection.

**TLS:**
*   \`tls.handshake.type == 1\`: Client Hello.
*   \`tls.handshake.ciphersuite\`: Used encryption algorithms.
*   \`tls.record.version == 0x0303\`: TLS 1.2.

**ARP:**
*   \`arp.opcode == 1\`: ARP Request (Who has this IP?).
*   \`arp.opcode == 2\`: ARP Reply (I have this IP).
*   \`arp.src.hw_mac == 00:11:22:33:44:55\`: ARPs from specific MAC.

**ICMP:**
*   \`icmp.type == 8\`: Echo Request (Ping).
*   \`icmp.type == 0\`: Echo Reply (Pong).
*   \`icmp.type == 3\`: Destination Unreachable.

**DHCP:**
*   \`bootp.option.type == 53\`: DHCP message type.
*   \`bootp.hw.mac == ...\`: Client MAC address.

**Wi-Fi:**
*   \`wlan.fc.type_subtype == 0x08\`: Beacon frame.
*   \`wlan.fc.type_subtype == 0x0c\`: Deauthentication frame.
*   \`wlan.sa == ff:ff:ff:ff:ff:ff\`: Broadcast source.

## 6. Real Pentest Scenarios + Filters

**Port Scanning Detection:**
\`\`\`
tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size <= 1024
\`\`\`
Small window SYN packets to many different ports in short time indicate scanning.

**SYN Flood Analysis:**
\`\`\`
tcp.flags.syn == 1 && tcp.analysis.retransmission
\`\`\`
If many SYNs are sent but retransmitted due to no ACK, it might be a flood attack.

**DNS Exfiltration Detection:**
\`\`\`
dns.qry.name.len > 50
\`\`\`
Very long subdomain queries (e.g., \`base64data.hacker.com\`) indicate data exfiltration.

**HTTP Credential Leak Analysis:**
\`\`\`
http.request.method == "POST" && (http contains "user" || http contains "pass")
\`\`\`
Captures usernames and passwords sent over cleartext HTTP.

**Rogue DHCP Attack Detection:**
\`\`\`
bootp.type == 2 && ip.src != 192.168.1.1
\`\`\`
Finds DHCP Offer/Ack packets coming from an IP other than the authorized DHCP server (192.168.1.1).

**MITM (ARP Spoofing) Detection:**
\`\`\`
arp.duplicate-address-detected
\`\`\`
Wireshark warns when different MAC addresses are seen for the same IP.

**TLS Negotiation Failure:**
\`\`\`
tls.alert_message.level == 2
\`\`\`
Shows fatal TLS errors (handshake failure, certificate error).

**Malware C2 Communication:**
\`\`\`
http.request.uri matches "\\.(php|jsp|asp)$" && frame.len < 500
\`\`\`
Small requests to specific script files at regular intervals might be C2 heartbeat.

**ICMP Tunnel Detection:**
\`\`\`
icmp.type == 8 && data.len > 100
\`\`\`
If Ping packet payload is larger than normal, it might be carrying data.

**IoT Device Anomaly:**
\`\`\`
mqtt || coap
\`\`\`
Filter IoT protocols and check for communication with unexpected IPs.

**WPA/WPA2 Handshake Capture:**
\`\`\`
eapol
\`\`\`
Shows the 4-packet handshake required to crack Wi-Fi password.

## 8. Best Practices (Expert Level)

*   **Capture vs Display Filter:** Use *Capture Filter* if possible. Reducing data written to disk speeds up analysis and saves space.
*   **Snaplen Setting:** If only analyzing headers, reduce Snaplen (e.g., 96 bytes). Drastically reduces file size.
*   **Name Resolution:** Turn off DNS resolution. Wireshark querying DNS for every IP slows down analysis and creates network noise.
*   **Ring Buffer:** Use "Multiple Files" and "Ring Buffer" for long-term captures (e.g., 10 files of 100MB each, oldest deleted).
*   **Coloring Rules:** Create your own coloring rules (e.g., Orange for SYN, Red for RST).
*   **TLS Decryption:** If you have the server private key, load it into Wireshark to decrypt traffic.
*   **Tshark:** Use command-line version \`tshark\` when GUI (Wireshark) is too slow or for automation.

## 9. Common Mistakes

*   **Confusing Capture vs Display Filter:** Capture filter uses BPF (\`host 1.1.1.1\`), Display filter uses Wireshark syntax (\`ip.addr == 1.1.1.1\`). Mixing them causes errors.
*   **Leaving Snaplen Small:** If analyzing payload (HTTP body, SMB file), don't limit snaplen, data will be truncated.
*   **Not Using Monitor Mode:** Without monitor mode in Wi-Fi analysis, you only see your own traffic.
*   **Leaving DNS Resolution On:** Performing DNS lookups for thousands of packets locks up Wireshark.
*   **Timezone Differences:** Be aware of time zone differences (UTC vs Local) when comparing logs with server logs.
*   **TCP Reassembly Off:** TCP Reassembly must be on when analyzing protocols like HTTP, otherwise stream integrity is lost.
*   **Missing VLAN Tagged Packets:** Some cards strip VLAN tags. Check driver settings.
*   **Only-TCP:** If you apply \`tcp\` filter, you miss UDP (DNS, DHCP) traffic and might miss the root cause.
`;

async function addWireshark() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Wireshark cheatsheet...');

        // 1. Find or create the category
        let category = await Category.findOne({ 'name.en': 'Traffic Analysis' });
        if (!category) {
            console.log('Category "Traffic Analysis" not found, creating...');
            category = await Category.create({
                name: { tr: 'Trafik Analizi', en: 'Traffic Analysis' },
                description: { tr: 'Ağ trafiği ve paket analizi araçları', en: 'Network traffic and packet analysis tools' },
                slug: 'traffic-analysis',
                icon: 'Activity'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Wireshark Cheat Sheet',
                en: 'Wireshark Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['wireshark', 'network', 'analysis', 'packet', 'pcap', 'forensics']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Wireshark Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Wireshark cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addWireshark();
