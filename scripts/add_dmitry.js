import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const cheatsheetsPath = path.join(__dirname, '..', 'mdb', 'cheatsheets.json');

const trDescription = `# DMitry (Deepmagic Information Gathering Tool)

## 1. Açıklama
DMitry, UNIX/(GNU)Linux tabanlı sistemler için C ile yazılmış bir **Information Gathering** aracıdır. **OSINT**, **Passive Recon** ve **Active Recon** süreçlerinde hibrit bir rol oynar. Özellikle hedef hakkında hızlıca **subdomain discovery**, **email enumeration** ve **port scanning** yapmak istendiğinde tercih edilir. Hafif ve hızlı olması, **initial footprinting** aşamasında onu değerli kılar.

## 2. Temel Komutlar ve Parametre Açıklamaları

### Netcraft Araması
\`\`\`bash
dmitry -n target.com
\`\`\`
*   \`-n\`: Hedef domain için **Netcraft.com** üzerinde arama yapar. Host bilgileri ve işletim sistemi geçmişi gibi verileri toplar.

### Whois Sorgusu
\`\`\`bash
dmitry -w target.com
\`\`\`
*   \`-w\`: Hedef domainin **Whois** kaydını sorgular. Registrar, admin contact ve name server bilgilerini getirir.

### Subdomain Discovery
\`\`\`bash
dmitry -s target.com
\`\`\`
*   \`-s\`: Arama motorlarını ve pasif kaynakları kullanarak **subdomain enumeration** yapar.

### Email Address Enumeration
\`\`\`bash
dmitry -e target.com
\`\`\`
*   \`-e\`: Hedef domain ile ilişkili e-posta adreslerini arar (**Email harvesting**).

### TCP Port Scanning
\`\`\`bash
dmitry -p target.com
\`\`\`
*   \`-p\`: Hedef üzerinde **TCP port scanning** yapar. Açık portları listeler.

### Banner Grabbing
\`\`\`bash
dmitry -b target.com
\`\`\`
*   \`-b\`: Açık portlardan **banner grabbing** yaparak servis versiyonlarını ve işletim sistemi ipuçlarını toplar.

### Raporlama
\`\`\`bash
dmitry -d -o report.txt target.com
\`\`\`
*   \`-d\`: Toplanan tüm bilgileri belirtilen çıktı dosyasına yazar.
*   \`-o <file>\`: Çıktının kaydedileceği dosya adını belirler.

### Hedef Belirtme
\`\`\`bash
dmitry -i 192.168.1.1
\`\`\`
*   \`-i <IP/domain>\`: Hedef IP adresi veya domain. Genellikle komutun sonunda parametresiz olarak da verilebilir.

### Diğer
*   \`-v\`: **Verbose** mod. İşlem detaylarını ekrana basar.
*   \`--no-color\`: Renkli çıktıyı kapatır (loglama için uygundur).

## 3. Temel Kullanım

### Passive Recon
Hedefe temas etmeden bilgi toplama.
\`\`\`bash
dmitry -n -w -s -e target.com
\`\`\`

### Whois Lookup
Domain sahiplik bilgilerini sorgulama.
\`\`\`bash
dmitry -w target.com
\`\`\`

### Netcraft-based Info Gathering
Netcraft veritabanından host geçmişi çekme.
\`\`\`bash
dmitry -n target.com
\`\`\`

### Subdomain Enumeration
Alt alan adlarını pasif olarak listeleme.
\`\`\`bash
dmitry -s target.com
\`\`\`

### Email Enumeration
Kurumsal e-posta adreslerini tespit etme.
\`\`\`bash
dmitry -e target.com
\`\`\`

### Basic Port Scan
En çok kullanılan 150 portu tarama.
\`\`\`bash
dmitry -p target.com
\`\`\`

### Banner Grabbing
Servis versiyonlarını tespit etme.
\`\`\`bash
dmitry -p -b target.com
\`\`\`

### Combined Scans
Tüm modülleri aynı anda çalıştırma.
\`\`\`bash
dmitry -winsepfb target.com
\`\`\`

### Output Report Oluşturma
Sonuçları dosyaya kaydetme.
\`\`\`bash
dmitry -winsepfb -o results.txt target.com
\`\`\`

## 4. İleri Seviye Kullanım

### Passive Fingerprinting Metodolojisi
DMitry'nin \`-n\` (Netcraft) ve \`-w\` (Whois) modülleri, hedefe paket göndermeden **passive fingerprinting** yapar. Bu, **IDS/IPS** sistemlerini tetiklemeden hedef altyapısı hakkında bilgi (OS, Hosting Provider, IP range) toplamak için kritiktir.

### DNS-based Attack Surface Mapping
\`-s\` parametresi ile elde edilen subdomain listesi, saldırı yüzeyini (**attack surface**) haritalandırmak için kullanılır. Bulunan her subdomain, potansiyel bir giriş noktasıdır (örn: \`dev.target.com\`, \`vpn.target.com\`).

### Subdomain Discovery Techniques
DMitry, **passive** yöntemler kullanır (arama motorları, Netcraft). **Brute-force** yapmaz. Bu nedenle, \`sublist3r\` veya \`amass\` gibi araçlarla kombine edilerek **dictionary-based** taramalarla desteklenmelidir.

### Email Pattern Extraction
\`-e\` ile bulunan e-postalar (örn: \`isim.soyisim@target.com\`), kurumun e-posta isimlendirme standardını (**naming convention**) ortaya çıkarır. Bu, **password spraying** veya **phishing** senaryoları için temel oluşturur.

### Banner Fingerprinting
\`-b\` parametresi, servisin döndürdüğü "hoşgeldin" mesajını yakalar. Bu banner, servisin tam sürümünü (örn: \`Apache/2.4.41\`) ifşa edebilir. Ancak, adminler banner'ı değiştirebileceği için (**false banner**), bu bilgi her zaman %100 güvenilir değildir.

### Port Scanning Limitasyonları
DMitry'nin port tarayıcısı (\`-p\`), **Nmap** kadar gelişmiş değildir. Sadece TCP connect scan yapar ve sınırlı sayıda portu tarar. **Stealth scan** (SYN scan) veya **UDP scan** yapmaz. Hızlı bir ön bakış için uygundur.

### Response Signature Analysis
Netcraft sorgusu (\`-n\`), hedefin web sunucusu ve işletim sistemi değişim geçmişini gösterir. Bu, hedefin **patch management** sıklığı ve altyapı değişiklikleri hakkında **intelligence** sağlar.

### CDN Önünde Bilgi Toplama Limitasyonları
Hedef **Cloudflare** veya benzeri bir **CDN** arkasındaysa, \`-p\` taraması CDN'in portlarını gösterecektir. Ancak \`-s\` (subdomain) ve \`-e\` (email) modülleri CDN'den etkilenmez ve gerçek hedefe dair izler taşıyabilir.

### Hidden Infrastructure Enumeration
Whois verisindeki "Technical Contact" veya "Name Server" bilgileri, hedefin kullandığı hosting sağlayıcısını veya gizli yan kuruluşlarını ifşa edebilir.

### Reverse IP Lookup Mantığı
DMitry doğrudan reverse IP yapmasa da, Netcraft sonuçları aynı IP'de barınan diğer domainleri (virtual hosts) gösterebilir. Bu, **shared hosting** ortamlarında komşu sitelerden sızma (**lateral movement**) potansiyelini gösterir.

### Baseline Fingerprinting
Pentest'in başında DMitry ile alınan tam çıktı (\`-winsepfb\`), hedefin o anki durumunun bir **snapshot**'ıdır (baseline). İlerleyen aşamalarda yapılan değişiklikleri karşılaştırmak için referans noktası olur.

### OSINT -> Active Recon Geçiş Mantığı
Süreç \`-winse\` (Passive) ile başlar. Elde edilen veriler (IP'ler, subdomainler) doğrulandıktan sonra \`-p\` ve \`-b\` (Active) aşamasına geçilir. Bu, erken fark edilme riskini azaltır.

### Firewall / IDS Altında DMitry Davranışı
\`-p\` modülü tam TCP bağlantısı kurduğu için (3-way handshake), **Firewall** ve **IDS** loglarında çok gürültülüdür. **Stealth** gerektiren durumlarda sadece pasif modüller (\`-winse\`) kullanılmalıdır.

### Rate Limiting Etkisi
DMitry'nin hız kontrolü (timing template) yoktur. Çok hızlı tarama yaparsa hedef WAF veya arama motorları tarafından **IP ban** yiyebilir.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar
\`\`\`bash
dmitry -n target.com
\`\`\`
*   **Açıklama**: Sadece Netcraft sorgusu yapar.
*   **Argümanlar**: \`-n\` (Netcraft lookup).

\`\`\`bash
dmitry -w target.com
\`\`\`
*   **Açıklama**: Sadece Whois sorgusu yapar.
*   **Argümanlar**: \`-w\` (Whois lookup).

\`\`\`bash
dmitry -s target.com
\`\`\`
*   **Açıklama**: Sadece subdomain araması yapar.
*   **Argümanlar**: \`-s\` (Subdomain search).

\`\`\`bash
dmitry -e target.com
\`\`\`
*   **Açıklama**: Sadece e-posta adresi toplar.
*   **Argümanlar**: \`-e\` (Email search).

\`\`\`bash
dmitry -p target.com
\`\`\`
*   **Açıklama**: Sadece TCP port taraması yapar.
*   **Argümanlar**: \`-p\` (TCP Port scan).

\`\`\`bash
dmitry -b target.com
\`\`\`
*   **Açıklama**: Sadece banner grabbing yapar (Genellikle -p ile kullanılır).
*   **Argümanlar**: \`-b\` (Read banners).

### Network / Scanning
\`\`\`bash
dmitry -p -b target.com
\`\`\`
*   **Açıklama**: Port taraması yapar ve bulunan portlardan banner bilgisi çeker.
*   **Argümanlar**: \`-p\` (Port scan), \`-b\` (Banner grab).

\`\`\`bash
dmitry -p -v target.com
\`\`\`
*   **Açıklama**: Port taramasını detaylı (verbose) modda yapar.
*   **Argümanlar**: \`-p\` (Port scan), \`-v\` (Verbose).

### OSINT & Enumeration
\`\`\`bash
dmitry -n -w target.com
\`\`\`
*   **Açıklama**: Netcraft ve Whois bilgilerini birlikte getirir.
*   **Argümanlar**: \`-n\` (Netcraft), \`-w\` (Whois).

\`\`\`bash
dmitry -s -e target.com
\`\`\`
*   **Açıklama**: Subdomain ve e-posta adreslerini toplar.
*   **Argümanlar**: \`-s\` (Subdomains), \`-e\` (Emails).

\`\`\`bash
dmitry -winse target.com
\`\`\`
*   **Açıklama**: Tam pasif tarama (Whois, IP, Netcraft, Subdomain, Email). Hedefe paket göndermez (IP lookup hariç).
*   **Argümanlar**: \`-w\`, \`-i\` (IP lookup), \`-n\`, \`-s\`, \`-e\`.

### Output
\`\`\`bash
dmitry -winsepfb -o full_scan.txt target.com
\`\`\`
*   **Açıklama**: Tüm modülleri çalıştırır ve sonucu \`full_scan.txt\` dosyasına yazar.
*   **Argümanlar**: \`-winsepfb\` (All flags), \`-o\` (Output file).

## 6. Gerçek Pentest Senaryoları

### CDN Arkasında Temel OSINT Toplama
Hedef Cloudflare arkasındaysa, port taraması yanıltıcı olur. Sadece pasif bilgi toplanmalıdır.
\`\`\`bash
dmitry -n -w -s -e target.com
\`\`\`
*   **Argümanlar**: \`-n\` (Netcraft), \`-w\` (Whois), \`-s\` (Subdomain), \`-e\` (Email). Aktif tarama (\`-p\`) kapalı.

### Passive Recon ile "Zero-Touch Footprinting"
Hedef sistemde hiç log oluşturmadan bilgi toplama.
\`\`\`bash
dmitry -n -w -s target.com
\`\`\`
*   **Argümanlar**: \`-n\`, \`-w\`, \`-s\`. Bu sorgular 3. parti servislere yapılır, hedefe gitmez.

### Email Pattern Extraction (Kurumsal Yapılar)
Sosyal mühendislik veya brute-force listesi hazırlamak için e-posta formatını belirleme.
\`\`\`bash
dmitry -e target.com
\`\`\`
*   **Argümanlar**: \`-e\`. Çıktıdaki e-postalar analiz edilerek (örn: \`ad.soyad@\`) wordlist oluşturulur.

### Multi-stage Bilgi Toplama
Önce pasif tarama ile hedefleri belirleyip, sonra seçilenlere aktif tarama yapma.
1. Aşama (Pasif):
\`\`\`bash
dmitry -s -o subs.txt target.com
\`\`\`
2. Aşama (Aktif - Bulunan subdomain için):
\`\`\`bash
dmitry -p -b -i sub.target.com
\`\`\`

### Banner Fingerprinting ile Legacy Service Tespiti
Eski ve savunmasız servisleri banner bilgilerinden yakalama.
\`\`\`bash
dmitry -p -b target.com
\`\`\`
*   **Argümanlar**: \`-p\`, \`-b\`. Çıktıda \`IIS 6.0\` veya \`Apache 2.2\` gibi eski sürümler aranır.

## 7. Best Practices (Uzman Seviye)
*   **Passive First**: Her zaman \`-winse\` (pasif) modları ile başlayın, sonra \`-p\` (aktif) moduna geçin.
*   **Verify Subdomains**: \`-s\` çıktısını \`Sublist3r\` veya \`Amass\` sonuçlarıyla çapraz doğrulayın.
*   **Save Output**: Her zaman \`-o\` parametresini kullanın. Terminal çıktısı kaybolabilir.
*   **False Banners**: \`-b\` ile gelen banner bilgisine körü körüne güvenmeyin, \`Nmap -sV\` ile doğrulayın.
*   **CDN Awareness**: Hedef IP'nin bir CDN'e ait olup olmadığını Whois (\`-w\`) ile kontrol edin.
*   **Legal Compliance**: \`-p\` ve \`-b\` aktif tarama yapar ve izinsiz yapılması suç teşkil edebilir.

## 8. Sık Yapılan Hatalar
*   **Tek Flag Kullanımı**: Sadece \`dmitry target.com\` yazmak (parametresiz) çok sınırlı bilgi verir.
*   **No Output File**: Uzun taramaları \`-o\` olmadan yapmak ve veriyi kaybetmek.
*   **Trusting Port Scan**: DMitry'nin basit port tarayıcısını Nmap'in yerini tutacak sanmak.
*   **Ignoring Verbose**: Hata ayıklama veya detay görme gerektiğinde \`-v\` kullanmamak.
*   **Scanning CDN**: Cloudflare IP'sine port taraması yapıp "açık port buldum" diye sevinmek.
`;

const enDescription = `# DMitry (Deepmagic Information Gathering Tool)

## 1. Description
DMitry is an **Information Gathering** tool written in C for UNIX/(GNU)Linux systems. It plays a hybrid role in **OSINT**, **Passive Recon**, and **Active Recon** processes. It is preferred for quick **subdomain discovery**, **email enumeration**, and **port scanning** on a target. Its lightweight and fast nature makes it valuable during the **initial footprinting** phase.

## 2. Basic Commands and Parameter Explanations

### Netcraft Search
\`\`\`bash
dmitry -n target.com
\`\`\`
*   \`-n\`: Performs a search on **Netcraft.com** for the target domain. Retrieves host information and operating system history.

### Whois Lookup
\`\`\`bash
dmitry -w target.com
\`\`\`
*   \`-w\`: Queries the **Whois** record of the target domain. Retrieves registrar, admin contact, and name server information.

### Subdomain Discovery
\`\`\`bash
dmitry -s target.com
\`\`\`
*   \`-s\`: Performs **subdomain enumeration** using search engines and passive sources.

### Email Address Enumeration
\`\`\`bash
dmitry -e target.com
\`\`\`
*   \`-e\`: Searches for email addresses associated with the target domain (**Email harvesting**).

### TCP Port Scanning
\`\`\`bash
dmitry -p target.com
\`\`\`
*   \`-p\`: Performs **TCP port scanning** on the target. Lists open ports.

### Banner Grabbing
\`\`\`bash
dmitry -b target.com
\`\`\`
*   \`-b\`: Performs **banner grabbing** from open ports to gather service versions and OS clues.

### Reporting
\`\`\`bash
dmitry -d -o report.txt target.com
\`\`\`
*   \`-d\`: Writes all collected information to the specified output file.
*   \`-o <file>\`: Specifies the name of the output file.

### Specifying Target
\`\`\`bash
dmitry -i 192.168.1.1
\`\`\`
*   \`-i <IP/domain>\`: Target IP address or domain. Usually can be given at the end of the command without a parameter.

### Other
*   \`-v\`: **Verbose** mode. Prints operation details to the screen.
*   \`--no-color\`: Disables colored output (suitable for logging).

## 3. Basic Usage

### Passive Recon
Gathering information without touching the target.
\`\`\`bash
dmitry -n -w -s -e target.com
\`\`\`

### Whois Lookup
Querying domain ownership information.
\`\`\`bash
dmitry -w target.com
\`\`\`

### Netcraft-based Info Gathering
Fetching host history from Netcraft database.
\`\`\`bash
dmitry -n target.com
\`\`\`

### Subdomain Enumeration
Passively listing subdomains.
\`\`\`bash
dmitry -s target.com
\`\`\`

### Email Enumeration
Detecting corporate email addresses.
\`\`\`bash
dmitry -e target.com
\`\`\`

### Basic Port Scan
Scanning the most common 150 ports.
\`\`\`bash
dmitry -p target.com
\`\`\`

### Banner Grabbing
Detecting service versions.
\`\`\`bash
dmitry -p -b target.com
\`\`\`

### Combined Scans
Running all modules simultaneously.
\`\`\`bash
dmitry -winsepfb target.com
\`\`\`

### Creating Output Report
Saving results to a file.
\`\`\`bash
dmitry -winsepfb -o results.txt target.com
\`\`\`

## 4. Advanced Usage

### Passive Fingerprinting Methodology
DMitry's \`-n\` (Netcraft) and \`-w\` (Whois) modules perform **passive fingerprinting** without sending packets to the target. This is critical for gathering infrastructure info (OS, Hosting Provider, IP range) without triggering **IDS/IPS** systems.

### DNS-based Attack Surface Mapping
The subdomain list obtained with \`-s\` is used to map the **attack surface**. Each found subdomain is a potential entry point (e.g., \`dev.target.com\`, \`vpn.target.com\`).

### Subdomain Discovery Techniques
DMitry uses **passive** methods (search engines, Netcraft). It does not perform **brute-force**. Therefore, it should be supported by **dictionary-based** scans using tools like \`sublist3r\` or \`amass\`.

### Email Pattern Extraction
Emails found with \`-e\` (e.g., \`firstname.lastname@target.com\`) reveal the organization's **naming convention**. This forms the basis for **password spraying** or **phishing** scenarios.

### Banner Fingerprinting
The \`-b\` parameter captures the "welcome" message returned by the service. This banner can reveal the exact version (e.g., \`Apache/2.4.41\`). However, since admins can change the banner (**false banner**), this info is not always 100% reliable.

### Port Scanning Limitations
DMitry's port scanner (\`-p\`) is not as advanced as **Nmap**. It only performs TCP connect scans and scans a limited number of ports. It does not perform **Stealth scan** (SYN scan) or **UDP scan**. Suitable for a quick preview.

### Response Signature Analysis
Netcraft query (\`-n\`) shows the target's web server and OS change history. This provides **intelligence** on the target's **patch management** frequency and infrastructure changes.

### Limitations of Gathering Info Behind CDN
If the target is behind **Cloudflare** or a similar **CDN**, the \`-p\` scan will show the CDN's ports. However, \`-s\` (subdomain) and \`-e\` (email) modules are unaffected by CDN and may carry traces of the real target.

### Hidden Infrastructure Enumeration
"Technical Contact" or "Name Server" info in Whois data can reveal the hosting provider or hidden subsidiaries used by the target.

### Reverse IP Lookup Logic
Although DMitry does not do direct reverse IP, Netcraft results can show other domains hosted on the same IP (virtual hosts). This indicates **lateral movement** potential from neighboring sites in **shared hosting** environments.

### Baseline Fingerprinting
The full output taken with DMitry at the beginning of a pentest (\`-winsepfb\`) is a **snapshot** (baseline) of the target's current state. It serves as a reference point for comparing changes made in later stages.

### OSINT -> Active Recon Transition Logic
The process starts with \`-winse\` (Passive). After verifying obtained data (IPs, subdomains), the process moves to \`-p\` and \`-b\` (Active). This reduces the risk of early detection.

### DMitry Behavior Under Firewall / IDS
Since the \`-p\` module establishes a full TCP connection (3-way handshake), it is very noisy in **Firewall** and **IDS** logs. In situations requiring **Stealth**, only passive modules (\`-winse\`) should be used.

### Rate Limiting Impact
DMitry has no speed control (timing template). If it scans too fast, the target WAF or search engines may **IP ban** it.

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments
\`\`\`bash
dmitry -n target.com
\`\`\`
*   **Description**: Performs only Netcraft query.
*   **Arguments**: \`-n\` (Netcraft lookup).

\`\`\`bash
dmitry -w target.com
\`\`\`
*   **Description**: Performs only Whois query.
*   **Arguments**: \`-w\` (Whois lookup).

\`\`\`bash
dmitry -s target.com
\`\`\`
*   **Description**: Performs only subdomain search.
*   **Arguments**: \`-s\` (Subdomain search).

\`\`\`bash
dmitry -e target.com
\`\`\`
*   **Description**: Collects only email addresses.
*   **Arguments**: \`-e\` (Email search).

\`\`\`bash
dmitry -p target.com
\`\`\`
*   **Description**: Performs only TCP port scan.
*   **Arguments**: \`-p\` (TCP Port scan).

\`\`\`bash
dmitry -b target.com
\`\`\`
*   **Description**: Performs only banner grabbing (Usually used with -p).
*   **Arguments**: \`-b\` (Read banners).

### Network / Scanning
\`\`\`bash
dmitry -p -b target.com
\`\`\`
*   **Description**: Performs port scan and grabs banner info from found ports.
*   **Arguments**: \`-p\` (Port scan), \`-b\` (Banner grab).

\`\`\`bash
dmitry -p -v target.com
\`\`\`
*   **Description**: Performs port scan in verbose mode.
*   **Arguments**: \`-p\` (Port scan), \`-v\` (Verbose).

### OSINT & Enumeration
\`\`\`bash
dmitry -n -w target.com
\`\`\`
*   **Description**: Fetches Netcraft and Whois info together.
*   **Arguments**: \`-n\` (Netcraft), \`-w\` (Whois).

\`\`\`bash
dmitry -s -e target.com
\`\`\`
*   **Description**: Collects subdomains and email addresses.
*   **Arguments**: \`-s\` (Subdomains), \`-e\` (Emails).

\`\`\`bash
dmitry -winse target.com
\`\`\`
*   **Description**: Full passive scan (Whois, IP, Netcraft, Subdomain, Email). Does not send packets to target (except IP lookup).
*   **Arguments**: \`-w\`, \`-i\` (IP lookup), \`-n\`, \`-s\`, \`-e\`.

### Output
\`\`\`bash
dmitry -winsepfb -o full_scan.txt target.com
\`\`\`
*   **Description**: Runs all modules and writes result to \`full_scan.txt\`.
*   **Arguments**: \`-winsepfb\` (All flags), \`-o\` (Output file).

## 6. Real Pentest Scenarios

### Basic OSINT Collection Behind CDN
If target is behind Cloudflare, port scan is misleading. Only passive info should be collected.
\`\`\`bash
dmitry -n -w -s -e target.com
\`\`\`
*   **Arguments**: \`-n\` (Netcraft), \`-w\` (Whois), \`-s\` (Subdomain), \`-e\` (Email). Active scan (\`-p\`) is off.

### "Zero-Touch Footprinting" with Passive Recon
Gathering info without generating any logs on target system.
\`\`\`bash
dmitry -n -w -s target.com
\`\`\`
*   **Arguments**: \`-n\`, \`-w\`, \`-s\`. These queries are made to 3rd party services, not the target.

### Email Pattern Extraction (Corporate Structures)
Determining email format for social engineering or brute-force list preparation.
\`\`\`bash
dmitry -e target.com
\`\`\`
*   **Arguments**: \`-e\`. Emails in output are analyzed (e.g., \`first.last@\`) to create wordlist.

### Multi-stage Information Gathering
First identifying targets with passive scan, then active scanning selected ones.
Phase 1 (Passive):
\`\`\`bash
dmitry -s -o subs.txt target.com
\`\`\`
Phase 2 (Active - For found subdomain):
\`\`\`bash
dmitry -p -b -i sub.target.com
\`\`\`

### Legacy Service Detection with Banner Fingerprinting
Catching old and vulnerable services from banner info.
\`\`\`bash
dmitry -p -b target.com
\`\`\`
*   **Arguments**: \`-p\`, \`-b\`. Look for old versions like \`IIS 6.0\` or \`Apache 2.2\` in output.

## 7. Best Practices (Expert Level)
*   **Passive First**: Always start with \`-winse\` (passive) modes, then move to \`-p\` (active).
*   **Verify Subdomains**: Cross-verify \`-s\` output with \`Sublist3r\` or \`Amass\` results.
*   **Save Output**: Always use \`-o\` parameter. Terminal output can be lost.
*   **False Banners**: Do not blindly trust banner info from \`-b\`, verify with \`Nmap -sV\`.
*   **CDN Awareness**: Check if target IP belongs to a CDN with Whois (\`-w\`).
*   **Legal Compliance**: \`-p\` and \`-b\` perform active scanning and doing so without permission may be a crime.

## 8. Common Mistakes
*   **Single Flag Usage**: Just typing \`dmitry target.com\` (no parameters) gives very limited info.
*   **No Output File**: Doing long scans without \`-o\` and losing data.
*   **Trusting Port Scan**: Thinking DMitry's simple port scanner replaces Nmap.
*   **Ignoring Verbose**: Not using \`-v\` when debugging or detail is needed.
*   **Scanning CDN**: Port scanning Cloudflare IP and rejoicing "found open port".
`;

const newCheatsheet = {
    title: {
        tr: "DMitry Cheatsheet",
        en: "DMitry Cheatsheet"
    },
    description: {
        tr: trDescription,
        en: enDescription
    },
    tags: ["dmitry", "osint", "recon", "information-gathering", "subdomain", "email", "passive-recon"],
    links: ["https://github.com/jaygreig86/dmitry", "https://tools.kali.org/information-gathering/dmitry"],
    category: { "$oid": "6915e1cc2ee79a06a3d4bc44" } // Web Enumeration
};

try {
    const data = JSON.parse(fs.readFileSync(cheatsheetsPath, 'utf-8'));
    data.push(newCheatsheet);
    fs.writeFileSync(cheatsheetsPath, JSON.stringify(data, null, 2));
    console.log('Successfully added DMitry cheatsheet.');
} catch (err) {
    console.error('Error adding cheatsheet:', err);
}
