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

const contentTR = `# theHarvester - Open Source Intelligence (OSINT) Tool

## 1. Araç Tanımı
**theHarvester**, sızma testlerinin ilk aşaması olan bilgi toplama (OSINT) sürecinde kullanılan, açık kaynaklı ve çok yönlü bir araçtır. Arama motorları, sosyal medya, DNS kayıtları ve Shodan gibi pasif kaynaklardan e-posta adresleri, subdomainler, IP adresleri ve çalışan isimlerini toplar. Aktif ve pasif tarama yetenekleriyle hedef saldırı yüzeyini (attack surface) belirlemede kritik rol oynar.

## 2. Kurulum
*   **Linux (Kali/Debian)**: \`sudo apt install theharvester\` veya \`git clone\` ile.
*   **Pip ile**: \`pip3 install theHarvester\`
*   **API Key Gereksinimleri**: Shodan, Hunter.io, SecurityTrails gibi servisler için \`api-keys.yaml\` dosyasına anahtar girilmelidir.
*   **Modül Bağımlılıkları**: \`requirements.txt\` içindeki kütüphaneler (aiodns, shodan, beautifulsoup4 vb.) kurulmalıdır.
*   **Rate-Limit**: Google ve Bing gibi kaynaklar çok sık istekte IP'yi bloklayabilir.
*   **Proxy**: \`-p\` veya \`--proxies\` ile HTTP proxy (Burp) veya TOR kullanılabilir.

## 3. Temel Kullanım

**Temel Domain Taraması:**
\`\`\`bash
theHarvester -d target.com -b all -l 500 -f sonuc.html
\`\`\`
**Açıklama:**
target.com için desteklenen tüm kaynakları (-b all) kullanarak tarama yapar, sonuçları 500 ile sınırlar ve HTML dosyasına kaydeder.
**Argümanlar:**
*   **-d**: Hedef domain.
*   **-b**: Veri kaynağı (google, bing, all).
*   **-l**: Sonuç limiti.
*   **-f**: Çıktı dosyası adı.

**DNS Çözümleme ile Tarama:**
\`\`\`bash
theHarvester -d target.com -b crtsh --dns-lookup
\`\`\`
**Açıklama:**
crt.sh üzerinden subdomainleri bulur ve aktif olup olmadıklarını DNS sorgusu ile doğrular.
**Argümanlar:**
*   **--dns-lookup**: Bulunan hostların IP adreslerini çözümler.

**Shodan Entegrasyonu:**
\`\`\`bash
theHarvester -d target.com -b shodan --shodan
\`\`\`
**Açıklama:**
Shodan API kullanarak hedefle ilgili port ve servis bilgilerini çeker.
**Argümanlar:**
*   **--shodan**: Shodan sorgularını aktif eder.

## 4. Desteklenen Kaynaklar (Teknik Liste)

*   **Arama Motorları (Google, Bing, DuckDuckGo, Yahoo)**:
    *   **Ne Toplar?**: Subdomain, Email, URL.
    *   **Not**: Rate-limit riski yüksektir, captcha çıkabilir.
*   **DNS Kaynakları (crt.sh, dnsdumpster)**:
    *   **Ne Toplar?**: Subdomain (Sertifika şeffaflık kayıtları).
    *   **Avantaj**: Pasif olduğu için hedefle etkileşime girmez, çok hızlıdır.
*   **Shodan**:
    *   **Ne Toplar?**: IP, Port, Servis Banner, OS bilgisi.
    *   **Gereksinim**: API Key.
*   **Hunter.io / Snov.io**:
    *   **Ne Toplar?**: Kurumsal e-posta adresleri, çalışan isimleri.
    *   **Gereksinim**: API Key.
*   **IntelligenceX / AlienVault (OTX)**:
    *   **Ne Toplar?**: Leak verileri, subdomainler, tehdit istihbaratı.
*   **URLScan.io / Wayback Machine**:
    *   **Ne Toplar?**: Eski URL'ler, ekran görüntüleri, JS dosyaları.

## 5. İleri Seviye Kullanım

### API Key Konfigürasyonu
Kurulum dizinindeki \`api-keys.yaml\` dosyasını düzenleyin:
\`\`\`yaml
shodan:
  key: API_KEY_BURAYA
hunter:
  key: API_KEY_BURAYA
\`\`\`
Bu anahtarlar olmadan ilgili modüller çalışmaz veya kısıtlı veri döner.

### Kombine OSINT Teknikleri
*   **Pasif -> Aktif Zinciri**: Önce \`crt.sh\` ve \`anubis\` gibi pasif kaynaklarla subdomain listesi oluşturun, sonra \`--dns-lookup\` veya \`dnsx\` ile aktiflik testi yapın.
*   **DNS Brute Force**: theHarvester yerleşik brute-force yapmaz, ancak çıktıları \`gobuster dns\` veya \`amass\` için wordlist olarak kullanılabilir.

### Proxy Kullanımı
\`\`\`bash
theHarvester -d target.com -b google -p http://127.0.0.1:8080
\`\`\`
Trafiği Burp Suite üzerinden geçirerek hangi sorguların yapıldığını analiz edebilir veya dönen yanıtları manipüle edebilirsiniz.

### Advanced DNS Enum
*   **Forward DNS**: Bulunan her subdomain için A kaydı sorgusu.
*   **Reverse DNS**: IP aralığı tespit edilirse, PTR kayıtlarından diğer domainleri bulma.
*   **Virtual Host**: Aynı IP'deki diğer siteleri (vhost) arama (\`-c\` parametresi).

## 6. Açıklamalı Komutlar (GENİŞ LİSTE)

**Komut:**
\`\`\`bash
theHarvester -d target.com -b google -l 200
\`\`\`
**Açıklama:**
Sadece Google'ı kullanarak 200 sonuçla sınırlı temel tarama.
**Argümanlar:**
*   **-d**: Domain.
*   **-b google**: Kaynak.
*   **-l 200**: Limit.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b all -f report.xml
\`\`\`
**Açıklama:**
Tüm kaynakları tara ve sonucu XML olarak kaydet (Diğer araçlara import için).
**Argümanlar:**
*   **-f report.xml**: XML çıktı dosyası.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b linkedin -l 500
\`\`\`
**Açıklama:**
LinkedIn üzerinden çalışan isimlerini toplar (Google dorking kullanır).
**Argümanlar:**
*   **-b linkedin**: LinkedIn kaynağı.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b crtsh --dns-lookup
\`\`\`
**Açıklama:**
SSL sertifika kayıtlarından subdomain bulur ve IP'lerini çözer.
**Argümanlar:**
*   **--dns-lookup**: Aktif DNS çözümleme.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b shodan --shodan
\`\`\`
**Açıklama:**
Shodan veritabanından hedefle ilgili açık portları listeler.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b all -s 100
\`\`\`
**Açıklama:**
Arama motoru sonuçlarının ilk 100'ünü atlayarak (offset) taramaya başlar.
**Argümanlar:**
*   **-s 100**: Start offset.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b bing -v
\`\`\`
**Açıklama:**
Bing taraması yaparken detaylı (verbose) çıktı verir.
**Argümanlar:**
*   **-v**: Verbose mod.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b all -n
\`\`\`
**Açıklama:**
DNS çözümlemesi yapmadan (pasif) sadece metin bazlı sonuçları getirir.
**Argümanlar:**
*   **-n**: No DNS lookup.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b all -c
\`\`\`
**Açıklama:**
DNS çözümlemesi yapar ve bulunan IP'lerde Virtual Host taraması gerçekleştirir.
**Argümanlar:**
*   **-c**: Virtual Host brute-force.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b all -e 8.8.8.8
\`\`\`
**Açıklama:**
DNS sorguları için Google DNS sunucusunu kullanır.
**Argümanlar:**
*   **-e 8.8.8.8**: Özel DNS sunucusu.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b all -t
\`\`\`
**Açıklama:**
TLD (Top Level Domain) genişletmesi yaparak farklı uzantıları (.net, .org) arar.
**Argümanlar:**
*   **-t**: TLD expansion.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b google -g
\`\`\`
**Açıklama:**
Google Dorking modunu kullanarak daha spesifik aramalar yapar.
**Argümanlar:**
*   **-g**: Google Dorking.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b all --proxies http://127.0.0.1:8080
\`\`\`
**Açıklama:**
Tüm trafiği belirtilen HTTP proxy üzerinden geçirir.
**Argümanlar:**
*   **--proxies**: Proxy URL.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b hunter
\`\`\`
**Açıklama:**
Hunter.io API kullanarak kurumsal e-posta adreslerini listeler (API Key gerekir).

**Komut:**
\`\`\`bash
theHarvester -d target.com -b securitytrails
\`\`\`
**Açıklama:**
SecurityTrails API ile geçmiş DNS kayıtlarını ve subdomainleri çeker.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b virustotal
\`\`\`
**Açıklama:**
VirusTotal veritabanından ilişkili domain ve IP'leri çeker.

**Komut:**
\`\`\`bash
theHarvester -d target.com -b all -r
\`\`\`
**Açıklama:**
Bulunan IP adresleri için Reverse DNS (PTR) sorgusu yapar.
**Argümanlar:**
*   **-r**: Reverse lookup.

**Komut:**
\`\`\`bash
theHarvester -h
\`\`\`
**Açıklama:**
Yardım menüsünü ve tüm parametreleri gösterir.

## 7. Gerçek Pentest / OSINT Senaryoları

**Senaryo: Kurumsal Email Toplama (Phishing Öncesi)**
*   **Adımlar**: \`theHarvester -d sirket.com -b linkedin,hunter,google -l 500 -f emails.html\`
*   **Açıklama**: LinkedIn ve Hunter.io kullanarak çalışan isimlerini ve e-posta formatını (ad.soyad@sirket.com) belirleyin.
*   **Sonuç**: Hedefli phishing saldırısı için geçerli e-posta listesi.

**Senaryo: Subdomain Keşfi ve Aktiflik Testi**
*   **Adımlar**: \`theHarvester -d hedef.com -b crtsh,anubis,dnsdumpster --dns-lookup -f subs.xml\`
*   **Açıklama**: Pasif kaynaklardan subdomainleri toplayıp, DNS sorgusu ile hangilerinin hala aktif olduğunu (IP döndürdüğünü) doğrulayın.
*   **Sonuç**: Saldırı yüzeyi haritası (Attack Surface).

**Senaryo: Cloud Asset Discovery**
*   **Adımlar**: \`theHarvester -d hedef.com -b all\` çıktısında "s3", "azure", "dev" gibi kelimeleri içeren subdomainleri filtreleyin.
*   **Açıklama**: Geliştiricilerin unuttuğu test ortamlarını veya açık S3 bucketlarını tespit edin.

**Senaryo: Brand Monitoring**
*   **Adımlar**: \`theHarvester -d marka.com -b twitter,reddit,google\`
*   **Açıklama**: Sosyal medyada ve arama motorlarında marka hakkında konuşulanları veya sızdırılan bilgileri izleyin.

## 8. En İyi Uygulamalar (Uzman Seviye)

*   **API Key Kullanımı**: Shodan, Hunter, SecurityTrails gibi kaynaklar API key olmadan çalışmaz veya çok az veri verir. Mutlaka \`api-keys.yaml\` dosyasını doldurun.
*   **Rate-Limit Yönetimi**: Google ve Bing taramalarında \`-l\` limitini düşük tutun veya proxy rotasyonu kullanın.
*   **Kaynak Optimizasyonu**: Her taramada \`-b all\` kullanmak yavaştır. Sadece ihtiyacınız olan kaynakları (örn: subdomain için crtsh, email için hunter) seçin.
*   **Pipeline Entegrasyonu**: theHarvester çıktısını (\`-f\`) JSON/XML olarak alıp, \`jq\` ile parse ederek \`nmap\` veya \`httpx\` gibi araçlara pipe edin.
*   **False-Positive Azaltma**: \`--dns-lookup\` parametresini mutlaka kullanın. Pasif kaynaklarda görünen subdomainler kapanmış olabilir.

## 9. Sık Yapılan Hatalar

*   **API Key Eklememek**: Aracın gücünün %80'ini kullanmamak demektir.
*   **DNS Resolution Kapalıyken IP Doğrulama**: \`-n\` kullanırsanız subdomainlerin aktif olup olmadığını bilemezsiniz.
*   **Output Parse Etmemek**: Ekrana basılan veriyi kopyala-yapıştır yapmak yerine \`-f\` ile dosya çıktısı alıp işleyin.
*   **Cloud Assetleri Gözden Kaçırmak**: Subdomain listesindeki 3. parti hizmetleri (AWS, Heroku, Azure) atlamayın, subdomain takeover zafiyeti olabilir.
`;

const contentEN = `# theHarvester - Open Source Intelligence (OSINT) Tool

## 1. Tool Definition
**theHarvester** is an open-source, versatile tool used in the information gathering (OSINT) phase of penetration testing. It collects emails, subdomains, IP addresses, and employee names from passive sources like search engines, social media, DNS records, and Shodan. It plays a critical role in defining the target attack surface through both active and passive scanning capabilities.

## 2. Installation
*   **Linux (Kali/Debian)**: \`sudo apt install theharvester\` or via \`git clone\`.
*   **Via Pip**: \`pip3 install theHarvester\`
*   **API Key Requirements**: Keys must be entered in \`api-keys.yaml\` for services like Shodan, Hunter.io, SecurityTrails.
*   **Module Dependencies**: Libraries in \`requirements.txt\` (aiodns, shodan, beautifulsoup4, etc.) must be installed.
*   **Rate-Limit**: Sources like Google and Bing may block IPs for frequent requests.
*   **Proxy**: Use \`-p\` or \`--proxies\` for HTTP proxy (Burp) or TOR.

## 3. Basic Usage

**Basic Domain Scan:**
\`\`\`bash
theHarvester -d target.com -b all -l 500 -f result.html
\`\`\`
**Description:**
Scans target.com using all supported sources (-b all), limits results to 500, and saves to an HTML file.
**Arguments:**
*   **-d**: Target domain.
*   **-b**: Data source (google, bing, all).
*   **-l**: Result limit.
*   **-f**: Output filename.

**Scan with DNS Resolution:**
\`\`\`bash
theHarvester -d target.com -b crtsh --dns-lookup
\`\`\`
**Description:**
Finds subdomains via crt.sh and verifies if they are active using DNS queries.
**Arguments:**
*   **--dns-lookup**: Resolves IP addresses of found hosts.

**Shodan Integration:**
\`\`\`bash
theHarvester -d target.com -b shodan --shodan
\`\`\`
**Description:**
Retrieves port and service info about the target using Shodan API.
**Arguments:**
*   **--shodan**: Activates Shodan queries.

## 4. Supported Sources (Technical List)

*   **Search Engines (Google, Bing, DuckDuckGo, Yahoo)**:
    *   **Collects**: Subdomains, Emails, URLs.
    *   **Note**: High rate-limit risk, captchas may appear.
*   **DNS Sources (crt.sh, dnsdumpster)**:
    *   **Collects**: Subdomains (Certificate Transparency logs).
    *   **Advantage**: Passive (no interaction with target), very fast.
*   **Shodan**:
    *   **Collects**: IPs, Ports, Service Banners, OS info.
    *   **Requirement**: API Key.
*   **Hunter.io / Snov.io**:
    *   **Collects**: Corporate emails, employee names.
    *   **Requirement**: API Key.
*   **IntelligenceX / AlienVault (OTX)**:
    *   **Collects**: Leaked data, subdomains, threat intelligence.
*   **URLScan.io / Wayback Machine**:
    *   **Collects**: Old URLs, screenshots, JS files.

## 5. Advanced Usage

### API Key Configuration
Edit \`api-keys.yaml\` in the installation directory:
\`\`\`yaml
shodan:
  key: API_KEY_HERE
hunter:
  key: API_KEY_HERE
\`\`\`
Without these keys, relevant modules won't work or will return limited data.

### Combined OSINT Techniques
*   **Passive -> Active Chain**: First build a subdomain list with passive sources like \`crt.sh\` and \`anubis\`, then verify activity with \`--dns-lookup\` or \`dnsx\`.
*   **DNS Brute Force**: theHarvester doesn't do built-in brute-force, but its output can be used as a wordlist for \`gobuster dns\` or \`amass\`.

### Proxy Usage
\`\`\`bash
theHarvester -d target.com -b google -p http://127.0.0.1:8080
\`\`\`
Route traffic through Burp Suite to analyze queries or manipulate responses.

### Advanced DNS Enum
*   **Forward DNS**: A record query for every found subdomain.
*   **Reverse DNS**: If an IP range is found, find other domains via PTR records.
*   **Virtual Host**: Search for other sites on the same IP (\`-c\` parameter).

## 6. Annotated Commands (EXTENDED LIST)

**Command:**
\`\`\`bash
theHarvester -d target.com -b google -l 200
\`\`\`
**Description:**
Basic scan using only Google, limited to 200 results.
**Arguments:**
*   **-d**: Domain.
*   **-b google**: Source.
*   **-l 200**: Limit.

**Command:**
\`\`\`bash
theHarvester -d target.com -b all -f report.xml
\`\`\`
**Description:**
Scan all sources and save result as XML (for import into other tools).
**Arguments:**
*   **-f report.xml**: XML output file.

**Command:**
\`\`\`bash
theHarvester -d target.com -b linkedin -l 500
\`\`\`
**Description:**
Collects employee names via LinkedIn (uses Google dorking).
**Arguments:**
*   **-b linkedin**: LinkedIn source.

**Command:**
\`\`\`bash
theHarvester -d target.com -b crtsh --dns-lookup
\`\`\`
**Description:**
Finds subdomains from SSL cert logs and resolves IPs.
**Arguments:**
*   **--dns-lookup**: Active DNS resolution.

**Command:**
\`\`\`bash
theHarvester -d target.com -b shodan --shodan
\`\`\`
**Description:**
Lists open ports for the target from Shodan database.

**Command:**
\`\`\`bash
theHarvester -d target.com -b all -s 100
\`\`\`
**Description:**
Starts scanning after skipping the first 100 search engine results (offset).
**Arguments:**
*   **-s 100**: Start offset.

**Command:**
\`\`\`bash
theHarvester -d target.com -b bing -v
\`\`\`
**Description:**
Verbose output while scanning Bing.
**Arguments:**
*   **-v**: Verbose mode.

**Command:**
\`\`\`bash
theHarvester -d target.com -b all -n
\`\`\`
**Description:**
Text-only results without DNS resolution (passive).
**Arguments:**
*   **-n**: No DNS lookup.

**Command:**
\`\`\`bash
theHarvester -d target.com -b all -c
\`\`\`
**Description:**
Performs DNS resolution and Virtual Host scanning on found IPs.
**Arguments:**
*   **-c**: Virtual Host brute-force.

**Command:**
\`\`\`bash
theHarvester -d target.com -b all -e 8.8.8.8
\`\`\`
**Description:**
Uses Google DNS server for queries.
**Arguments:**
*   **-e 8.8.8.8**: Custom DNS server.

**Command:**
\`\`\`bash
theHarvester -d target.com -b all -t
\`\`\`
**Description:**
Performs TLD expansion to find different extensions (.net, .org).
**Arguments:**
*   **-t**: TLD expansion.

**Command:**
\`\`\`bash
theHarvester -d target.com -b google -g
\`\`\`
**Description:**
Uses Google Dorking mode for more specific searches.
**Arguments:**
*   **-g**: Google Dorking.

**Command:**
\`\`\`bash
theHarvester -d target.com -b all --proxies http://127.0.0.1:8080
\`\`\`
**Description:**
Routes all traffic through the specified HTTP proxy.
**Arguments:**
*   **--proxies**: Proxy URL.

**Command:**
\`\`\`bash
theHarvester -d target.com -b hunter
\`\`\`
**Description:**
Lists corporate emails using Hunter.io API (Requires API Key).

**Command:**
\`\`\`bash
theHarvester -d target.com -b securitytrails
\`\`\`
**Description:**
Fetches historical DNS records and subdomains via SecurityTrails API.

**Command:**
\`\`\`bash
theHarvester -d target.com -b virustotal
\`\`\`
**Description:**
Fetches related domains and IPs from VirusTotal database.

**Command:**
\`\`\`bash
theHarvester -d target.com -b all -r
\`\`\`
**Description:**
Performs Reverse DNS (PTR) lookup for found IP addresses.
**Arguments:**
*   **-r**: Reverse lookup.

**Command:**
\`\`\`bash
theHarvester -h
\`\`\`
**Description:**
Shows help menu and all parameters.

## 7. Real Pentest / OSINT Scenarios

**Scenario: Corporate Email Gathering (Pre-Phishing)**
*   **Steps**: \`theHarvester -d company.com -b linkedin,hunter,google -l 500 -f emails.html\`
*   **Description**: Determine employee names and email format (first.last@company.com) using LinkedIn and Hunter.io.
*   **Result**: Valid email list for targeted phishing attacks.

**Scenario: Subdomain Discovery and Activity Test**
*   **Steps**: \`theHarvester -d target.com -b crtsh,anubis,dnsdumpster --dns-lookup -f subs.xml\`
*   **Description**: Collect subdomains from passive sources and verify which ones are still active (return IP) via DNS query.
*   **Result**: Attack Surface map.

**Scenario: Cloud Asset Discovery**
*   **Steps**: Filter subdomains containing "s3", "azure", "dev" from \`theHarvester -d target.com -b all\` output.
*   **Description**: Detect test environments or open S3 buckets forgotten by developers.

**Scenario: Brand Monitoring**
*   **Steps**: \`theHarvester -d brand.com -b twitter,reddit,google\`
*   **Description**: Monitor mentions or leaked info about the brand on social media and search engines.

## 8. Best Practices (Expert Level)

*   **API Key Usage**: Sources like Shodan, Hunter, SecurityTrails won't work or give limited data without keys. Always fill \`api-keys.yaml\`.
*   **Rate-Limit Management**: Keep \`-l\` limit low for Google/Bing scans or use proxy rotation.
*   **Source Optimization**: \`-b all\` is slow. Select only needed sources (e.g., crtsh for subdomains, hunter for emails).
*   **Pipeline Integration**: Pipe theHarvester output (\`-f\`) as JSON/XML to \`jq\` and then to tools like \`nmap\` or \`httpx\`.
*   **False-Positive Reduction**: Always use \`--dns-lookup\`. Subdomains in passive sources might be dead.

## 9. Common Mistakes

*   **Not Adding API Keys**: Missing out on 80% of the tool's power.
*   **IP Verification without DNS Resolution**: Using \`-n\` means you won't know if subdomains are active.
*   **Not Parsing Output**: Copy-pasting from screen instead of processing file output (\`-f\`).
*   **Overlooking Cloud Assets**: Missing 3rd party services (AWS, Heroku, Azure) in subdomain lists, which could lead to subdomain takeover.
`;

async function addTheHarvester() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding theHarvester cheatsheet...');

        // 1. Find or create the category
        let category = await Category.findOne({ 'name.en': 'Information Gathering' });
        if (!category) {
            console.log('Category "Information Gathering" not found, creating...');
            category = await Category.create({
                name: { tr: 'Bilgi Toplama', en: 'Information Gathering' },
                description: { tr: 'OSINT ve keşif araçları', en: 'OSINT and reconnaissance tools' },
                slug: 'information-gathering',
                icon: 'Search'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'theHarvester Cheat Sheet',
                en: 'theHarvester Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['theharvester', 'osint', 'recon', 'email', 'subdomain', 'dns', 'shodan']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'theHarvester Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('theHarvester cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addTheHarvester();
