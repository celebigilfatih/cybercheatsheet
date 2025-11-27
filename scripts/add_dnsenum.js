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

const contentTR = `# dnsenum - Advanced DNS Enumeration Tool

## 1. Araç Tanımı
**dnsenum**, DNS keşif (reconnaissance) sürecini otomatize eden, çok işlevli bir Perl scriptidir. Subdomain enumeration, zone transfer testleri, reverse domain scanning, brute force ve Google scraping tekniklerini birleştirerek hedef domain hakkında kapsamlı bilgi toplar. OSINT pipeline'larında ve sızma testlerinin ilk aşamasında DNS yüzeyini haritalamak için kullanılır.

## 2. Kurulum
*   **Kali Linux / Parrot OS**: Varsayılan olarak yüklü gelir.
*   **Manuel Kurulum**: \`git clone https://github.com/fwaeytens/dnsenum\`
*   **Perl Bağımlılıkları**: \`cpan install Net::IP Net::DNS Net::Netmask XML::Writer\`
*   **Not**: Root yetkisi gerektirmez ancak bazı ağ işlemleri için önerilir.

## 3. Temel Kullanım

**Basit Domain Taraması:**
\`\`\`bash
dnsenum target.com
\`\`\`
**Açıklama:**
Varsayılan ayarlarla (NS, MX, A kayıtları ve varsayılan wordlist ile brute-force) tarama yapar.

**Kapsamlı Tarama (Full Enum):**
\`\`\`bash
dnsenum --enum target.com
\`\`\`
**Açıklama:**
Google scraping, brute-force, zone transfer ve reverse lookup dahil tüm modülleri çalıştırır.
**Argümanlar:**
*   **--enum**: Kısayol parametresi (threads=5, -s 15, -w).

**Output Dosyasına Yazma:**
\`\`\`bash
dnsenum target.com -o result.xml
\`\`\`
**Açıklama:**
Sonuçları XML formatında kaydeder.
**Argümanlar:**
*   **-o**: Çıktı dosyası.

**Temel Argümanlar:**
*   **-d [saniye]**: Whois sorguları arasındaki bekleme süresi (delay).
*   **-t [sayı]**: Brute-force sırasında kullanılacak thread sayısı.
*   **-f [dosya]**: Subdomain brute-force için özel wordlist.
*   **-r**: Reverse lookup için alt alan taramasını aktif eder.
*   **--dnsserver [IP]**: Sorgular için özel DNS sunucusu kullanır.
*   **--timeout [saniye]**: DNS sorgu zaman aşımı süresi.
*   **--norecursion**: Recursion (yineleme) özelliğini kapatır.
*   **--no-color**: Renkli çıktıyı kapatır.
*   **--noreverse**: Reverse lookup işlemini devre dışı bırakır.
*   **--nogoogle**: Google scraping işlemini devre dışı bırakır.
*   **--scrap [sayı]**: Google scraping için maksimum sayfa sayısı.

## 4. Desteklenen Modlar

*   **Zone Transfer (AXFR)**: Hedefin DNS sunucularından tüm domain kayıtlarını (zone file) çekmeye çalışır. Başarılı olursa tüm subdomainler listelenir.
*   **Google Scraping**: Google arama sonuçlarından subdomainleri toplar (-p ve -s parametreleri ile kontrol edilir).
*   **Brute Force**: Belirtilen wordlist (varsayılan: dns.txt) ile subdomainleri tahmin etmeye çalışır.
*   **Reverse DNS Sweep**: Bulunan subdomainlerin IP aralıklarını (C-class) tarayarak o aralıktaki diğer domainleri (PTR kayıtları) bulur.
*   **Wildcard Detection**: Rastgele subdomainler deneyerek wildcard DNS (her şeye cevap veren) yapılandırmasını tespit eder.

## 5. İleri Seviye Kullanım

*   **DNS Bruteforce Optimizasyonu**: Büyük wordlistler (Seclists) kullanırken \`-t 20\` veya üzeri thread sayısı verin ve \`--timeout 1\` ile hızı artırın.
*   **Wildcard Filtreleme**: Wildcard tespit edildiğinde dnsenum otomatik olarak uyarı verir, ancak \`--exclude\` ile belirli patternleri hariç tutabilirsiniz.
*   **Reverse Sweep + ASN**: Reverse lookup sonuçlarını bir ASN lookup aracıyla birleştirerek hedefin tüm IP bloklarını doğrulayın.
*   **DNS Server Seçimi**: Google (8.8.8.8) veya Cloudflare (1.1.1.1) gibi public resolverlar kullanarak hedef sunucudaki yükü dağıtın ve bloklanmayı önleyin.

## 6. Açıklamalı Komutlar (GENİŞ LİSTE)

**Komut:**
\`\`\`bash
dnsenum --enum -f /usr/share/wordlists/dns.txt target.com
\`\`\`
**Açıklama:**
Tam kapsamlı tarama ve özel wordlist kullanımı.
**Argümanlar:**
*   **--enum**: Full mod.
*   **-f**: Wordlist yolu.

**Komut:**
\`\`\`bash
dnsenum --noreverse -o output.xml target.com
\`\`\`
**Açıklama:**
Reverse lookup yapmadan tarar ve XML çıktısı verir.
**Argümanlar:**
*   **--noreverse**: Reverse DNS kapalı.
*   **-o**: Çıktı dosyası.

**Komut:**
\`\`\`bash
dnsenum --dnsserver 8.8.8.8 --threads 50 target.com
\`\`\`
**Açıklama:**
Google DNS kullanarak ve 50 thread ile hızlı tarama yapar.
**Argümanlar:**
*   **--dnsserver**: DNS sunucusu.
*   **--threads**: Paralel işlem sayısı.

**Komut:**
\`\`\`bash
dnsenum --private -f subdomains.txt target.com
\`\`\`
**Açıklama:**
Domainin IP adreslerini private (özel) IP aralıklarında arar ve günceller.
**Argümanlar:**
*   **--private**: Private IP'leri göster/işle.

**Komut:**
\`\`\`bash
dnsenum --subfile found_subs.txt target.com
\`\`\`
**Açıklama:**
Bulunan tüm subdomainleri belirtilen dosyaya yazar (sonraki araçlar için).
**Argümanlar:**
*   **--subfile**: Subdomain çıktı dosyası.

**Komut:**
\`\`\`bash
dnsenum --scrap 50 target.com
\`\`\`
**Açıklama:**
Google scraping modunda 50 sayfa tarar.
**Argümanlar:**
*   **--scrap**: Google sayfa limiti.

**Komut:**
\`\`\`bash
dnsenum --whois target.com
\`\`\`
**Açıklama:**
Domain ve IP blokları için Whois sorgusu yapar.
**Argümanlar:**
*   **--whois**: Whois lookup aktif.

**Komut:**
\`\`\`bash
dnsenum --exclude "vpn.*" target.com
\`\`\`
**Açıklama:**
"vpn" ile başlayan subdomainleri sonuçlardan hariç tutar (Regex desteği).
**Argümanlar:**
*   **--exclude**: Regex filtreleme.

**Komut:**
\`\`\`bash
dnsenum -r target.com
\`\`\`
**Açıklama:**
Recursion (yineleme) ile subdomainlerin alt subdomainlerini de arar.
**Argümanlar:**
*   **-r**: Recursive scan.

**Komut:**
\`\`\`bash
dnsenum --timeout 5 target.com
\`\`\`
**Açıklama:**
Yavaş ağlar için DNS zaman aşımını 5 saniyeye çıkarır.
**Argümanlar:**
*   **--timeout**: Saniye cinsinden timeout.

**Komut:**
\`\`\`bash
dnsenum --no-color target.com > result.txt
\`\`\`
**Açıklama:**
Renkli çıktıyı kapatarak temiz bir metin dosyasına yönlendirme yapar.
**Argümanlar:**
*   **--no-color**: ANSI renk kodlarını kapatır.

**Komut:**
\`\`\`bash
dnsenum --norecursion target.com
\`\`\`
**Açıklama:**
Sadece ana domainin subdomainlerini bulur, derinlemesine inmez.
**Argümanlar:**
*   **--norecursion**: Derinlik taraması kapalı.

**Komut:**
\`\`\`bash
dnsenum --dnsserver 1.1.1.1,8.8.8.8 target.com
\`\`\`
**Açıklama:**
Birden fazla DNS sunucusu kullanarak yükü dağıtır.

**Komut:**
\`\`\`bash
dnsenum -t 10 -f big_wordlist.txt target.com
\`\`\`
**Açıklama:**
Büyük bir wordlist ile 10 thread kullanarak brute-force yapar.

**Komut:**
\`\`\`bash
dnsenum --xml output.xml target.com
\`\`\`
**Açıklama:**
Sonuçları XML formatında dışa aktarır.

**Komut:**
\`\`\`bash
dnsenum --nogoogle target.com
\`\`\`
**Açıklama:**
Google scraping yapmadan sadece brute-force ve DNS sorguları ile tarar.

**Komut:**
\`\`\`bash
dnsenum -d 5 target.com
\`\`\`
**Açıklama:**
Whois sorguları arasına 5 saniye bekleme koyar (Rate-limit önleme).

**Komut:**
\`\`\`bash
dnsenum --enum --subfile subs.txt -o full_report.xml target.com
\`\`\`
**Açıklama:**
Full tarama, subdomainleri txt'ye, raporu XML'e kaydeder.

**Komut:**
\`\`\`bash
dnsenum -h
\`\`\`
**Açıklama:**
Yardım menüsünü görüntüler.

**Komut:**
\`\`\`bash
dnsenum --version
\`\`\`
**Açıklama:**
Yüklü versiyonu gösterir.

## 7. Gerçek Pentest Senaryoları

**Senaryo: Zone Transfer Misconfig Tespiti**
*   **Adımlar**: \`dnsenum target.com\` komutu otomatik olarak AXFR dener.
*   **Açıklama**: Eğer hedef DNS sunucusu yanlış yapılandırılmışsa, tüm DNS kayıtlarını (gizli subdomainler dahil) sızdırır. Bu kritik bir zafiyettir.

**Senaryo: Cloud Asset Discovery**
*   **Adımlar**: \`dnsenum --enum target.com\` çıktısında CNAME kayıtlarını inceleyin.
*   **Açıklama**: \`s3.amazonaws.com\`, \`azurewebsites.net\` gibi CNAME'ler cloud varlıklarını gösterir. Subdomain takeover için kontrol edilmelidir.

**Senaryo: Reverse DNS ile IP Keşfi**
*   **Adımlar**: \`dnsenum --enum --norecursion target.com\`
*   **Açıklama**: Bulunan subdomainlerin IP bloklarını tarayarak (Reverse Lookup), aynı blokta şirkete ait unutulmuş sunucuları (PTR kayıtlarından) bulur.

**Senaryo: CDN Arkasındaki Gerçek IP'yi Bulma**
*   **Adımlar**: Brute-force ile \`dev\`, \`origin\`, \`direct\`, \`ftp\` gibi subdomainleri arayın.
*   **Açıklama**: Bu subdomainler genellikle CDN (Cloudflare vb.) arkasında değildir ve sunucunun gerçek IP adresini ifşa eder.

## 8. Best Practices (Uzman Seviye)

*   **Resolver Seçimi**: Varsayılan sistem DNS'i yerine güvenilir ve hızlı public DNS'leri (\`--dnsserver\`) kullanın.
*   **Thread Tuning**: Ev bağlantısında 10-20 thread yeterlidir. VPS üzerinde 50-100 thread'e çıkabilirsiniz.
*   **Wordlist Optimizasyonu**: Hedefin diline ve sektörüne uygun wordlist seçin (örn: \`seclists/Discovery/DNS\`).
*   **Wildcard Filtreleme**: Eğer tüm subdomainler aynı IP'ye dönüyorsa (Wildcard), brute-force sonuçları çöp olur. Bu durumda dnsenum'un wildcard tespitine güvenin veya \`massdns\` gibi araçlara geçin.
*   **Pipeline**: dnsenum çıktısını (\`--subfile\`) alıp \`httpx\` ile aktif web servislerini tarayın.

## 9. Sık Yapılan Hatalar

*   **Wildcard Tespiti Yapamamak**: Binlerce false-positive subdomain bulmak.
*   **Google Rate-Limit**: \`--scrap\` değerini çok yüksek tutarak Google tarafından bloklanmak.
*   **Yetersiz Wordlist**: Sadece varsayılan wordlist ile tarama yapıp gizli subdomainleri kaçırmak.
*   **Output Parse Etmemek**: XML veya subfile çıktısı almayıp veriyi manuel kopyalamaya çalışmak.
*   **Recursive Scan Unutmak**: \`-r\` kullanmayıp alt subdomainleri (örn: \`api.dev.target.com\`) kaçırmak.
`;

const contentEN = `# dnsenum - Advanced DNS Enumeration Tool

## 1. Tool Definition
**dnsenum** is a multithreaded Perl script designed to automate the DNS reconnaissance process. It combines subdomain enumeration, zone transfer testing, reverse domain scanning, brute force, and Google scraping to gather comprehensive information about a target domain. It is widely used in OSINT pipelines and the initial phase of penetration testing to map the DNS attack surface.

## 2. Installation
*   **Kali Linux / Parrot OS**: Pre-installed.
*   **Manual Installation**: \`git clone https://github.com/fwaeytens/dnsenum\`
*   **Perl Dependencies**: \`cpan install Net::IP Net::DNS Net::Netmask XML::Writer\`
*   **Note**: Root privileges are not strictly required but recommended for some network operations.

## 3. Basic Usage

**Simple Domain Scan:**
\`\`\`bash
dnsenum target.com
\`\`\`
**Description:**
Performs a scan with default settings (NS, MX, A records, and brute-force with default wordlist).

**Comprehensive Scan (Full Enum):**
\`\`\`bash
dnsenum --enum target.com
\`\`\`
**Description:**
Runs all modules including Google scraping, brute-force, zone transfer, and reverse lookup.
**Arguments:**
*   **--enum**: Shortcut parameter (equivalent to threads=5, -s 15, -w).

**Writing to Output File:**
\`\`\`bash
dnsenum target.com -o result.xml
\`\`\`
**Description:**
Saves results in XML format.
**Arguments:**
*   **-o**: Output file.

**Basic Arguments:**
*   **-d [seconds]**: Delay between Whois queries.
*   **-t [number]**: Number of threads for brute-force.
*   **-f [file]**: Custom wordlist for subdomain brute-force.
*   **-r**: Enables recursive lookup for subdomains.
*   **--dnsserver [IP]**: Uses a custom DNS server for queries.
*   **--timeout [seconds]**: DNS query timeout duration.
*   **--norecursion**: Disables recursion.
*   **--no-color**: Disables colored output.
*   **--noreverse**: Disables reverse lookup operations.
*   **--nogoogle**: Disables Google scraping.
*   **--scrap [number]**: Maximum number of pages to scrape from Google.

## 4. Supported Modes

*   **Zone Transfer (AXFR)**: Attempts to retrieve all domain records (zone file) from the target's nameservers. If successful, lists all subdomains.
*   **Google Scraping**: Harvests subdomains from Google search results (controlled via -p and -s parameters).
*   **Brute Force**: Attempts to guess subdomains using a wordlist (default: dns.txt).
*   **Reverse DNS Sweep**: Scans IP ranges (C-class) of found subdomains to discover other domains (PTR records) hosted on the same network.
*   **Wildcard Detection**: Detects wildcard DNS configurations (responding to any query) by testing random subdomains.

## 5. Advanced Usage

*   **DNS Bruteforce Optimization**: When using large wordlists (Seclists), use \`-t 20\` or more threads and decrease timeout with \`--timeout 1\`.
*   **Wildcard Filtering**: dnsenum warns about wildcards, but you can exclude specific patterns using \`--exclude\`.
*   **Reverse Sweep + ASN**: Correlate reverse lookup results with an ASN lookup tool to verify all IP blocks belonging to the target.
*   **DNS Server Selection**: Use public resolvers like Google (8.8.8.8) or Cloudflare (1.1.1.1) to distribute load and avoid blocking.

## 6. Annotated Commands (EXTENDED LIST)

**Command:**
\`\`\`bash
dnsenum --enum -f /usr/share/wordlists/dns.txt target.com
\`\`\`
**Description:**
Full comprehensive scan using a custom wordlist.
**Arguments:**
*   **--enum**: Full mode.
*   **-f**: Wordlist path.

**Command:**
\`\`\`bash
dnsenum --noreverse -o output.xml target.com
\`\`\`
**Description:**
Scans without reverse lookup and outputs to XML.
**Arguments:**
*   **--noreverse**: Reverse DNS disabled.
*   **-o**: Output file.

**Command:**
\`\`\`bash
dnsenum --dnsserver 8.8.8.8 --threads 50 target.com
\`\`\`
**Description:**
Fast scan using Google DNS and 50 threads.
**Arguments:**
*   **--dnsserver**: DNS server.
*   **--threads**: Parallel process count.

**Command:**
\`\`\`bash
dnsenum --private -f subdomains.txt target.com
\`\`\`
**Description:**
Processes and shows private IP addresses for the domain.
**Arguments:**
*   **--private**: Show/process private IPs.

**Command:**
\`\`\`bash
dnsenum --subfile found_subs.txt target.com
\`\`\`
**Description:**
Writes all found subdomains to the specified file (for use in other tools).
**Arguments:**
*   **--subfile**: Subdomain output file.

**Command:**
\`\`\`bash
dnsenum --scrap 50 target.com
\`\`\`
**Description:**
Scrapes 50 pages from Google.
**Arguments:**
*   **--scrap**: Google page limit.

**Command:**
\`\`\`bash
dnsenum --whois target.com
\`\`\`
**Description:**
Performs Whois lookup for domain and IP blocks.
**Arguments:**
*   **--whois**: Whois lookup active.

**Command:**
\`\`\`bash
dnsenum --exclude "vpn.*" target.com
\`\`\`
**Description:**
Excludes subdomains matching the regex "vpn" from results.
**Arguments:**
*   **--exclude**: Regex filtering.

**Command:**
\`\`\`bash
dnsenum -r target.com
\`\`\`
**Description:**
Recursively searches for subdomains of found subdomains.
**Arguments:**
*   **-r**: Recursive scan.

**Command:**
\`\`\`bash
dnsenum --timeout 5 target.com
\`\`\`
**Description:**
Increases DNS timeout to 5 seconds for slow networks.
**Arguments:**
*   **--timeout**: Timeout in seconds.

**Command:**
\`\`\`bash
dnsenum --no-color target.com > result.txt
\`\`\`
**Description:**
Disables color codes for clean redirection to a text file.
**Arguments:**
*   **--no-color**: Disable ANSI color codes.

**Command:**
\`\`\`bash
dnsenum --norecursion target.com
\`\`\`
**Description:**
Finds subdomains of the main domain only, does not go deeper.
**Arguments:**
*   **--norecursion**: Deep scan disabled.

**Command:**
\`\`\`bash
dnsenum --dnsserver 1.1.1.1,8.8.8.8 target.com
\`\`\`
**Description:**
Uses multiple DNS servers to distribute load.

**Command:**
\`\`\`bash
dnsenum -t 10 -f big_wordlist.txt target.com
\`\`\`
**Description:**
Brute-force using a large wordlist with 10 threads.

**Command:**
\`\`\`bash
dnsenum --xml output.xml target.com
\`\`\`
**Description:**
Exports results in XML format.

**Command:**
\`\`\`bash
dnsenum --nogoogle target.com
\`\`\`
**Description:**
Scans using only brute-force and DNS queries, skipping Google scraping.

**Command:**
\`\`\`bash
dnsenum -d 5 target.com
\`\`\`
**Description:**
Adds a 5-second delay between Whois queries (Anti-rate-limit).

**Command:**
\`\`\`bash
dnsenum --enum --subfile subs.txt -o full_report.xml target.com
\`\`\`
**Description:**
Full scan, saves subdomains to txt and report to XML.

**Command:**
\`\`\`bash
dnsenum -h
\`\`\`
**Description:**
Displays help menu.

**Command:**
\`\`\`bash
dnsenum --version
\`\`\`
**Description:**
Shows installed version.

## 7. Real Pentest Scenarios

**Scenario: Zone Transfer Misconfig Detection**
*   **Steps**: \`dnsenum target.com\` automatically attempts AXFR.
*   **Description**: If the target nameserver is misconfigured, it leaks all DNS records (including hidden subdomains). This is a critical vulnerability.

**Scenario: Cloud Asset Discovery**
*   **Steps**: Inspect CNAME records in \`dnsenum --enum target.com\` output.
*   **Description**: CNAMEs like \`s3.amazonaws.com\` or \`azurewebsites.net\` indicate cloud assets. Check for subdomain takeover.

**Scenario: IP Discovery via Reverse DNS**
*   **Steps**: \`dnsenum --enum --norecursion target.com\`
*   **Description**: Scans IP blocks of found subdomains (Reverse Lookup) to find other forgotten servers (via PTR records) in the same block belonging to the company.

**Scenario: Finding Real IP Behind CDN**
*   **Steps**: Brute-force for subdomains like \`dev\`, \`origin\`, \`direct\`, \`ftp\`.
*   **Description**: These subdomains are often not routed through CDNs (like Cloudflare) and reveal the real server IP.

## 8. Best Practices (Expert Level)

*   **Resolver Selection**: Use reliable and fast public DNS (\`--dnsserver\`) instead of default system DNS.
*   **Thread Tuning**: 10-20 threads are enough for home connections. On VPS, you can go up to 50-100.
*   **Wordlist Optimization**: Choose a wordlist suitable for the target's language and sector (e.g., \`seclists/Discovery/DNS\`).
*   **Wildcard Filtering**: If all subdomains resolve to the same IP (Wildcard), brute-force results are useless. Rely on dnsenum's detection or switch to tools like \`massdns\`.
*   **Pipeline**: Pipe dnsenum output (\`--subfile\`) to \`httpx\` to scan for active web services.

## 9. Common Mistakes

*   **Failing to Detect Wildcard**: Getting thousands of false-positive subdomains.
*   **Google Rate-Limit**: Getting blocked by Google for setting \`--scrap\` too high.
*   **Insufficient Wordlist**: Missing hidden subdomains by only using the default wordlist.
*   **Not Parsing Output**: Manually copying data instead of using XML or subfile output.
*   **Forgetting Recursive Scan**: Missing sub-subdomains (e.g., \`api.dev.target.com\`) by not using \`-r\`.
`;

async function addDnsenum() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding dnsenum cheatsheet...');

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
                tr: 'dnsenum Cheat Sheet',
                en: 'dnsenum Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['dnsenum', 'dns', 'recon', 'subdomain', 'brute-force', 'zone-transfer']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'dnsenum Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('dnsenum cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addDnsenum();
