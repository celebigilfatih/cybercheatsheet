import dbConnect from '../lib/dbConnect.js';
import Cheatsheet from '../models/Cheatsheet.js';
import Category from '../models/Category.js';
import mongoose from 'mongoose';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

const contentTR = `# WAFW00F - Web Application Firewall Fingerprinting

## 1. Araç Tanımı
**WAFW00F**, web uygulamalarının önünde çalışan Web Application Firewall (WAF) sistemlerini tespit etmek ve parmak izini (fingerprint) almak için kullanılan Python tabanlı bir araçtır. HTTP isteklerine verilen yanıtları, cookie'leri, header'ları ve hata mesajlarını analiz ederek Cloudflare, AWS WAF, Imperva, F5 BIG-IP gibi 100'den fazla WAF ürününü tanımlayabilir.

## 2. Kurulum
*   **Kali Linux**: \`apt install wafw00f\` (Varsayılan yüklü gelir)
*   **GitHub**: \`git clone https://github.com/EnableSecurity/wafw00f.git\`
*   **Python**: \`pip install wafw00f\`

## 3. Temel Kullanım

### Temel WAF Detection
Hedef URL'ye basit istekler göndererek WAF varlığını kontrol eder.
\`\`\`bash
wafw00f https://target.com
\`\`\`
**Argüman Açıklamaları:**
*   **https://target.com**: Test edilecek hedef URL.

### Tekli Hedef Testi
Belirli bir domain veya IP adresini test eder.
\`\`\`bash
wafw00f target.com
\`\`\`

### Çoklu Hedef Testi
Birden fazla hedefi sırayla test etmek için boşlukla ayrılmış liste verilebilir.
\`\`\`bash
wafw00f target1.com target2.com
\`\`\`

### Fingerprinting
WAF tespit edildikten sonra, spesifik vendor ve versiyon bilgisini (mümkünse) çıkarır.

### WAF Türü Belirleme
WAF'ın Cloud-based (örn: Cloudflare) mi yoksa On-premise (örn: F5) mi olduğunu anlamaya yardımcı olur.

### Response Analysis
Sunucudan dönen HTTP status code (403, 406, 501 vb.) ve response body analiz edilir.

### HTTP Yöntemleri ile Test
GET, POST, HEAD gibi farklı metodlarla WAF tepkisi ölçülür.

### Proxy Üzerinden Test
Trafiği bir proxy sunucusu üzerinden geçirerek analiz yapar.
\`\`\`bash
wafw00f target.com -p http://127.0.0.1:8080
\`\`\`
**Argüman Açıklamaları:**
*   **-p**: Proxy URL.

## 4. İleri Seviye Kullanım

### WAF Fingerprinting Metodolojisi
WAFW00F, önce normal bir istek gönderir, ardından zararlı (malicious) bir istek göndererek sunucunun tepkisini karşılaştırır.

### Payload-based Detection
XSS, SQLi ve Path Traversal payloadları göndererek WAF'ın bloklama sayfasını veya hata mesajını tetikler.

### Heuristic Detection Mantığı
Bilinen bir imza (signature) eşleşmezse, dönen yanıtın anormalliğine bakarak WAF varlığını tahmin eder.

### Signature-based Analiz
Cookie isimleri (örn: \`__cfduid\`), Header bilgileri (örn: \`X-CDN\`) ve HTML body içindeki karakteristik stringleri veritabanındaki imzalarla karşılaştırır.

### False-Positive Engelleme
\`-a\` (find all) parametresi ile tek bir eşleşmede durmaz, tüm olası WAF imzalarını dener.

### Tam Manuel Payload Gönderme
WAFW00F otomatik payloadlar kullanır ancak header manipülasyonu ile manuel testler desteklenebilir.

### HTTP Header Manipulation
\`-H\` parametresi ile özel headerlar eklenerek WAF'ın header bazlı kuralları test edilir.

### WAF Arkasındaki Gerçek Sunucuyu Tespit Teknikleri
WAF tespit edildikten sonra, bypass teknikleri veya IP history servisleri kullanılarak origin server aranır.

### CDN Arkasında WAF Algılama
CDN (Content Delivery Network) genellikle WAF özelliği de sunar. WAFW00F, CDN ve WAF ayrımını yapmaya çalışır.

### Rate Limiting Bazlı Fingerprinting
Bazı WAF'lar belirli sayıda istekten sonra 429 Too Many Requests döner veya IP'yi bloklar. Bu davranış fingerprinting için kullanılır.

### Custom Request Templates
Araç, varsayılan olarak belirli request şablonları kullanır.

### Proxy Chaining
Gizlilik veya bypass için proxy zinciri kullanılabilir.

### Randomized User-Agent & Header Spoofing
WAF'ın bot korumasını atlatmak için User-Agent değiştirilir.

### HTTP Method Fuzzing (OPTIONS, PUT, TRACE)
Standart dışı HTTP metodları göndererek WAF'ın yapılandırma hataları aranır.

### WAF Bypass Detection
WAF tespit edilse bile, bazı payloadların geçip geçmediği analiz edilebilir.

### Geçersiz Paket / Malformed Request Teknikleri
HTTP standardına uymayan paketler göndererek WAF'ın parser davranışı test edilir.

### Filtering Behavior Analysis
WAF'ın isteği tamamen mi kestiği (Drop), yoksa hata sayfası mı döndüğü (Block) analiz edilir.

### Passive vs Active Fingerprinting Farkı
*   **Passive**: Sadece normal trafiği izler (WAFW00F aktif bir araçtır).
*   **Active**: Özel payloadlar göndererek tetikleme yapar.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar

**Komut:**
\`\`\`bash
wafw00f https://target.com
\`\`\`
**Açıklama:**
Hedef domain üzerinde WAF tespit ve fingerprinting işlemi yapar.
**Argüman Açıklamaları:**
*   **target.com**: Hedef URL.

**Komut:**
\`\`\`bash
wafw00f -v target.com
\`\`\`
**Açıklama:**
Verbose modda çalışarak detaylı çıktı verir.
**Argüman Açıklamaları:**
*   **-v**: Verbose level 1.

**Komut:**
\`\`\`bash
wafw00f -vv target.com
\`\`\`
**Açıklama:**
Daha detaylı verbose (HTTP request/response headerları dahil).
**Argüman Açıklamaları:**
*   **-vv**: Verbose level 2.

**Komut:**
\`\`\`bash
wafw00f -a target.com
\`\`\`
**Açıklama:**
İlk eşleşmede durmaz, tüm WAF imzalarını dener.
**Argüman Açıklamaları:**
*   **-a**: Find all WAFs.

**Komut:**
\`\`\`bash
wafw00f --list
\`\`\`
**Açıklama:**
Tespit edilebilen tüm WAF markalarını listeler.
**Argüman Açıklamaları:**
*   **--list**: List supported WAFs.

### Proxy / Network

**Komut:**
\`\`\`bash
wafw00f target.com -p http://127.0.0.1:8080
\`\`\`
**Açıklama:**
Trafiği HTTP proxy (örn: Burp Suite) üzerinden geçirir.
**Argüman Açıklamaları:**
*   **-p**: Proxy URL.

**Komut:**
\`\`\`bash
wafw00f target.com -t 10
\`\`\`
**Açıklama:**
Timeout süresini 10 saniye olarak ayarlar.
**Argüman Açıklamaları:**
*   **-t**: Timeout (seconds).

### Payload & Header Manipulation

**Komut:**
\`\`\`bash
wafw00f target.com -H "X-Origin: 127.0.0.1"
\`\`\`
**Açıklama:**
İsteklere özel header ekler.
**Argüman Açıklamaları:**
*   **-H**: Custom header.

**Komut:**
\`\`\`bash
wafw00f target.com --headers-file headers.txt
\`\`\`
**Açıklama:**
Dosyadan okunan headerları kullanır.
**Argüman Açıklamaları:**
*   **--headers-file**: Header dosyası.

### Scanning / Enumeration

**Komut:**
\`\`\`bash
wafw00f -a -v target.com
\`\`\`
**Açıklama:**
Tüm WAF'ları detaylı modda arar.

**Komut:**
\`\`\`bash
wafw00f -i targets.txt
\`\`\`
**Açıklama:**
Dosyadaki URL listesini tarar.
**Argüman Açıklamaları:**
*   **-i**: Input file.

### Output

**Komut:**
\`\`\`bash
wafw00f target.com -o output.json --format json
\`\`\`
**Açıklama:**
Sonucu JSON formatında dosyaya kaydeder.
**Argüman Açıklamaları:**
*   **-o**: Output file.
*   **--format**: Output format (json, csv, text).

**Komut:**
\`\`\`bash
wafw00f target.com --no-colors
\`\`\`
**Açıklama:**
Renkli çıktıyı kapatır (Loglama için uygun).
**Argüman Açıklamaları:**
*   **--no-colors**: Disable colors.

## 6. Gerçek Pentest Senaryoları

### CDN + WAF Arkasındaki Gerçek Server Tespiti
\`\`\`bash
wafw00f -a -v target.com
\`\`\`
**Açıklama:**
Cloudflare veya Akamai gibi CDN'lerin arkasında başka bir WAF (örn: ModSecurity) olup olmadığını anlamak için \`-a\` kullanılır.

### WAF Fingerprinting → Hangi Vendor?
\`\`\`bash
wafw00f target.com
\`\`\`
**Açıklama:**
Standart tarama ile WAF vendor (F5, Imperva, Barracuda) belirlenir ve bypass stratejisi buna göre çizilir.

### 403 Dönen Endpointlerde WAF Doğrulaması
\`\`\`bash
wafw00f target.com/admin -H "User-Agent: Googlebot"
\`\`\`
**Açıklama:**
Erişim engeli olan sayfalarda WAF'ın mı yoksa ACL'in mi engellediğini anlamak için User-Agent değiştirilerek test yapılır.

### Rate Limit Tabanlı WAF Tanıma
\`\`\`bash
# WAFW00F bu testi dolaylı yapar, manuel script ile desteklenebilir.
wafw00f target.com -v
\`\`\`
**Açıklama:**
Verbose çıktıda ardışık isteklerin bloklanıp bloklanmadığı gözlemlenir.

### Custom Payload ile WAF Davranış Testi
\`\`\`bash
wafw00f target.com -H "X-Test: <script>alert(1)</script>"
\`\`\`
**Açıklama:**
Header içine XSS payload gömerek WAF'ın header filtrelemesi test edilir.

### Proxy Üzerinden WAF Algılama (Kurumsal Ağ)
\`\`\`bash
wafw00f target.com -p http://proxy.corp.local:8080
\`\`\`
**Açıklama:**
Kurumsal proxy arkasından dış hedef test edilir.

### Tor Üzerinden WAF Detection (Stealth Mode)
\`\`\`bash
wafw00f target.com -p socks5://127.0.0.1:9050
\`\`\`
**Açıklama:**
Tor ağı kullanılarak IP gizlenir ve WAF'ın Tor IP'lerine tepkisi ölçülür.

### Header Spoofing ile WAF Bypass Araştırması
\`\`\`bash
wafw00f target.com -H "X-Forwarded-For: 127.0.0.1"
\`\`\`
**Açıklama:**
WAF'ın kaynak IP kontrolünü atlatıp atlatmadığı test edilir.

### Reflected Response Farklılıkları ile WAF Tespiti
\`\`\`bash
wafw00f -vv target.com
\`\`\`
**Açıklama:**
Normal ve zararlı istekler arasındaki response body farkları incelenir.

### Large Payload Göndererek Filtre Testi
\`\`\`bash
# WAFW00F standart payload kullanır, manuel araç gerekebilir.
\`\`\`

### Query Parameter Manipulation
\`\`\`bash
wafw00f "target.com?id=1 UNION SELECT 1"
\`\`\`
**Açıklama:**
URL parametresine SQLi payload eklenerek WAF tetiklenir.

### HTTP Method Fuzzing
\`\`\`bash
# WAFW00F otomatik yapar.
\`\`\`

### Randomized Request Pattern ile Detection
\`\`\`bash
# WAFW00F imzaları dener.
\`\`\`

### Web App Firewall Signature Karşılaştırması
\`\`\`bash
wafw00f --list
\`\`\`
**Açıklama:**
Hangi WAF'ların tespit edilebildiği kontrol edilir.

### Active vs Passive WAF Detection Süreçleri
\`\`\`bash
wafw00f target.com
\`\`\`
**Açıklama:**
Aktif tarama yaparak WAF'ı zorlar ve yanıtı analiz eder.

## 8. Best Practices (Uzman Seviye)

*   **Verbose Kullanımı**: Her testte \`-v\` veya \`-vv\` kullanarak WAF'ın hangi isteğe ne yanıt verdiğini detaylı inceleyin.
*   **Proxy Entegrasyonu**: Testleri \`-p\` ile Burp Suite üzerinden geçirerek giden istekleri ve dönen yanıtları manuel olarak da doğrulayın.
*   **False-Positive Kontrolü**: \`-a\` parametresi ile birden fazla WAF tespiti yapın, bazen CDN ve WAF iç içe olabilir.
*   **User-Agent Spoofing**: WAF'ların botları engelleme davranışını analiz etmek için farklı User-Agent'lar deneyin.
*   **Tor Timeout**: Tor kullanırken \`-t\` parametresini artırın (örn: 20-30 sn).
*   **CDN Analizi**: Cloudflare gibi CDN'lerin arkasında "Origin Server" WAF'ı olup olmadığını kontrol edin.
*   **Payload Çeşitliliği**: Sadece XSS değil, SQLi ve LFI payloadları ile de WAF'ı tetiklemeye çalışın (WAFW00F bunu otomatik yapar).
*   **Raporlama**: Otomasyon süreçleri için \`--format json\` kullanın.
*   **Bypass Planı**: WAF tespit edildikten sonra, o vendor'a özel bypass tekniklerini (örn: case sensitivity, encoding) araştırın.

## 9. Sık Yapılan Hatalar

*   **Tek Seferlik Karar**: Tek bir tarama ile "WAF yok" demek. WAF sadece belirli path'lerde (örn: /admin) aktif olabilir.
*   **Timeout İhmali**: Varsayılan timeout süresinde yanıt dönmeyen WAF'ları kaçırmak.
*   **Mimariyi Göz Ardı Etmek**: CDN'i WAF sanmak veya CDN arkasındaki asıl WAF'ı görememek.
*   **Proxy'siz Test**: Trafiği izlemeden körlemesine tarama yapmak.
*   **Doğrulamama**: WAFW00F'un "Generic" dediği WAF'ı manuel doğrulamamak.
*   **Header Spoofing Yapmamak**: WAF'ın IP whitelist/blacklist davranışını test etmemek.
*   **Findall Kullanmamak**: \`-a\` kullanmayıp ilk bulduğu WAF'ta durmak (Multi-layer korumaları kaçırmak).
*   **Format Belirtmemek**: Çıktıyı parse etmek zorlaşır.
*   **Redirect Analizi**: \`--follow-redirects\` (varsayılan olabilir ama kontrol edilmeli) kullanmayıp redirect döngüsünde kaybolmak.
`;

const contentEN = `# WAFW00F - Web Application Firewall Fingerprinting

## 1. Tool Definition
**WAFW00F** is a Python-based tool used to identify and fingerprint Web Application Firewall (WAF) products protecting a website. It analyzes responses, cookies, headers, and error messages to detect over 100 WAF products like Cloudflare, AWS WAF, Imperva, and F5 BIG-IP.

## 2. Installation
*   **Kali Linux**: \`apt install wafw00f\` (Pre-installed)
*   **GitHub**: \`git clone https://github.com/EnableSecurity/wafw00f.git\`
*   **Python**: \`pip install wafw00f\`

## 3. Basic Usage

### Basic WAF Detection
Sends simple requests to the target URL to check for WAF presence.
\`\`\`bash
wafw00f https://target.com
\`\`\`
**Argument Explanations:**
*   **https://target.com**: Target URL to test.

### Single Target Test
Tests a specific domain or IP address.
\`\`\`bash
wafw00f target.com
\`\`\`

### Multi-Target Test
Multiple targets can be tested sequentially by listing them separated by spaces.
\`\`\`bash
wafw00f target1.com target2.com
\`\`\`

### Fingerprinting
Once a WAF is detected, it attempts to identify the specific vendor and version.

### WAF Type Identification
Helps determine if the WAF is Cloud-based (e.g., Cloudflare) or On-premise (e.g., F5).

### Response Analysis
Analyzes HTTP status codes (403, 406, 501, etc.) and response bodies returned by the server.

### Testing with HTTP Methods
Measures WAF response using different methods like GET, POST, HEAD.

### Testing via Proxy
Routes traffic through a proxy server for analysis.
\`\`\`bash
wafw00f target.com -p http://127.0.0.1:8080
\`\`\`
**Argument Explanations:**
*   **-p**: Proxy URL.

## 4. Advanced Usage

### WAF Fingerprinting Methodology
WAFW00F sends a normal request followed by a malicious request and compares the server's reactions.

### Payload-based Detection
Sends XSS, SQLi, and Path Traversal payloads to trigger the WAF's blocking page or error message.

### Heuristic Detection Logic
If no known signature matches, it guesses WAF presence based on response anomalies.

### Signature-based Analysis
Compares Cookie names (e.g., \`__cfduid\`), Headers (e.g., \`X-CDN\`), and characteristic strings in the HTML body against a database of signatures.

### False-Positive Prevention
Using \`-a\` (find all) prevents stopping at the first match and tries all possible WAF signatures.

### Full Manual Payload Sending
WAFW00F uses automated payloads, but manual tests can be supported via header manipulation.

### HTTP Header Manipulation
Using \`-H\` adds custom headers to test WAF's header-based rules.

### Detecting Real Server behind WAF
After WAF detection, bypass techniques or IP history services are used to find the origin server.

### Detecting WAF behind CDN
CDNs often offer WAF features. WAFW00F attempts to distinguish between CDN and WAF.

### Rate Limiting based Fingerprinting
Some WAFs return 429 Too Many Requests or block the IP after a certain number of requests. This behavior is used for fingerprinting.

### Custom Request Templates
The tool uses specific request templates by default.

### Proxy Chaining
Proxy chains can be used for privacy or bypass.

### Randomized User-Agent & Header Spoofing
User-Agent is changed to bypass WAF's bot protection.

### HTTP Method Fuzzing (OPTIONS, PUT, TRACE)
Sends non-standard HTTP methods to find WAF configuration errors.

### WAF Bypass Detection
Even if WAF is detected, analysis can be done to see if certain payloads pass through.

### Malformed Request Techniques
Sends packets that do not conform to HTTP standards to test WAF parser behavior.

### Filtering Behavior Analysis
Analyzes whether the WAF completely drops the request (Drop) or returns an error page (Block).

### Passive vs Active Fingerprinting Difference
*   **Passive**: Only monitors normal traffic (WAFW00F is an active tool).
*   **Active**: Sends specific payloads to trigger responses.

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments

**Command:**
\`\`\`bash
wafw00f https://target.com
\`\`\`
**Description:**
Performs WAF detection and fingerprinting on the target domain.
**Argument Explanations:**
*   **target.com**: Target URL.

**Command:**
\`\`\`bash
wafw00f -v target.com
\`\`\`
**Description:**
Runs in verbose mode providing detailed output.
**Argument Explanations:**
*   **-v**: Verbose level 1.

**Command:**
\`\`\`bash
wafw00f -vv target.com
\`\`\`
**Description:**
More detailed verbose (includes HTTP request/response headers).
**Argument Explanations:**
*   **-vv**: Verbose level 2.

**Command:**
\`\`\`bash
wafw00f -a target.com
\`\`\`
**Description:**
Does not stop at first match, tries all WAF signatures.
**Argument Explanations:**
*   **-a**: Find all WAFs.

**Command:**
\`\`\`bash
wafw00f --list
\`\`\`
**Description:**
Lists all detectable WAF brands.
**Argument Explanations:**
*   **--list**: List supported WAFs.

### Proxy / Network

**Command:**
\`\`\`bash
wafw00f target.com -p http://127.0.0.1:8080
\`\`\`
**Description:**
Routes traffic through HTTP proxy (e.g., Burp Suite).
**Argument Explanations:**
*   **-p**: Proxy URL.

**Command:**
\`\`\`bash
wafw00f target.com -t 10
\`\`\`
**Description:**
Sets timeout to 10 seconds.
**Argument Explanations:**
*   **-t**: Timeout (seconds).

### Payload & Header Manipulation

**Command:**
\`\`\`bash
wafw00f target.com -H "X-Origin: 127.0.0.1"
\`\`\`
**Description:**
Adds custom header to requests.
**Argument Explanations:**
*   **-H**: Custom header.

**Command:**
\`\`\`bash
wafw00f target.com --headers-file headers.txt
\`\`\`
**Description:**
Uses headers read from a file.
**Argument Explanations:**
*   **--headers-file**: Headers file.

### Scanning / Enumeration

**Command:**
\`\`\`bash
wafw00f -a -v target.com
\`\`\`
**Description:**
Searches for all WAFs in detailed mode.

**Command:**
\`\`\`bash
wafw00f -i targets.txt
\`\`\`
**Description:**
Scans a list of URLs from a file.
**Argument Explanations:**
*   **-i**: Input file.

### Output

**Command:**
\`\`\`bash
wafw00f target.com -o output.json --format json
\`\`\`
**Description:**
Saves result to file in JSON format.
**Argument Explanations:**
*   **-o**: Output file.
*   **--format**: Output format (json, csv, text).

**Command:**
\`\`\`bash
wafw00f target.com --no-colors
\`\`\`
**Description:**
Disables colored output (Suitable for logging).
**Argument Explanations:**
*   **--no-colors**: Disable colors.

## 6. Real Pentest Scenarios

### Detecting Real Server behind CDN + WAF
\`\`\`bash
wafw00f -a -v target.com
\`\`\`
**Description:**
Uses \`-a\` to check if there is another WAF (e.g., ModSecurity) behind CDNs like Cloudflare or Akamai.

### WAF Fingerprinting → Which Vendor?
\`\`\`bash
wafw00f target.com
\`\`\`
**Description:**
Standard scan identifies WAF vendor (F5, Imperva, Barracuda) to plan bypass strategy.

### WAF Verification on 403 Endpoints
\`\`\`bash
wafw00f target.com/admin -H "User-Agent: Googlebot"
\`\`\`
**Description:**
Tests restricted pages by changing User-Agent to see if WAF or ACL is blocking.

### Rate Limit based WAF Recognition
\`\`\`bash
# WAFW00F does this indirectly, manual script might be needed.
wafw00f target.com -v
\`\`\`
**Description:**
Observe in verbose output if sequential requests get blocked.

### WAF Behavior Test with Custom Payload
\`\`\`bash
wafw00f target.com -H "X-Test: <script>alert(1)</script>"
\`\`\`
**Description:**
Embeds XSS payload in header to test WAF's header filtering.

### WAF Detection via Proxy (Corporate Network)
\`\`\`bash
wafw00f target.com -p http://proxy.corp.local:8080
\`\`\`
**Description:**
Tests external target from behind a corporate proxy.

### WAF Detection over Tor (Stealth Mode)
\`\`\`bash
wafw00f target.com -p socks5://127.0.0.1:9050
\`\`\`
**Description:**
Uses Tor network to hide IP and measure WAF reaction to Tor IPs.

### WAF Bypass Research with Header Spoofing
\`\`\`bash
wafw00f target.com -H "X-Forwarded-For: 127.0.0.1"
\`\`\`
**Description:**
Tests if WAF bypasses source IP check.

### WAF Detection via Reflected Response Differences
\`\`\`bash
wafw00f -vv target.com
\`\`\`
**Description:**
Examines response body differences between normal and malicious requests.

### Filter Test by Sending Large Payload
\`\`\`bash
# WAFW00F uses standard payloads, manual tool might be needed.
\`\`\`

### Query Parameter Manipulation
\`\`\`bash
wafw00f "target.com?id=1 UNION SELECT 1"
\`\`\`
**Description:**
Triggers WAF by adding SQLi payload to URL parameter.

### HTTP Method Fuzzing
\`\`\`bash
# WAFW00F does this automatically.
\`\`\`

### Detection with Randomized Request Pattern
\`\`\`bash
# WAFW00F tries signatures.
\`\`\`

### Web App Firewall Signature Comparison
\`\`\`bash
wafw00f --list
\`\`\`
**Description:**
Checks which WAFs can be detected.

### Active vs Passive WAF Detection Processes
\`\`\`bash
wafw00f target.com
\`\`\`
**Description:**
Performs active scan forcing WAF to respond.

## 8. Best Practices (Expert Level)

*   **Use Verbose**: Always use \`-v\` or \`-vv\` to inspect detailed WAF responses.
*   **Proxy Integration**: Route tests through Burp Suite with \`-p\` to manually verify outgoing requests and responses.
*   **False-Positive Check**: Use \`-a\` to detect multiple WAFs, sometimes CDN and WAF are layered.
*   **User-Agent Spoofing**: Try different User-Agents to analyze WAF's bot blocking behavior.
*   **Tor Timeout**: Increase \`-t\` parameter (e.g., 20-30s) when using Tor.
*   **CDN Analysis**: Check if there is an "Origin Server" WAF behind CDNs like Cloudflare.
*   **Payload Variety**: Try triggering WAF with SQLi and LFI payloads, not just XSS (WAFW00F does this automatically).
*   **Reporting**: Use \`--format json\` for automation processes.
*   **Bypass Plan**: After detection, research bypass techniques specific to that vendor (e.g., case sensitivity, encoding).

## 9. Common Mistakes

*   **One-Time Decision**: Saying "No WAF" after a single scan. WAF might be active only on specific paths (e.g., /admin).
*   **Ignoring Timeout**: Missing WAFs that don't respond within default timeout.
*   **Ignoring Architecture**: Mistaking CDN for WAF or missing the actual WAF behind CDN.
*   **No Proxy**: Scanning blindly without monitoring traffic.
*   **No Verification**: Not manually verifying a "Generic" WAF result.
*   **No Header Spoofing**: Not testing WAF's IP whitelist/blacklist behavior.
*   **Not Using Findall**: Stopping at first match without \`-a\` (Missing multi-layer protections).
*   **No Format**: Makes parsing output difficult.
*   **Redirect Analysis**: Getting lost in redirect loops by not using \`--follow-redirects\` (check if default).
`;

async function addWafw00f() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding WAFW00F cheatsheet...');

        let category = await Category.findOne({ 'name.en': 'Web Application Security' });
        if (!category) {
            console.log('Category "Web Application Security" not found, creating...');
            category = await Category.create({
                name: { tr: 'Web Uygulama Güvenliği', en: 'Web Application Security' },
                description: { tr: 'Web zafiyet tarama ve analiz araçları', en: 'Web vulnerability scanning and analysis tools' },
                slug: 'web-application-security',
                icon: 'Globe'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'WAFW00F Cheat Sheet',
                en: 'WAFW00F Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['waf', 'firewall', 'fingerprinting', 'detection', 'wafw00f', 'web-security']
        };

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'WAFW00F Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('WAFW00F cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addWafw00f();
