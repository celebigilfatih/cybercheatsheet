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

const contentTR = `# Nikto - Web Server Scanner

## 1. Araç Tanımı
**Nikto**, web sunucularını potansiyel güvenlik açıklarına, yanlış yapılandırmalara (misconfigurations), varsayılan dosyalara/programlara ve güncel olmayan sunucu yazılımlarına karşı tarayan açık kaynaklı (GPL) bir web sunucusu tarayıcısıdır. 6700'den fazla potansiyel tehlikeli dosya/programı, 1250'den fazla güncel olmayan sunucu versiyonunu ve 270'den fazla sunucuya özgü problemi tespit eder.

## 2. Kurulum
*   **Kali Linux**: \`apt install nikto\` (Varsayılan yüklü gelir)
*   **GitHub**: \`git clone https://github.com/sullo/nikto.git\`
*   **Docker**: \`docker pull sullo/nikto\`

## 3. Temel Kullanım

### Temel Web Server Scanning
Hedef sunucuya standart bir tarama başlatır.
\`\`\`bash
nikto -h target.com
\`\`\`
**Argüman Açıklamaları:**
*   **-h**: Hedef host (IP veya domain).

### Tekli Hedef Testi
Belirli bir port ve protokol ile tek bir hedefi tarar.
\`\`\`bash
nikto -h https://target.com -p 443
\`\`\`
**Argüman Açıklamaları:**
*   **-p**: Port numarası.

### Çoklu Hedef Testi
Bir metin dosyasından okunan IP/Domain listesini tarar.
\`\`\`bash
nikto -h targets.txt
\`\`\`

### Service Fingerprinting
Sunucu banner'ını ve header bilgilerini analiz ederek sunucu türünü (Apache, Nginx, IIS) ve versiyonunu belirler.

### SSL/TLS Testi
SSL sertifikasının geçerliliğini, süresini ve desteklenen protokolleri kontrol eder.
\`\`\`bash
nikto -h target.com -ssl
\`\`\`
**Argüman Açıklamaları:**
*   **-ssl**: SSL modunu zorla.

### Output Formatları
Sonuçları XML, HTML, CSV veya NBE formatında kaydeder.
\`\`\`bash
nikto -h target.com -o scan.html -Format html
\`\`\`

### Port Testi
Varsayılan olarak 80. portu tarar, ancak \`-p\` ile çoklu port (80,8080,443) belirtilebilir.

### Proxy Üzerinden Test
Trafiği bir HTTP proxy (örn: Burp Suite) üzerinden geçirir.
\`\`\`bash
nikto -h target.com -useproxy http://127.0.0.1:8080
\`\`\`

### Request/Response Analizi
Sunucunun HTTP metodlarına (GET, POST, OPTIONS vb.) verdiği yanıtları analiz eder.

### Default Misconfiguration Tespiti
Varsayılan kurulum dosyaları, örnek scriptler ve korunmasız dizinleri tespit eder.

## 4. İleri Seviye Kullanım

### Nikto Fingerprinting Metodolojisi
Nikto, sunucuya özgü dosyaları (favicon, default error pages) ve header sıralamasını analiz ederek fingerprinting yapar.

### Banner-based Detection
Server header bilgisini veritabanındaki bilinen imzalarla karşılaştırır.

### Heuristic Scanning Mantığı
Bilinmeyen dosyalar veya dizinler için sunucunun verdiği yanıt kodlarını (200, 403, 404) analiz ederek varlık tespiti yapar.

### Signature-based Analiz
Bilinen zafiyetlerin imzalarını (MD5 hash veya regex) yanıt içeriğinde arar.

### Anti-WAF/IPS Modları
\`-evasion\` parametresi ile IDS/WAF atlatma teknikleri (URL encoding, directory traversal vb.) uygulanır.

### False-Positive Engelleme
\`-404code\` veya \`-no404\` parametreleri ile sunucunun özel 404 davranışları tanımlanarak hatalı tespitler azaltılır.

### Tam Manuel Payload Gönderme
Nikto otomatik bir araçtır ancak \`-mutate\` ile payload varyasyonları oluşturulabilir.

### Custom Scan DB Tanımlama
\`db_tests\`, \`db_variables\` gibi konfigürasyon dosyaları düzenlenerek özel imzalar eklenebilir.

### Custom Plugin Kullanımı
Perl ile yazılmış özel pluginler \`plugins\` dizinine eklenerek tarama yetenekleri genişletilebilir.

### CDN Arkasındaki Gerçek Server Tespiti
Header analizleri ile CDN (Cloudflare vb.) arkasındaki origin IP sızıntılarını arar.

### SSL Cipher Enumeration
Desteklenen şifreleme algoritmalarını listeler (ancak bu iş için \`testssl.sh\` daha iyidir).

### Rate Limiting Davranışı Gözlemleme
Sunucunun çoklu isteklere verdiği tepkiyi (429 Too Many Requests) analiz eder.

### User-Agent Spoofing
\`-useragent\` ile tarayıcı veya bot taklidi yaparak erişim kontrollerini test eder.

### Header Manipulation
İsteklere özel headerlar ekleyerek sunucu davranışı test edilir.

### Evasion Teknikleri
LibWhisker kütüphanesini kullanarak paket manipülasyonu yapar (URI encoding, fake params vb.).

### Passive vs Active Detection Farkı
Nikto tamamen **aktif** bir tarayıcıdır, sunucuya binlerce istek gönderir. Gürültülüdür.

### Nikto → Burp / Proxy Chaining Entegrasyonu
Nikto trafiğini Burp Suite'e yönlendirerek (Proxy chaining) manuel analiz ve doğrulama imkanı sağlar.

### Nikto → Nmap / Masscan Veri Birleştirme Mantığı
Nmap çıktısını (\`-oG\`) Nikto'ya girdi olarak vererek sadece açık portlara tarama yapılabilir.

### Web Server Anomaly Detection Mantığı
HTTP standartlarına uymayan yanıtları (örn: HTTP 200 dönen ama hata mesajı içeren sayfalar) tespit eder.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar

**Komut:**
\`\`\`bash
nikto -h https://target.com
\`\`\`
**Açıklama:**
Hedef üzerinde temel web server scanning, misconfiguration tespiti ve fingerprinting yapar.
**Argüman Açıklamaları:**
*   **-h**: Hedef host veya URL.

**Komut:**
\`\`\`bash
nikto -h target.com -p 8080
\`\`\`
**Açıklama:**
Spesifik bir portu tarar.
**Argüman Açıklamaları:**
*   **-p**: Port numarası.

**Komut:**
\`\`\`bash
nikto -h target.com -ssl
\`\`\`
**Açıklama:**
SSL/TLS üzerinden tarama yapar.
**Argüman Açıklamaları:**
*   **-ssl**: SSL modunu zorla.

**Komut:**
\`\`\`bash
nikto -h target.com -nossl
\`\`\`
**Açıklama:**
SSL kullanımını devre dışı bırakır (HTTP zorlar).
**Argüman Açıklamaları:**
*   **-nossl**: No SSL.

**Komut:**
\`\`\`bash
nikto -h target.com -id user:pass
\`\`\`
**Açıklama:**
Basic Authentication kullanan siteler için kimlik bilgisi.
**Argüman Açıklamaları:**
*   **-id**: Basic Auth (id:pw).

**Komut:**
\`\`\`bash
nikto -h target.com -timeout 10
\`\`\`
**Açıklama:**
İstek zaman aşımı süresini ayarlar.
**Argüman Açıklamaları:**
*   **-timeout**: Saniye cinsinden timeout.

### Proxy / Network

**Komut:**
\`\`\`bash
nikto -h target.com -useproxy http://127.0.0.1:8080
\`\`\`
**Açıklama:**
Trafiği belirtilen proxy üzerinden geçirir.
**Argüman Açıklamaları:**
*   **-useproxy**: Proxy URL.

**Komut:**
\`\`\`bash
nikto -h target.com -evasion 1
\`\`\`
**Açıklama:**
IDS/WAF atlatma tekniği uygular (Random URI encoding).
**Argüman Açıklamaları:**
*   **-evasion**: Evasion tekniği (1-8 arası).

### Payload & Request Manipulation

**Komut:**
\`\`\`bash
nikto -h target.com -useragent "Mozilla/5.0"
\`\`\`
**Açıklama:**
User-Agent başlığını değiştirir.
**Argüman Açıklamaları:**
*   **-useragent**: Custom User-Agent string.

**Komut:**
\`\`\`bash
nikto -h target.com -Tuning 9
\`\`\`
**Açıklama:**
Sadece SQL Injection testlerini çalıştırır.
**Argüman Açıklamaları:**
*   **-Tuning**: Test kategorisi (1:Log, 2:Misconfig, 8:Command Exec, 9:SQLi vb.).

**Komut:**
\`\`\`bash
nikto -h target.com -mutate 3
\`\`\`
**Açıklama:**
Kullanıcı adlarını numaralandırarak (enumerate) dener.
**Argüman Açıklamaları:**
*   **-mutate**: Mutasyon tekniği.

### Scanning / Enumeration

**Komut:**
\`\`\`bash
nikto -list-plugins
\`\`\`
**Açıklama:**
Mevcut tüm pluginleri listeler.
**Argüman Açıklamaları:**
*   **-list-plugins**: Plugin listesi.

**Komut:**
\`\`\`bash
nikto -h target.com -Plugins apacheusers
\`\`\`
**Açıklama:**
Sadece 'apacheusers' pluginini çalıştırır.
**Argüman Açıklamaları:**
*   **-Plugins**: Çalıştırılacak plugin adı.

**Komut:**
\`\`\`bash
nikto -h target.com -Display V
\`\`\`
**Açıklama:**
Ekrana detaylı çıktı basar (Verbose).
**Argüman Açıklamaları:**
*   **-Display**: Çıktı modu (V: Verbose, P: Progress).

### Output

**Komut:**
\`\`\`bash
nikto -h target.com -output scan_result.html -Format html
\`\`\`
**Açıklama:**
Sonucu HTML rapor olarak kaydeder.
**Argüman Açıklamaları:**
*   **-output**: Dosya adı.
*   **-Format**: Dosya formatı.

**Komut:**
\`\`\`bash
nikto -update
\`\`\`
**Açıklama:**
Nikto veritabanını ve pluginlerini günceller.
**Argüman Açıklamaları:**
*   **-update**: Update DB.

## 6. Gerçek Pentest Senaryoları

### CDN Arkasındaki Gerçek Server Tespiti
\`\`\`bash
nikto -h target.com -Display V
\`\`\`
**Açıklama:**
Verbose modda headerları inceleyerek "X-Origin-IP" veya benzeri sızıntıları arar.

### Reverse Proxy Arkasında Fingerprinting
\`\`\`bash
nikto -h target.com -no404
\`\`\`
**Açıklama:**
Reverse proxy'nin özel hata sayfalarını ignore ederek backend sunucusunu tespit etmeye çalışır.

### WAF Karşısında Evasion + Header Manipulation
\`\`\`bash
nikto -h target.com -evasion 167 -useragent "Googlebot/2.1"
\`\`\`
**Açıklama:**
URI encoding (1), directory self-reference (6) ve case change (7) tekniklerini birleştirir ve Googlebot taklidi yapar.

### Rate-Limit Analizi ile WAF Davranışı Çözümleme
\`\`\`bash
nikto -h target.com -timeout 1
\`\`\`
**Açıklama:**
Hızlı istekler göndererek WAF'ın ne zaman blokladığını (429 veya timeout) gözlemler.

### Custom Payload ile Misconfiguration Tespiti
\`\`\`bash
nikto -h target.com -Plugins tests
\`\`\`
**Açıklama:**
Genel test pluginlerini çalıştırarak bilinen yanlış yapılandırmaları arar.

### SSL Cipher Enumeration
\`\`\`bash
nikto -h target.com -ssl
\`\`\`
**Açıklama:**
Zayıf SSL/TLS protokollerini ve cipher suite'leri raporlar.

### HSTS Kontrolü
\`\`\`bash
# Nikto otomatik kontrol eder
nikto -h target.com
\`\`\`
**Açıklama:**
Strict-Transport-Security header'ının eksikliğini raporlar.

### Default Admin Panel Discovery
\`\`\`bash
nikto -h target.com -Tuning 2
\`\`\`
**Açıklama:**
Sadece "Misconfiguration / Default File" kategorisini tarayarak admin panellerini arar.

### Directory Traversal + Nikto Plugin Analizi
\`\`\`bash
nikto -h target.com -Tuning 8
\`\`\`
**Açıklama:**
Command Execution / Traversal zafiyetlerine odaklanır.

### Basic Auth Brute-Force Davranış Testi
\`\`\`bash
nikto -h target.com -id admin:123456
\`\`\`
**Açıklama:**
Tek bir credential ile auth mekanizmasının tepkisini ölçer (Brute-force aracı değildir).

### Proxy Üzerinden Tarama (Kurumsal Ağ)
\`\`\`bash
nikto -h target.com -useproxy http://proxy.corp:8080
\`\`\`
**Açıklama:**
Kurumsal proxy arkasından dış hedefi tarar.

### Tor Üzerinden Stealth Scanning
\`\`\`bash
nikto -h target.com -useproxy socks5://127.0.0.1:9050
\`\`\`
**Açıklama:**
Tor ağı üzerinden anonim tarama (Yavaştır).

### Cookie Manipulation
\`\`\`bash
# nikto.conf dosyasında STATIC-COOKIE ayarlanabilir
\`\`\`
**Açıklama:**
Özel cookie ile (örn: session ID) tarama yapar.

### Reflected Response Farklılıkları
\`\`\`bash
nikto -h target.com -Display D
\`\`\`
**Açıklama:**
Debug modunda request/response detaylarını gösterir.

### Large Request Göndererek Throttle Testi
\`\`\`bash
# Nikto standart requestler kullanır, manuel analiz gerekir.
\`\`\`

### Weird Header Injection ile Server Behavior Analizi
\`\`\`bash
# nikto.conf üzerinden özel header eklenebilir.
\`\`\`

### Web Server Signature Spoofing Tespiti
\`\`\`bash
nikto -h target.com
\`\`\`
**Açıklama:**
Server header'ı ile gerçek davranış arasındaki tutarsızlıkları raporlar (örn: Apache diyor ama IIS hatası veriyor).

### CORS Misconfiguration Analizi
\`\`\`bash
# Nikto header analizinde CORS başlıklarını kontrol eder.
\`\`\`

### Info Leak Kontrolü
\`\`\`bash
nikto -h target.com -Tuning 3
\`\`\`
**Açıklama:**
Information Disclosure kategorisini tarar.

### Passive vs Active Fingerprinting
\`\`\`bash
nikto -h target.com
\`\`\`
**Açıklama:**
Aktif tarama yapar.

### Nikto Sonuçlarını Burp/Nmap ile Korelasyon
\`\`\`bash
nmap -p80,443 target.com -oG - | nikto -h -
\`\`\`
**Açıklama:**
Nmap çıktısını pipe ile Nikto'ya besler.

## 8. Best Practices (Uzman Seviye)

*   **Output Formatı**: Her zaman \`-o scan.html -Format html\` veya XML kullanarak sonuçları saklayın ve raporlayın.
*   **False-Positive**: Şüpheli bir bulguyu \`-Plugins\` ile spesifik olarak tekrar tarayın veya manuel doğrulayın.
*   **Custom User-Agent**: WAF veya log analizini atlatmak için \`-useragent\` ile Googlebot veya iPhone gibi davranın.
*   **CDN Analizi**: IP adresinin CDN'e mi yoksa Origin'e mi ait olduğunu Nslookup/Whois ile doğruladıktan sonra tarayın.
*   **Rate-Limit**: \`-timeout\` değerini artırarak (örn: 10s) WAF/IPS engellemelerinden kaçının.
*   **WAF Evasion**: \`-evasion\` parametrelerini (1, 2, A, B) kombinasyonlu deneyerek WAF kurallarını test edin.
*   **Proxy Kontrolü**: \`-useproxy\` ile trafiği Burp'e yönlendirip Nikto'nun ne gönderdiğini tam olarak görün.
*   **Nmap Entegrasyonu**: Önce Nmap ile açık portları bulun, sonra sadece o portlara Nikto atın (Zaman tasarrufu).
*   **Display**: \`-Display V\` ile tarama sırasında ne olduğunu görün, \`-Display P\` ile sadece ilerlemeyi izleyin.
*   **SSL**: SSL olan sitelerde \`-ssl\` parametresini manuel eklemek bazen otomatik tespitten daha sağlıklıdır.

## 9. Sık Yapılan Hatalar

*   **Default User-Agent**: Varsayılan "Nikto" user-agent'ı ile tarama yapıp WAF/IPS tarafından anında bloklanmak.
*   **SSL Unutmak**: HTTPS çalışan siteye HTTP isteği gönderip sadece 301 Redirect veya 400 Bad Request almak.
*   **404 Analizi**: Sunucunun her şeye 200 OK döndüğü durumlarda (Soft 404) Nikto'nun binlerce false positive üretmesi (\`-no404\` kullanın).
*   **Evasion İhmali**: WAF varken evasion kullanmayıp taramanın yarıda kesilmesi.
*   **Outputsuz Çalıştırma**: Terminal kapandığında sonucun kaybolması.
*   **Proxy Ayarsızlık**: Kurumsal ağda proxy belirtmeden dışarı çıkmaya çalışmak.
*   **Yanlış Plugin**: Sadece SQLi ararken tüm pluginleri çalıştırıp zaman kaybetmek (\`-Tuning 9\` kullanın).
*   **Port Hatası**: 443 portuna SSL'siz (\`-nossl\`) veya 80 portuna SSL'li (\`-ssl\`) bağlanmaya çalışmak.
*   **Redirect**: \`-followredirects\` kullanmayıp ana sayfadaki yönlendirmeyi takip etmemek.
`;

const contentEN = `# Nikto - Web Server Scanner

## 1. Tool Definition
**Nikto** is an Open Source (GPL) web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version specific problems on over 270 servers. It also checks for server configuration items such as the presence of multiple index files, HTTP server options, and will attempt to identify installed web servers and software.

## 2. Installation
*   **Kali Linux**: \`apt install nikto\` (Pre-installed)
*   **GitHub**: \`git clone https://github.com/sullo/nikto.git\`
*   **Docker**: \`docker pull sullo/nikto\`

## 3. Basic Usage

### Basic Web Server Scanning
Initiates a standard scan against the target server.
\`\`\`bash
nikto -h target.com
\`\`\`
**Argument Explanations:**
*   **-h**: Target host (IP or domain).

### Single Target Test
Scans a single target with specific port and protocol.
\`\`\`bash
nikto -h https://target.com -p 443
\`\`\`
**Argument Explanations:**
*   **-p**: Port number.

### Multi-Target Test
Scans a list of IPs/Domains read from a text file.
\`\`\`bash
nikto -h targets.txt
\`\`\`

### Service Fingerprinting
Analyzes server banners and headers to identify server type (Apache, Nginx, IIS) and version.

### SSL/TLS Test
Checks SSL certificate validity, expiration, and supported protocols.
\`\`\`bash
nikto -h target.com -ssl
\`\`\`
**Argument Explanations:**
*   **-ssl**: Force SSL mode.

### Output Formats
Saves results in XML, HTML, CSV, or NBE format.
\`\`\`bash
nikto -h target.com -o scan.html -Format html
\`\`\`

### Port Test
Scans port 80 by default, but multiple ports (80,8080,443) can be specified with \`-p\`.

### Testing via Proxy
Routes traffic through an HTTP proxy (e.g., Burp Suite).
\`\`\`bash
nikto -h target.com -useproxy http://127.0.0.1:8080
\`\`\`

### Request/Response Analysis
Analyzes server responses to HTTP methods (GET, POST, OPTIONS, etc.).

### Default Misconfiguration Detection
Detects default installation files, sample scripts, and unprotected directories.

## 4. Advanced Usage

### Nikto Fingerprinting Methodology
Nikto fingerprints by analyzing server-specific files (favicon, default error pages) and header ordering.

### Banner-based Detection
Compares Server header info against a database of known signatures.

### Heuristic Scanning Logic
Analyzes server response codes (200, 403, 404) for unknown files or directories to determine existence.

### Signature-based Analysis
Searches for signatures (MD5 hash or regex) of known vulnerabilities in response content.

### Anti-WAF/IPS Modes
Applies IDS/WAF evasion techniques (URL encoding, directory traversal, etc.) using \`-evasion\` parameter.

### False-Positive Prevention
Reduces false positives by defining server's specific 404 behavior using \`-404code\` or \`-no404\`.

### Full Manual Payload Sending
Nikto is automated, but payload variations can be created with \`-mutate\`.

### Custom Scan DB Definition
Custom signatures can be added by editing configuration files like \`db_tests\`, \`db_variables\`.

### Custom Plugin Usage
Scanning capabilities can be extended by adding custom Perl plugins to the \`plugins\` directory.

### Detecting Real Server behind CDN
Searches for origin IP leaks behind CDNs (like Cloudflare) via header analysis.

### SSL Cipher Enumeration
Lists supported encryption algorithms (though \`testssl.sh\` is better for this).

### Observing Rate Limiting Behavior
Analyzes server reaction (429 Too Many Requests) to multiple requests.

### User-Agent Spoofing
Tests access controls by mimicking browsers or bots using \`-useragent\`.

### Header Manipulation
Tests server behavior by adding custom headers to requests.

### Evasion Techniques
Uses LibWhisker library for packet manipulation (URI encoding, fake params, etc.).

### Passive vs Active Detection Difference
Nikto is a fully **active** scanner, sending thousands of requests. It is noisy.

### Nikto → Burp / Proxy Chaining Integration
Routes Nikto traffic to Burp Suite (Proxy chaining) for manual analysis and verification.

### Nikto → Nmap / Masscan Data Merging Logic
Can scan only open ports by piping Nmap output (\`-oG\`) to Nikto.

### Web Server Anomaly Detection Logic
Detects responses that do not comply with HTTP standards (e.g., pages returning HTTP 200 but containing error messages).

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments

**Command:**
\`\`\`bash
nikto -h https://target.com
\`\`\`
**Description:**
Performs basic web server scanning, misconfiguration detection, and fingerprinting on the target.
**Argument Explanations:**
*   **-h**: Target host or URL.

**Command:**
\`\`\`bash
nikto -h target.com -p 8080
\`\`\`
**Description:**
Scans a specific port.
**Argument Explanations:**
*   **-p**: Port number.

**Command:**
\`\`\`bash
nikto -h target.com -ssl
\`\`\`
**Description:**
Scans over SSL/TLS.
**Argument Explanations:**
*   **-ssl**: Force SSL mode.

**Command:**
\`\`\`bash
nikto -h target.com -nossl
\`\`\`
**Description:**
Disables SSL usage (Forces HTTP).
**Argument Explanations:**
*   **-nossl**: No SSL.

**Command:**
\`\`\`bash
nikto -h target.com -id user:pass
\`\`\`
**Description:**
Credentials for sites using Basic Authentication.
**Argument Explanations:**
*   **-id**: Basic Auth (id:pw).

**Command:**
\`\`\`bash
nikto -h target.com -timeout 10
\`\`\`
**Description:**
Sets request timeout duration.
**Argument Explanations:**
*   **-timeout**: Timeout in seconds.

### Proxy / Network

**Command:**
\`\`\`bash
nikto -h target.com -useproxy http://127.0.0.1:8080
\`\`\`
**Description:**
Routes traffic through the specified proxy.
**Argument Explanations:**
*   **-useproxy**: Proxy URL.

**Command:**
\`\`\`bash
nikto -h target.com -evasion 1
\`\`\`
**Description:**
Applies IDS/WAF evasion technique (Random URI encoding).
**Argument Explanations:**
*   **-evasion**: Evasion technique (1-8).

### Payload & Request Manipulation

**Command:**
\`\`\`bash
nikto -h target.com -useragent "Mozilla/5.0"
\`\`\`
**Description:**
Changes the User-Agent header.
**Argument Explanations:**
*   **-useragent**: Custom User-Agent string.

**Command:**
\`\`\`bash
nikto -h target.com -Tuning 9
\`\`\`
**Description:**
Runs only SQL Injection tests.
**Argument Explanations:**
*   **-Tuning**: Test category (1:Log, 2:Misconfig, 8:Command Exec, 9:SQLi, etc.).

**Command:**
\`\`\`bash
nikto -h target.com -mutate 3
\`\`\`
**Description:**
Tries to enumerate usernames.
**Argument Explanations:**
*   **-mutate**: Mutation technique.

### Scanning / Enumeration

**Command:**
\`\`\`bash
nikto -list-plugins
\`\`\`
**Description:**
Lists all available plugins.
**Argument Explanations:**
*   **-list-plugins**: Plugin list.

**Command:**
\`\`\`bash
nikto -h target.com -Plugins apacheusers
\`\`\`
**Description:**
Runs only the 'apacheusers' plugin.
**Argument Explanations:**
*   **-Plugins**: Plugin name to run.

**Command:**
\`\`\`bash
nikto -h target.com -Display V
\`\`\`
**Description:**
Prints detailed output to screen (Verbose).
**Argument Explanations:**
*   **-Display**: Output mode (V: Verbose, P: Progress).

### Output

**Command:**
\`\`\`bash
nikto -h target.com -output scan_result.html -Format html
\`\`\`
**Description:**
Saves result as HTML report.
**Argument Explanations:**
*   **-output**: Filename.
*   **-Format**: File format.

**Command:**
\`\`\`bash
nikto -update
\`\`\`
**Description:**
Updates Nikto database and plugins.
**Argument Explanations:**
*   **-update**: Update DB.

## 6. Real Pentest Scenarios

### Detecting Real Server behind CDN
\`\`\`bash
nikto -h target.com -Display V
\`\`\`
**Description:**
Looks for origin IP leaks like "X-Origin-IP" by inspecting headers in verbose mode.

### Fingerprinting behind Reverse Proxy
\`\`\`bash
nikto -h target.com -no404
\`\`\`
**Description:**
Attempts to identify backend server by ignoring reverse proxy's custom error pages.

### Evasion + Header Manipulation against WAF
\`\`\`bash
nikto -h target.com -evasion 167 -useragent "Googlebot/2.1"
\`\`\`
**Description:**
Combines URI encoding (1), directory self-reference (6), case change (7), and mimics Googlebot.

### Analyzing WAF Behavior via Rate-Limit
\`\`\`bash
nikto -h target.com -timeout 1
\`\`\`
**Description:**
Observes when WAF blocks (429 or timeout) by sending fast requests.

### Misconfiguration Detection with Custom Payload
\`\`\`bash
nikto -h target.com -Plugins tests
\`\`\`
**Description:**
Runs general test plugins to find known misconfigurations.

### SSL Cipher Enumeration
\`\`\`bash
nikto -h target.com -ssl
\`\`\`
**Description:**
Reports weak SSL/TLS protocols and cipher suites.

### HSTS Check
\`\`\`bash
# Nikto checks automatically
nikto -h target.com
\`\`\`
**Description:**
Reports missing Strict-Transport-Security header.

### Default Admin Panel Discovery
\`\`\`bash
nikto -h target.com -Tuning 2
\`\`\`
**Description:**
Scans only "Misconfiguration / Default File" category to find admin panels.

### Directory Traversal + Nikto Plugin Analysis
\`\`\`bash
nikto -h target.com -Tuning 8
\`\`\`
**Description:**
Focuses on Command Execution / Traversal vulnerabilities.

### Basic Auth Brute-Force Behavior Test
\`\`\`bash
nikto -h target.com -id admin:123456
\`\`\`
**Description:**
Measures auth mechanism reaction with a single credential (Not a brute-force tool).

### Scanning via Proxy (Corporate Network)
\`\`\`bash
nikto -h target.com -useproxy http://proxy.corp:8080
\`\`\`
**Description:**
Scans external target from behind a corporate proxy.

### Stealth Scanning over Tor
\`\`\`bash
nikto -h target.com -useproxy socks5://127.0.0.1:9050
\`\`\`
**Description:**
Anonymous scanning over Tor network (Slow).

### Cookie Manipulation
\`\`\`bash
# Can be set in nikto.conf via STATIC-COOKIE
\`\`\`
**Description:**
Scans with a specific cookie (e.g., session ID).

### Reflected Response Differences
\`\`\`bash
nikto -h target.com -Display D
\`\`\`
**Description:**
Shows request/response details in Debug mode.

### Throttle Test by Sending Large Request
\`\`\`bash
# Nikto uses standard requests, manual analysis needed.
\`\`\`

### Server Behavior Analysis with Weird Header Injection
\`\`\`bash
# Custom header can be added via nikto.conf.
\`\`\`

### Web Server Signature Spoofing Detection
\`\`\`bash
nikto -h target.com
\`\`\`
**Description:**
Reports discrepancies between Server header and actual behavior (e.g., says Apache but gives IIS error).

### CORS Misconfiguration Analysis
\`\`\`bash
# Nikto checks CORS headers in header analysis.
\`\`\`

### Info Leak Check
\`\`\`bash
nikto -h target.com -Tuning 3
\`\`\`
**Description:**
Scans Information Disclosure category.

### Passive vs Active Fingerprinting
\`\`\`bash
nikto -h target.com
\`\`\`
**Description:**
Performs active scan.

### Correlating Nikto Results with Burp/Nmap
\`\`\`bash
nmap -p80,443 target.com -oG - | nikto -h -
\`\`\`
**Description:**
Feeds Nmap output to Nikto via pipe.

## 8. Best Practices (Expert Level)

*   **Output Format**: Always save and report results using \`-o scan.html -Format html\` or XML.
*   **False-Positive**: Re-scan suspicious findings specifically with \`-Plugins\` or verify manually.
*   **Custom User-Agent**: Use \`-useragent\` to mimic Googlebot or iPhone to bypass WAF or log analysis.
*   **CDN Analysis**: Verify if IP belongs to CDN or Origin via Nslookup/Whois before scanning.
*   **Rate-Limit**: Increase \`-timeout\` (e.g., 10s) to avoid WAF/IPS blocking.
*   **WAF Evasion**: Try \`-evasion\` parameters (1, 2, A, B) in combination to test WAF rules.
*   **Proxy Check**: Use \`-useproxy\` to route traffic to Burp and see exactly what Nikto sends.
*   **Nmap Integration**: Find open ports with Nmap first, then throw Nikto only at those ports (Save time).
*   **Display**: Use \`-Display V\` to see what's happening during scan, \`-Display P\` to watch progress only.
*   **SSL**: Manually adding \`-ssl\` parameter on SSL sites is sometimes healthier than auto-detection.

## 9. Common Mistakes

*   **Default User-Agent**: Scanning with default "Nikto" user-agent and getting blocked instantly by WAF/IPS.
*   **Forgetting SSL**: Sending HTTP request to HTTPS site and getting only 301 Redirect or 400 Bad Request.
*   **404 Analysis**: Nikto generating thousands of false positives when server returns 200 OK for everything (Soft 404) (Use \`-no404\`).
*   **Ignoring Evasion**: Scanning stops halfway because evasion wasn't used when WAF is present.
*   **Running without Output**: Result is lost when terminal closes.
*   **No Proxy Setting**: Trying to go out without specifying proxy in corporate network.
*   **Wrong Plugin**: Running all plugins when looking only for SQLi, wasting time (Use \`-Tuning 9\`).
*   **Port Error**: Trying to connect to port 443 without SSL (\`-nossl\`) or port 80 with SSL (\`-ssl\`).
*   **Redirect**: Not using \`-followredirects\` and failing to follow redirection on homepage.
`;

async function addNikto() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Nikto cheatsheet...');

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
                tr: 'Nikto Cheat Sheet',
                en: 'Nikto Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['nikto', 'web-scanner', 'vulnerability', 'misconfiguration', 'fingerprinting', 'ssl']
        };

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Nikto Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Nikto cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addNikto();
