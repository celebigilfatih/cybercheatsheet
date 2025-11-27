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

const contentTR = `# Dirsearch - Web Path Scanner

## 3. Temel Kullanım

**Basit directory brute-force:**
\`\`\`bash
dirsearch -u https://target.com
\`\`\`
→ **-u**: Hedef URL belirtir.

**Hedef URL üzerinde varsayılan wordlist kullanımı:**
\`\`\`bash
dirsearch -u https://target.com -w /usr/share/wordlists/dirb/common.txt
\`\`\`
→ **-w**: Kullanılacak wordlist dosya yolunu belirtir.

**Status code filtreleme / match etme:**
\`\`\`bash
dirsearch -u https://target.com --exclude-status 404,500 --include-status 200,301
\`\`\`
→ **--exclude-status**: Gösterilmeyecek HTTP durum kodları.
→ **--include-status**: Sadece bu kodlara sahip yanıtları gösterir.

**Extension ekleme:**
\`\`\`bash
dirsearch -u https://target.com -e php,html,js
\`\`\`
→ **-e**: Taranacak dosya uzantıları listesi (virgülle ayrılmış).

**Proxy kullanımı:**
\`\`\`bash
dirsearch -u https://target.com --proxy http://127.0.0.1:8080
\`\`\`
→ **--proxy**: HTTP/SOCKS proxy adresi (örn: Burp Suite).

**Threads ayarı:**
\`\`\`bash
dirsearch -u https://target.com -t 50
\`\`\`
→ **-t**: Eşzamanlı istek (thread) sayısı.

**Timeout ayarı:**
\`\`\`bash
dirsearch -u https://target.com --timeout 10
\`\`\`
→ **--timeout**: İstek zaman aşımı süresi (saniye).

**Redirect handling:**
\`\`\`bash
dirsearch -u https://target.com --follow-redirects
\`\`\`
→ **--follow-redirects**: HTTP yönlendirmelerini takip eder.

**Output alma:**
\`\`\`bash
dirsearch -u https://target.com --format json -o report.json
\`\`\`
→ **--format**: Çıktı formatı (json, simple, plain, xml, md, csv).
→ **-o**: Çıktı dosya adı.

**Robots.txt ve favicon analizinin devre dışı bırakılması:**
\`\`\`bash
dirsearch -u https://target.com --no-robots-txt --no-favicon-effect
\`\`\`
→ **--no-robots-txt**: robots.txt dosyasını taramaz.
→ **--no-favicon-effect**: Favicon tabanlı analiz yapmaz.

## 4. İleri Seviye Kullanım

**Çoklu wordlist kullanımı:**
Büyük taramalarda birden fazla wordlist'i birleştirerek kapsamı genişletin. SecLists'in farklı kategorilerini (Discovery, CMS, Fuzzing) aynı anda kullanabilirsiniz.

**File extension chaining (e.g. .php,.bak,.old):**
Dosya uzantılarını zincirleme kullanarak yedek dosyaları tespit edin. Örneğin, \`index.php\` bulunduğunda \`index.php.bak\` veya \`index.php.old\` gibi varyasyonları otomatik dener.

**Recursive brute-forcing:**
Bulunan her dizin için otomatik olarak yeni bir tarama başlatır. Derinlemesine analiz için kritiktir ancak tarama süresini uzatır. \`--recursion-depth\` ile derinlik sınırlandırılmalıdır.

**Status, size, word filters:**
False positive sonuçları elemek için sadece status code yetmez. Yanıt boyutuna (\`--exclude-size\`) veya içerikteki kelime sayısına göre filtreleme yaparak daha temiz sonuçlar elde edin.

**Rate-limit bypass stratejileri:**
WAF veya IPS engellemelerini aşmak için \`--random-agent\`, \`--delay\` (istekler arası bekleme) ve \`--max-rate\` (saniyedeki maksimum istek) parametrelerini kullanın.

**Payload randomization:**
Statik istekler yerine dinamik payloadlar kullanarak güvenlik cihazlarını atlatmaya çalışın.

**Header bruteforce (–H):**
Özel başlıklar (headers) ekleyerek (örn: \`X-Forwarded-For\`) erişim kontrollerini test edin veya sunucu davranışını değiştirin.

**User-Agent rotation:**
Tek bir User-Agent yerine her istekte rastgele bir User-Agent kullanarak bot tespiti yapan sistemleri atlatın.

**HTTP method fuzzing:**
Sadece GET değil, POST, PUT, DELETE gibi metodları da deneyerek ( \`-m\` argümanı ile) farklı tepkileri ölçün.

**Dirsearch + Burp proxy workflow:**
Trafiği Burp Suite üzerinden geçirerek (\`--proxy\`) istekleri manuel inceleyin, Intruder veya Repeater'a gönderin.

**403 bypass teknikleri:**
Yasaklı (403) dizinlere erişmek için header manipülasyonu veya URL encoding tekniklerini deneyin.

**URL encoding / double encoding testleri:**
WAF kurallarını atlatmak için URL'leri encode ederek gönderin.

**Hidden admin/debug panel arama stratejileri:**
Standart wordlistler yerine admin panelleri için özelleştirilmiş listeler kullanarak gizli yönetim arayüzlerini hedefleyin.

**"Forced browsing" teknikleri:**
Sunucunun listelemediği ancak doğrudan erişilebilen kaynakları zorla tarayarak bulun.

**Cloudflare / WAF arkasındaki hedeflerde optimizasyon:**
WAF tarafından engellenmemek için thread sayısını düşürün (\`-t\`), gecikme ekleyin (\`--delay\`) ve gerçekçi User-Agent kullanın.

**Dictionary tuning (SecLists + custom wordlist):**
Hedef teknolojiye (PHP, Java, IIS vb.) uygun wordlistler seçerek tarama verimliliğini artırın.

**Parametrik dosya uzantı kombinasyonları:**
Uzantıları manuel belirtmek yerine \`--suffixes\` ile otomatik son ekler ekleyin (örn: \`.bak\`, \`~\`).

**Çok büyük domainlerde concurrency optimizasyonu:**
Büyük ölçekli taramalarda thread sayısını artırın ancak sunucuyu düşürmemek (DoS) için dikkatli olun.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

**Komut:**
\`\`\`bash
dirsearch -u https://target.com -e php,html,txt -w wordlist.txt -t 20 --timeout 5 --exclude-status 404
\`\`\`
**Açıklama:**
Standart bir web taraması. Belirtilen uzantılarla, özel wordlist kullanarak, 20 thread ile ve 404 hatalarını gizleyerek tarama yapar.

**Argüman Açıklamaları:**
*   **-u**: Hedef URL.
*   **-e**: Uzantı listesi.
*   **-w**: Wordlist yolu.
*   **-t**: Thread sayısı.
*   **--timeout**: Zaman aşımı.
*   **--exclude-status**: Hariç tutulacak durum kodu.

**Argüman Kategorileri:**

**Temel Argümanlar:**
*   **-u**: Hedef URL.
*   **-e**: Extension listesi.
*   **-w**: Wordlist.
*   **-t**: Thread sayısı.
*   **--timeout**: Timeout süresi.
*   **--exclude-status**: Hariç tutulacak HTTP status.
*   **--include-status**: Dahil edilecek status.
*   **--exclude-size**: Boyuta göre filtre.
*   **--exclude-text**: İçerik string'ine göre filtre.
*   **--exclude-regex**: Regex filtre.
*   **--follow-redirects**: Redirect takip.
*   **--full-url**: Sonuçlarda tam URL yazdır.
*   **--plain-text-report**: Output dosyası (düz metin).
*   **--json-report**: JSON çıktı.
*   **--format**: Output formatı.

**HTTP / Request Argümanları:**
*   **-H**: Özel header ekleme.
*   **--user-agent**: User-Agent belirleme.
*   **--cookie**: Cookie ekleme.
*   **--data**: POST body verisi.
*   **--method**: HTTP method seçimi.
*   **--proxy**: HTTP/SOCKS proxy.
*   **--random-agent**: Rastgele User-Agent.
*   **--auth**: Basic/Digest auth.
*   **--max-rate**: Rate limit (istek/saniye).

**Recursive & Advanced:**
*   **--recursive**: Recursive tarama.
*   **--recursion-depth**: Recursive derinliği.
*   **--recursion-status**: Recursive tetikleyecek status kodları.
*   **--scan-subdir**: Alt dizinleri tarama.
*   **--force-extensions**: Uzantıları zorla ekle.
*   **--suffixes**: Çoklu son ek testi.
*   **--skip-on-status**: Belirli statusta atla.
*   **--skip-on-regex**: Regex eşleşirse atla.
*   **--skip-on-size**: Boyut eşleşirse atla.

## 6. Gerçek Pentest Senaryoları

**Gizli admin paneli keşfi:**
\`\`\`bash
dirsearch -u https://target.com -w admin-panels.txt -e php,asp,jsp --exclude-status 404
\`\`\`
Özel admin wordlist'i ile yönetim panellerini arar.

**Backup dosyaları bulma (.bak, .old, .tar, .zip):**
\`\`\`bash
dirsearch -u https://target.com -e bak,old,tar,zip,sql --suffixes ~,.swp
\`\`\`
Yedek, arşiv ve geçici dosyaları tespit eder.

**Login panel brute-force (endpoint discovery):**
\`\`\`bash
dirsearch -u https://target.com -w login-pages.txt --include-status 200
\`\`\`
Giriş sayfalarını tespit eder.

**API endpoint mapping:**
\`\`\`bash
dirsearch -u https://api.target.com -w api-endpoints.txt -e json,xml
\`\`\`
API endpointlerini haritalandırır.

**403 forbidden bypass testleri:**
\`\`\`bash
dirsearch -u https://target.com/admin -H "X-Custom-IP-Authorization: 127.0.0.1"
\`\`\`
Header manipülasyonu ile erişim kontrollerini test eder.

**Rate-limit korumalı hedeflerde tespit:**
\`\`\`bash
dirsearch -u https://target.com --max-rate 2 --delay 1 --random-agent
\`\`\`
Yavaş ve dikkatli tarama ile rate-limit'e takılmadan ilerler.

**WAF arkasında directory brute-force optimizasyonu:**
\`\`\`bash
dirsearch -u https://target.com -t 5 --random-agent --delay 2
\`\`\`
WAF tespiti riskini azaltmak için düşük hız ve rastgele ajan kullanımı.

**Subdirectory enumeration (recursive):**
\`\`\`bash
dirsearch -u https://target.com --recursive --recursion-depth 2
\`\`\`
Bulunan dizinlerin içine de girerek tarama yapar.

**Teknoloji stack analizine göre targeted wordlist kullanımı:**
\`\`\`bash
dirsearch -u https://target.com -w php-files.txt -e php
\`\`\`
Hedef PHP kullanıyorsa sadece PHP dosyalarına odaklanır.

**Cloud / storage endpoint keşfi (AWS, GCP, Azure):**
\`\`\`bash
dirsearch -u https://target.com -w cloud-buckets.txt
\`\`\`
Açık bulut depolama alanlarını arar.

**Staging / development klasör arama:**
\`\`\`bash
dirsearch -u https://target.com -w staging.txt
\`\`\`
Geliştirme ve test ortamlarını bulur.

**Container / CI-CD pipeline izleri yakalama:**
\`\`\`bash
dirsearch -u https://target.com -w cicd.txt
\`\`\`
Jenkins, Docker, Git gibi CI/CD kalıntılarını arar.

**SPA / JS application endpoint çıkarımı:**
\`\`\`bash
dirsearch -u https://target.com -e js,map
\`\`\`
JavaScript ve kaynak haritası dosyalarını bulur.

**Gömülü panel (IoT, router firmware) keşfi:**
\`\`\`bash
dirsearch -u https://192.168.1.1 -w iot-panels.txt
\`\`\`
IoT cihazlarının yönetim arayüzlerini arar.

## 8. Best Practices (Uzman Seviye)

*   **Status filtering doğru kullanımı:** Sadece 200'e odaklanmayın, 301/302 (redirect) ve 403 (forbidden) kodları da bilgi verir.
*   **Büyük wordlistlerde doğru thread ayarı:** Çok büyük listelerde thread sayısını artırın (örn: 50-100), ancak sunucu kapasitesini göz önünde bulundurun.
*   **Blind brute-force yerine targeted fuzzing:** Hedefin teknolojisini (Wappalyzer vb. ile) belirleyip ona uygun wordlist kullanın.
*   **Rate-limit ve WAF bypass stratejileri:** Agresif taramadan kaçının, \`--random-agent\` ve \`--delay\` kullanın.
*   **Directory recursion risk analizi:** Recursion sonsuz döngüye girebilir veya çok uzun sürebilir, derinliği (\`--recursion-depth\`) sınırlayın.
*   **Proxy türevleriyle request inspection:** Şüpheli yanıtları analiz etmek için trafiği Burp Suite'e yönlendirin.
*   **Wordlist optimizasyonu:** Gereksiz girdileri temizleyin, hedefe özel kelimeler ekleyin.
*   **Extension chaining stratejileri:** Kritik dosyalar için \`.bak\`, \`.old\` gibi uzantıları zincirleme deneyin.
*   **Server signature analizine göre hedefli saldırı:** IIS için \`.asp\`, \`.aspx\`; Apache/Nginx için \`.php\` öncelikli tarayın.
*   **Output loglarını sınıflama ve işleme:** Çıktıları JSON formatında alıp (\`--json-report\`) jq gibi araçlarla analiz edin.
*   **Idle / slow server’larda timeout tuning:** Yavaş sunucular için \`--timeout\` değerini artırın.

## 9. Sık Yapılan Hatalar

*   **Çok yüksek thread kullanmak:** 429 (Too Many Requests) hatasına veya IP banlanmasına yol açar.
*   **Yanlış extension kombinasyonu:** PHP sunucuda .asp taramak zaman kaybıdır.
*   **Status filtrelerini yanlış kullanmak:** 403'leri gizlemek, potansiyel admin panellerini kaçırmanıza neden olabilir.
*   **Redirect takibini açık bırakmak:** Sonsuz döngülere veya kapsam dışı taramalara neden olabilir (dikkatli kullanılmalı).
*   **Wordlist'i hedef stack’e göre optimize etmemek:** Genel wordlistler her zaman etkili değildir.
*   **Proxy kullanmadan ham brute-force çalıştırmak:** Trafiği analiz etmeyi zorlaştırır.
*   **Recursion’u kontrolsüz açmak:** Tarama süresini katlanarak artırır.
*   **Çok fazla gereksiz sonuç:** \`--exclude-size\` veya \`--exclude-text\` kullanmamak raporu kirletir.
*   **SSL/TLS hata çıktılarının yanlış yorumlanması:** Sertifika hatalarını sunucu hatası sanmak.
`;

const contentEN = `# Dirsearch - Web Path Scanner

## 3. Basic Usage

**Simple directory brute-force:**
\`\`\`bash
dirsearch -u https://target.com
\`\`\`
→ **-u**: Specifies the target URL.

**Using default wordlist on target URL:**
\`\`\`bash
dirsearch -u https://target.com -w /usr/share/wordlists/dirb/common.txt
\`\`\`
→ **-w**: Specifies the path to the wordlist file.

**Status code filtering / matching:**
\`\`\`bash
dirsearch -u https://target.com --exclude-status 404,500 --include-status 200,301
\`\`\`
→ **--exclude-status**: HTTP status codes to exclude.
→ **--include-status**: Only show responses with these codes.

**Adding extensions:**
\`\`\`bash
dirsearch -u https://target.com -e php,html,js
\`\`\`
→ **-e**: List of file extensions to scan (comma-separated).

**Using a Proxy:**
\`\`\`bash
dirsearch -u https://target.com --proxy http://127.0.0.1:8080
\`\`\`
→ **--proxy**: HTTP/SOCKS proxy address (e.g., Burp Suite).

**Thread setting:**
\`\`\`bash
dirsearch -u https://target.com -t 50
\`\`\`
→ **-t**: Number of concurrent requests (threads).

**Timeout setting:**
\`\`\`bash
dirsearch -u https://target.com --timeout 10
\`\`\`
→ **--timeout**: Request timeout duration (seconds).

**Redirect handling:**
\`\`\`bash
dirsearch -u https://target.com --follow-redirects
\`\`\`
→ **--follow-redirects**: Follows HTTP redirects.

**Output generation:**
\`\`\`bash
dirsearch -u https://target.com --format json -o report.json
\`\`\`
→ **--format**: Output format (json, simple, plain, xml, md, csv).
→ **-o**: Output filename.

**Disabling robots.txt and favicon analysis:**
\`\`\`bash
dirsearch -u https://target.com --no-robots-txt --no-favicon-effect
\`\`\`
→ **--no-robots-txt**: Do not scan robots.txt.
→ **--no-favicon-effect**: Do not perform favicon-based analysis.

## 4. Advanced Usage

**Using multiple wordlists:**
Combine multiple wordlists to expand scope in large scans. You can use different categories of SecLists (Discovery, CMS, Fuzzing) simultaneously.

**File extension chaining (e.g. .php,.bak,.old):**
Use extension chaining to detect backup files. For example, if \`index.php\` is found, it automatically tries variations like \`index.php.bak\` or \`index.php.old\`.

**Recursive brute-forcing:**
Automatically starts a new scan for every directory found. Critical for deep analysis but increases scan time. Depth should be limited with \`--recursion-depth\`.

**Status, size, word filters:**
Status codes alone are not enough to eliminate false positives. Filter by response size (\`--exclude-size\`) or word count in content for cleaner results.

**Rate-limit bypass strategies:**
Use \`--random-agent\`, \`--delay\` (wait between requests), and \`--max-rate\` (max requests per second) to bypass WAF or IPS blocks.

**Payload randomization:**
Try to bypass security devices by using dynamic payloads instead of static requests.

**Header bruteforce (–H):**
Test access controls or modify server behavior by adding custom headers (e.g., \`X-Forwarded-For\`).

**User-Agent rotation:**
Bypass systems that detect bots by using a random User-Agent for each request instead of a single one.

**HTTP method fuzzing:**
Measure different responses by trying methods like POST, PUT, DELETE (using \`-m\` argument) in addition to GET.

**Dirsearch + Burp proxy workflow:**
Route traffic through Burp Suite (\`--proxy\`) to manually inspect requests or send them to Intruder/Repeater.

**403 bypass techniques:**
Try header manipulation or URL encoding techniques to access forbidden (403) directories.

**URL encoding / double encoding tests:**
Send URLs encoded to bypass WAF rules.

**Hidden admin/debug panel search strategies:**
Target hidden management interfaces using specialized wordlists for admin panels instead of standard ones.

**"Forced browsing" techniques:**
Find resources that are not listed by the server but are directly accessible by forcibly scanning them.

**Optimization for targets behind Cloudflare / WAF:**
Reduce thread count (\`-t\`), add delay (\`--delay\`), and use realistic User-Agents to avoid being blocked by WAF.

**Dictionary tuning (SecLists + custom wordlist):**
Increase scan efficiency by selecting wordlists appropriate for the target technology (PHP, Java, IIS, etc.).

**Parametric file extension combinations:**
Instead of manually specifying extensions, use \`--suffixes\` to automatically add suffixes (e.g., \`.bak\`, \`~\`).

**Concurrency optimization on very large domains:**
Increase thread count for large-scale scans but be careful not to crash the server (DoS).

## 5. Annotated Commands (EXTENDED LIST)

**Command:**
\`\`\`bash
dirsearch -u https://target.com -e php,html,txt -w wordlist.txt -t 20 --timeout 5 --exclude-status 404
\`\`\`
**Description:**
A standard web scan. Scans with specified extensions, using a custom wordlist, with 20 threads, hiding 404 errors.

**Argument Explanations:**
*   **-u**: Target URL.
*   **-e**: Extension list.
*   **-w**: Wordlist path.
*   **-t**: Thread count.
*   **--timeout**: Timeout.
*   **--exclude-status**: Status code to exclude.

**Argument Categories:**

**Basic Arguments:**
*   **-u**: Target URL.
*   **-e**: Extension list.
*   **-w**: Wordlist.
*   **-t**: Thread count.
*   **--timeout**: Timeout duration.
*   **--exclude-status**: HTTP status to exclude.
*   **--include-status**: Status to include.
*   **--exclude-size**: Filter by size.
*   **--exclude-text**: Filter by content string.
*   **--exclude-regex**: Regex filter.
*   **--follow-redirects**: Follow redirects.
*   **--full-url**: Print full URL in results.
*   **--plain-text-report**: Output file (plain text).
*   **--json-report**: JSON output.
*   **--format**: Output format.

**HTTP / Request Arguments:**
*   **-H**: Add custom header.
*   **--user-agent**: Set User-Agent.
*   **--cookie**: Add cookie.
*   **--data**: POST body data.
*   **--method**: Select HTTP method.
*   **--proxy**: HTTP/SOCKS proxy.
*   **--random-agent**: Random User-Agent.
*   **--auth**: Basic/Digest auth.
*   **--max-rate**: Rate limit (req/s).

**Recursive & Advanced:**
*   **--recursive**: Recursive scan.
*   **--recursion-depth**: Recursion depth.
*   **--recursion-status**: Status codes to trigger recursion.
*   **--scan-subdir**: Scan subdirectories.
*   **--force-extensions**: Force extensions.
*   **--suffixes**: Multiple suffix test.
*   **--skip-on-status**: Skip on specific status.
*   **--skip-on-regex**: Skip if regex matches.
*   **--skip-on-size**: Skip if size matches.

## 6. Real Pentest Scenarios

**Hidden admin panel discovery:**
\`\`\`bash
dirsearch -u https://target.com -w admin-panels.txt -e php,asp,jsp --exclude-status 404
\`\`\`
Searches for management panels using a custom admin wordlist.

**Finding backup files (.bak, .old, .tar, .zip):**
\`\`\`bash
dirsearch -u https://target.com -e bak,old,tar,zip,sql --suffixes ~,.swp
\`\`\`
Detects backup, archive, and temporary files.

**Login panel brute-force (endpoint discovery):**
\`\`\`bash
dirsearch -u https://target.com -w login-pages.txt --include-status 200
\`\`\`
Detects login pages.

**API endpoint mapping:**
\`\`\`bash
dirsearch -u https://api.target.com -w api-endpoints.txt -e json,xml
\`\`\`
Maps API endpoints.

**403 forbidden bypass tests:**
\`\`\`bash
dirsearch -u https://target.com/admin -H "X-Custom-IP-Authorization: 127.0.0.1"
\`\`\`
Tests access controls via header manipulation.

**Detection on rate-limited targets:**
\`\`\`bash
dirsearch -u https://target.com --max-rate 2 --delay 1 --random-agent
\`\`\`
Proceeds without hitting rate limits using slow and careful scanning.

**Directory brute-force optimization behind WAF:**
\`\`\`bash
dirsearch -u https://target.com -t 5 --random-agent --delay 2
\`\`\`
Low speed and random agent usage to reduce WAF detection risk.

**Subdirectory enumeration (recursive):**
\`\`\`bash
dirsearch -u https://target.com --recursive --recursion-depth 2
\`\`\`
Scans inside found directories as well.

**Targeted wordlist usage based on technology stack:**
\`\`\`bash
dirsearch -u https://target.com -w php-files.txt -e php
\`\`\`
Focuses only on PHP files if the target uses PHP.

**Cloud / storage endpoint discovery (AWS, GCP, Azure):**
\`\`\`bash
dirsearch -u https://target.com -w cloud-buckets.txt
\`\`\`
Searches for open cloud storage buckets.

**Staging / development folder search:**
\`\`\`bash
dirsearch -u https://target.com -w staging.txt
\`\`\`
Finds development and test environments.

**Capturing Container / CI-CD pipeline traces:**
\`\`\`bash
dirsearch -u https://target.com -w cicd.txt
\`\`\`
Searches for remnants of Jenkins, Docker, Git, etc.

**SPA / JS application endpoint extraction:**
\`\`\`bash
dirsearch -u https://target.com -e js,map
\`\`\`
Finds JavaScript and source map files.

**Embedded panel (IoT, router firmware) discovery:**
\`\`\`bash
dirsearch -u https://192.168.1.1 -w iot-panels.txt
\`\`\`
Searches for management interfaces of IoT devices.

## 8. Best Practices (Expert Level)

*   **Correct use of status filtering:** Don't just focus on 200; 301/302 (redirect) and 403 (forbidden) codes also provide information.
*   **Correct thread setting for large wordlists:** Increase thread count for very large lists (e.g., 50-100), but consider server capacity.
*   **Targeted fuzzing instead of blind brute-force:** Determine target technology (with Wappalyzer etc.) and use appropriate wordlists.
*   **Rate-limit and WAF bypass strategies:** Avoid aggressive scanning, use \`--random-agent\` and \`--delay\`.
*   **Directory recursion risk analysis:** Recursion can loop infinitely or take too long; limit depth (\`--recursion-depth\`).
*   **Request inspection with Proxy derivatives:** Route traffic to Burp Suite to analyze suspicious responses.
*   **Wordlist optimization:** Clean unnecessary entries, add target-specific words.
*   **Extension chaining strategies:** Try chaining extensions like \`.bak\`, \`.old\` for critical files.
*   **Targeted attack based on server signature:** Prioritize \`.asp\`, \`.aspx\` for IIS; \`.php\` for Apache/Nginx.
*   **Classifying and processing output logs:** Get outputs in JSON format (\`--json-report\`) and analyze with tools like jq.
*   **Timeout tuning on idle / slow servers:** Increase \`--timeout\` value for slow servers.

## 9. Common Mistakes

*   **Using too many threads:** Leads to 429 (Too Many Requests) errors or IP bans.
*   **Wrong extension combination:** Scanning for .asp on a PHP server is a waste of time.
*   **Incorrect use of status filters:** Hiding 403s might cause you to miss potential admin panels.
*   **Leaving redirect following on:** Can cause infinite loops or out-of-scope scans (use with caution).
*   **Not optimizing wordlist for target stack:** Generic wordlists are not always effective.
*   **Running raw brute-force without proxy:** Makes traffic analysis difficult.
*   **Uncontrolled recursion:** Increases scan time exponentially.
*   **Too many unnecessary results:** Not using \`--exclude-size\` or \`--exclude-text\` pollutes the report.
*   **Misinterpreting SSL/TLS error outputs:** Mistaking certificate errors for server errors.
`;

async function addDirsearch() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Dirsearch cheatsheet...');

        // 1. Find or create the category
        let category = await Category.findOne({ 'name.en': 'Web Enumeration' });
        if (!category) {
            // Fallback if "Web Enumeration" doesn't exist, though it should
            console.log('Category "Web Enumeration" not found, creating...');
            category = await Category.create({
                name: { tr: 'Web Numaralandırma', en: 'Web Enumeration' },
                description: { tr: 'Web dizin ve dosya tarama araçları', en: 'Web directory and file scanning tools' },
                slug: 'web-enumeration',
                icon: 'Globe'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Dirsearch Cheat Sheet',
                en: 'Dirsearch Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['web', 'enumeration', 'bruteforce', 'fuzzing', 'python']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Dirsearch Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Dirsearch cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addDirsearch();
