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

const contentTR = `# WhatWeb - Next Gen Web Scanner

## 1. Araç Tanımı
**WhatWeb**, web sitelerinin kullandığı teknolojileri (CMS, Web Sunucusu, JavaScript kütüphaneleri, Framework'ler, Analitik araçları vb.) tespit eden gelişmiş bir fingerprinting aracıdır. Pasif ve agresif tarama modları, plugin tabanlı yapısı ve detaylı raporlama seçenekleri ile sızma testlerinin keşif aşamasında kritik rol oynar.

## 2. Kurulum
*   **Kali Linux**: \`sudo apt install whatweb\`
*   **Github**: \`git clone https://github.com/urbanadventurer/WhatWeb.git\`
*   **Ruby Gereksinimi**: Ruby 2.0+ gerektirir.

## 3. Temel Kullanım
*   **Basit Fingerprinting**: \`whatweb target.com\` komutu ile hızlı tarama.
*   **Versiyon Tespiti**: Yazılımların sürüm numaralarını (örn: WordPress 5.8) bulur.
*   **HTTP Response Analizi**: Server header, cookie ve meta tagleri inceler.
*   **Plugin Kullanımı**: 1800+ plugin ile spesifik teknolojileri tanır.

## 4. İleri Seviye Kullanım

### Aggressive Scan (--aggression)
*   **Level 1 (Stealthy)**: Sadece bir HTTP GET isteği atar, redirectleri izler.
*   **Level 3 (Aggressive)**: Varsayılan seviye. Pluginler ekstra istekler yapabilir.
*   **Level 4 (Heavy)**: Çok sayıda istek atar, tüm pluginleri dener.

### Proxy ve TOR
*   **Proxy**: \`--proxy <host:port>\` ile trafiği yönlendirir.
*   **TOR**: Anonimlik için TOR ağı üzerinden tarama yapılabilir.

### Request Header Spoofing
*   **User-Agent**: \`--user-agent\` ile tarayıcı veya bot taklidi yapılır.
*   **Cookie**: \`--cookie\` ile oturum açmış gibi tarama yapılabilir.

### Plugin Yönetimi
*   **List**: \`--list-plugins\` ile mevcut pluginleri listeler.
*   **Info**: \`--info <plugin>\` ile plugin detaylarını gösterir.
*   **Overrides**: Plugin ayarlarını manuel değiştirmek için kullanılır.

### IDS/IPS Bypass
*   **Fragmantasyon**: Paketleri bölerek IDS atlatmaya çalışır (WhatWeb doğrudan desteklemese de proxy ile yapılabilir).
*   **Random User-Agent**: Sürekli değişen UA ile tespiti zorlaştırır.

## 5. Açıklamalı Komutlar (Geniş Liste)

**Komut:**
\`\`\`bash
whatweb target.com
\`\`\`
**Açıklama:**
Basit fingerprinting yapar, hedefte kullanılan teknolojileri tespit eder.

**Komut:**
\`\`\`bash
whatweb --aggression 3 -v target.com
\`\`\`
**Açıklama:**
Agresif modda (seviye 3) ve detaylı (verbose) çıktı ile tarama yapar.
**Argümanlar:**
*   **--aggression 3**: Tarama şiddeti (1-4).
*   **-v**: Verbose (detaylı) çıktı.

**Komut:**
\`\`\`bash
whatweb --proxy 127.0.0.1:8080 target.com
\`\`\`
**Açıklama:**
Trafiği yerel proxy (örn: Burp Suite) üzerinden geçirir.
**Argümanlar:**
*   **--proxy**: Proxy adresi.

**Komut:**
\`\`\`bash
whatweb --user-agent "Googlebot/2.1" target.com
\`\`\`
**Açıklama:**
Kendini Googlebot olarak tanıtarak tarama yapar (WAF atlatma).
**Argümanlar:**
*   **--user-agent**: User-Agent stringi.

**Komut:**
\`\`\`bash
whatweb --input targets.txt --log-xml output.xml
\`\`\`
**Açıklama:**
Dosyadan okunan hedef listesini tarar ve sonucu XML olarak kaydeder.
**Argümanlar:**
*   **--input**: Hedef listesi dosyası.
*   **--log-xml**: XML çıktı formatı.

**Komut:**
\`\`\`bash
whatweb --no-errors -t 20 target.com
\`\`\`
**Açıklama:**
Hata mesajlarını gizler ve 20 thread ile hızlı tarar.
**Argümanlar:**
*   **--no-errors**: Hataları basma.
*   **-t 20**: Thread sayısı.

**Komut:**
\`\`\`bash
whatweb --header "Authorization: Basic YWRtaW46cGFzcw==" target.com
\`\`\`
**Açıklama:**
Özel bir HTTP header (örn: Basic Auth) ekleyerek istek atar.
**Argümanlar:**
*   **--header**: Özel header ekleme.

**Komut:**
\`\`\`bash
whatweb --cookie "PHPSESSID=12345" target.com
\`\`\`
**Açıklama:**
Oturum çerezi ile tarama yapar (Login arkası analiz).
**Argümanlar:**
*   **--cookie**: Cookie verisi.

**Komut:**
\`\`\`bash
whatweb --follow-redirect=never target.com
\`\`\`
**Açıklama:**
Yönlendirmeleri (301/302) takip etmez, sadece ilk yanıtı inceler.
**Argümanlar:**
*   **--follow-redirect**: Redirect davranışı.

**Komut:**
\`\`\`bash
whatweb --list-plugins
\`\`\`
**Açıklama:**
Mevcut tüm pluginleri listeler.

**Komut:**
\`\`\`bash
whatweb --info "WordPress"
\`\`\`
**Açıklama:**
WordPress plugini hakkında bilgi verir (hangi patternleri aradığı vb.).
**Argümanlar:**
*   **--info**: Plugin bilgisi.

**Komut:**
\`\`\`bash
whatweb --plugins "wordpress,joomla" target.com
\`\`\`
**Açıklama:**
Sadece belirtilen pluginleri kullanarak tarama yapar (Hız optimizasyonu).
**Argümanlar:**
*   **--plugins**: Virgülle ayrılmış plugin listesi.

**Komut:**
\`\`\`bash
whatweb --max-redirects 5 target.com
\`\`\`
**Açıklama:**
En fazla 5 yönlendirmeyi takip eder (Sonsuz döngü önleme).
**Argümanlar:**
*   **--max-redirects**: Maksimum redirect sayısı.

**Komut:**
\`\`\`bash
whatweb --timeout 10 target.com
\`\`\`
**Açıklama:**
İstek zaman aşımını 10 saniye olarak ayarlar.
**Argümanlar:**
*   **--timeout**: Timeout süresi.

**Komut:**
\`\`\`bash
whatweb --color=never target.com
\`\`\`
**Açıklama:**
Renkli çıktıyı kapatır (Log dosyasına yazarken bozulmayı önler).
**Argümanlar:**
*   **--color**: Renk ayarı.

**Komut:**
\`\`\`bash
whatweb --log-json result.json target.com
\`\`\`
**Açıklama:**
Sonuçları JSON formatında kaydeder (Otomasyon için ideal).
**Argümanlar:**
*   **--log-json**: JSON çıktı.

**Komut:**
\`\`\`bash
whatweb --log-brief target.com
\`\`\`
**Açıklama:**
Sadece tespit edilen teknolojilerin isimlerini özet olarak basar.
**Argümanlar:**
*   **--log-brief**: Özet çıktı.

**Komut:**
\`\`\`bash
whatweb --quiet target.com
\`\`\`
**Açıklama:**
Ekrana çıktı basmaz, sadece log dosyasına yazar (Log parametresi ile kullanılmalı).
**Argümanlar:**
*   **--quiet**: Sessiz mod.

**Komut:**
\`\`\`bash
whatweb --debug target.com
\`\`\`
**Açıklama:**
Hata ayıklama modunu açar, yapılan her işlemi gösterir.
**Argümanlar:**
*   **--debug**: Debug modu.

## 6. Gerçek Pentest Senaryoları

**Senaryo: Teknoloji Tespiti ve CVE Analizi**
*   **Adımlar**: \`whatweb --log-json out.json target.com\` ile versiyonları topla. Çıktıdaki versiyonları (örn: Apache 2.4.49) CVE veritabanında arat.
*   **Amaç**: Bilinen zafiyetleri (Path Traversal vb.) hızlıca tespit etmek.

**Senaryo: WAF Tespiti**
*   **Adımlar**: \`whatweb -a 3 target.com\` çıktısında "Cloudflare", "ModSecurity" veya "F5 BIG-IP" ibarelerini ara.
*   **Amaç**: Saldırı öncesi güvenlik duvarını belirleyip bypass stratejisi geliştirmek.

**Senaryo: Şirket Saldırı Yüzeyi Envanteri**
*   **Adımlar**: Tüm subdomainleri bir dosyaya (targets.txt) koy. \`whatweb --input targets.txt --log-xml inventory.xml\` çalıştır.
*   **Amaç**: Hangi subdomainde hangi teknolojinin (eski PHP, güncel olmayan IIS vb.) çalıştığını haritalamak.

**Senaryo: Login Portal Fingerprinting**
*   **Adımlar**: \`whatweb --aggression 3 target.com/admin\`
*   **Amaç**: Admin panelinin türünü (cPanel, phpMyAdmin, WordPress Admin) belirlemek.

## 8. Best Practices (Uzman Seviye)

*   **Stealth Tarama**: IDS/IPS'i tetiklememek için \`--aggression 1\` kullanın ve istekler arasına \`--wait\` ekleyin.
*   **Plugin Optimizasyonu**: Sadece hedefle ilgili pluginleri (\`--plugins\`) seçerek tarama süresini kısaltın.
*   **Otomasyon**: Çıktıları JSON/XML alarak CI/CD pipeline'larına veya diğer araçlara (Nessus, Burp) entegre edin.
*   **User-Agent**: Bazı siteler varsayılan WhatWeb UA'sını engeller. Mutlaka \`--user-agent\` ile geçerli bir tarayıcı taklidi yapın.

## 9. Sık Yapılan Hatalar

*   **Gereksiz Aggression**: \`-a 4\` kullanıp hedefi DoS etmek veya IP'yi banlatmak.
*   **Proxy Unutmak**: Kurumsal testlerde trafiği kayıt altına almadan (Burp/Zap kullanmadan) tarama yapmak.
*   **Thread Hatası**: Çok yüksek thread sayısı ile sunucuyu yormak veya timeout hataları almak.
*   **Redirect Yanılgısı**: \`--follow-redirect\` kullanmayıp sadece "301 Moved Permanently" sayfasını taramak.
`;

const contentEN = `# WhatWeb - Next Gen Web Scanner

## 1. Tool Definition
**WhatWeb** is an advanced fingerprinting tool that identifies technologies used by websites (CMS, Web Servers, JavaScript libraries, Frameworks, Analytics tools, etc.). With passive and aggressive scanning modes, a plugin-based structure, and detailed reporting options, it plays a critical role in the reconnaissance phase of penetration testing.

## 2. Installation
*   **Kali Linux**: \`sudo apt install whatweb\`
*   **Github**: \`git clone https://github.com/urbanadventurer/WhatWeb.git\`
*   **Ruby Requirement**: Requires Ruby 2.0+.

## 3. Basic Usage
*   **Simple Fingerprinting**: \`whatweb target.com\` for a quick scan.
*   **Version Detection**: Identifies software version numbers (e.g., WordPress 5.8).
*   **HTTP Response Analysis**: Inspects server headers, cookies, and meta tags.
*   **Plugin Usage**: Recognizes specific technologies using 1800+ plugins.

## 4. Advanced Usage

### Aggressive Scan (--aggression)
*   **Level 1 (Stealthy)**: Sends only one HTTP GET request, follows redirects.
*   **Level 3 (Aggressive)**: Default level. Plugins can make extra requests.
*   **Level 4 (Heavy)**: Sends many requests, tries all plugins.

### Proxy and TOR
*   **Proxy**: Routes traffic via \`--proxy <host:port>\`.
*   **TOR**: Scan anonymously over the TOR network.

### Request Header Spoofing
*   **User-Agent**: Spoof browser or bot via \`--user-agent\`.
*   **Cookie**: Scan as an authenticated user via \`--cookie\`.

### Plugin Management
*   **List**: \`--list-plugins\` lists available plugins.
*   **Info**: \`--info <plugin>\` shows plugin details.
*   **Overrides**: Used to manually change plugin settings.

### IDS/IPS Bypass
*   **Fragmentation**: Attempts to evade IDS by splitting packets (requires proxy).
*   **Random User-Agent**: Makes detection harder by constantly changing UA.

## 5. Annotated Commands (Extended List)

**Command:**
\`\`\`bash
whatweb target.com
\`\`\`
**Description:**
Performs simple fingerprinting, identifies technologies on the target.

**Command:**
\`\`\`bash
whatweb --aggression 3 -v target.com
\`\`\`
**Description:**
Scans in aggressive mode (level 3) with verbose output.
**Arguments:**
*   **--aggression 3**: Scan intensity (1-4).
*   **-v**: Verbose output.

**Command:**
\`\`\`bash
whatweb --proxy 127.0.0.1:8080 target.com
\`\`\`
**Description:**
Routes traffic through a local proxy (e.g., Burp Suite).
**Arguments:**
*   **--proxy**: Proxy address.

**Command:**
\`\`\`bash
whatweb --user-agent "Googlebot/2.1" target.com
\`\`\`
**Description:**
Scans by identifying as Googlebot (WAF evasion).
**Arguments:**
*   **--user-agent**: User-Agent string.

**Command:**
\`\`\`bash
whatweb --input targets.txt --log-xml output.xml
\`\`\`
**Description:**
Scans a list of targets from a file and saves result as XML.
**Arguments:**
*   **--input**: Target list file.
*   **--log-xml**: XML output format.

**Command:**
\`\`\`bash
whatweb --no-errors -t 20 target.com
\`\`\`
**Description:**
Hides error messages and scans fast with 20 threads.
**Arguments:**
*   **--no-errors**: Suppress errors.
*   **-t 20**: Number of threads.

**Command:**
\`\`\`bash
whatweb --header "Authorization: Basic YWRtaW46cGFzcw==" target.com
\`\`\`
**Description:**
Sends request with a custom HTTP header (e.g., Basic Auth).
**Arguments:**
*   **--header**: Custom header.

**Command:**
\`\`\`bash
whatweb --cookie "PHPSESSID=12345" target.com
\`\`\`
**Description:**
Scans with a session cookie (Analysis behind login).
**Arguments:**
*   **--cookie**: Cookie data.

**Command:**
\`\`\`bash
whatweb --follow-redirect=never target.com
\`\`\`
**Description:**
Does not follow redirects (301/302), inspects only the first response.
**Arguments:**
*   **--follow-redirect**: Redirect behavior.

**Command:**
\`\`\`bash
whatweb --list-plugins
\`\`\`
**Description:**
Lists all available plugins.

**Command:**
\`\`\`bash
whatweb --info "WordPress"
\`\`\`
**Description:**
Shows info about the WordPress plugin (patterns looked for, etc.).
**Arguments:**
*   **--info**: Plugin info.

**Command:**
\`\`\`bash
whatweb --plugins "wordpress,joomla" target.com
\`\`\`
**Description:**
Scans using only specified plugins (Speed optimization).
**Arguments:**
*   **--plugins**: Comma-separated plugin list.

**Command:**
\`\`\`bash
whatweb --max-redirects 5 target.com
\`\`\`
**Description:**
Follows at most 5 redirects (Prevent infinite loops).
**Arguments:**
*   **--max-redirects**: Max redirect count.

**Command:**
\`\`\`bash
whatweb --timeout 10 target.com
\`\`\`
**Description:**
Sets request timeout to 10 seconds.
**Arguments:**
*   **--timeout**: Timeout duration.

**Command:**
\`\`\`bash
whatweb --color=never target.com
\`\`\`
**Description:**
Disables colored output (Prevents corruption when writing to log files).
**Arguments:**
*   **--color**: Color setting.

**Command:**
\`\`\`bash
whatweb --log-json result.json target.com
\`\`\`
**Description:**
Saves results in JSON format (Ideal for automation).
**Arguments:**
*   **--log-json**: JSON output.

**Command:**
\`\`\`bash
whatweb --log-brief target.com
\`\`\`
**Description:**
Prints only the names of detected technologies as a summary.
**Arguments:**
*   **--log-brief**: Brief output.

**Command:**
\`\`\`bash
whatweb --quiet target.com
\`\`\`
**Description:**
No screen output, writes only to log file (Must use with log parameter).
**Arguments:**
*   **--quiet**: Quiet mode.

**Command:**
\`\`\`bash
whatweb --debug target.com
\`\`\`
**Description:**
Enables debug mode, showing every operation performed.
**Arguments:**
*   **--debug**: Debug mode.

## 6. Real Pentest Scenarios

**Scenario: Tech Detection and CVE Analysis**
*   **Steps**: Collect versions with \`whatweb --log-json out.json target.com\`. Search output versions (e.g., Apache 2.4.49) in CVE database.
*   **Goal**: Quickly identify known vulnerabilities (Path Traversal, etc.).

**Scenario: WAF Detection**
*   **Steps**: Look for "Cloudflare", "ModSecurity", or "F5 BIG-IP" in \`whatweb -a 3 target.com\` output.
*   **Goal**: Identify firewall before attack to develop bypass strategy.

**Scenario: Company Attack Surface Inventory**
*   **Steps**: Put all subdomains in a file (targets.txt). Run \`whatweb --input targets.txt --log-xml inventory.xml\`.
*   **Goal**: Map which technology (old PHP, outdated IIS, etc.) runs on which subdomain.

**Scenario: Login Portal Fingerprinting**
*   **Steps**: \`whatweb --aggression 3 target.com/admin\`
*   **Goal**: Determine the type of admin panel (cPanel, phpMyAdmin, WordPress Admin).

## 8. Best Practices (Expert Level)

*   **Stealth Scan**: Use \`--aggression 1\` and add \`--wait\` between requests to avoid triggering IDS/IPS.
*   **Plugin Optimization**: Select only relevant plugins (\`--plugins\`) to shorten scan time.
*   **Automation**: Integrate JSON/XML outputs into CI/CD pipelines or other tools (Nessus, Burp).
*   **User-Agent**: Some sites block default WhatWeb UA. Always spoof a valid browser with \`--user-agent\`.

## 9. Common Mistakes

*   **Unnecessary Aggression**: Using \`-a 4\` and DoS-ing the target or getting IP banned.
*   **Forgetting Proxy**: Scanning without recording traffic (Burp/Zap) in corporate tests.
*   **Thread Error**: Using too high thread count, exhausting server or getting timeouts.
*   **Redirect Fallacy**: Not using \`--follow-redirect\` and scanning only the "301 Moved Permanently" page.
`;

async function addWhatWeb() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding WhatWeb cheatsheet...');

        // 1. Find or create the category
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
                tr: 'WhatWeb Cheat Sheet',
                en: 'WhatWeb Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['whatweb', 'fingerprinting', 'web', 'scanner', 'cms', 'version']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'WhatWeb Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('WhatWeb cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addWhatWeb();
