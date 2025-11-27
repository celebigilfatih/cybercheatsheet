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

const contentTR = `# Burp Suite - Web Application Security Testing

## 1. Kısa Tanım
**Burp Suite**, web uygulamalarının güvenliğini test etmek için kullanılan entegre bir platformdur. Proxy, tarayıcı, zafiyet tarayıcısı ve çeşitli manuel test araçlarını tek bir arayüzde birleştirir. HTTP/HTTPS trafiğini yakalamak, değiştirmek ve analiz etmek için endüstri standardıdır.

## 2. Kurulum
*   **Windows/Linux/macOS**: PortSwigger resmi sitesinden installer indirilir.
*   **JRE/JDK**: Burp Java tabanlıdır, genellikle kendi JRE'si ile gelir ancak sistemde güncel Java yüklü olması önerilir.
*   **Community vs Professional**:
    *   **Community**: Temel manuel test araçları (Proxy, Repeater, Intruder - kısıtlı hız). Scanner ve gelişmiş eklentiler yoktur.
    *   **Professional**: Otomatik zafiyet tarayıcısı (Scanner), sınırsız Intruder hızı, Collaborator, BApp Store (Pro eklentileri) ve proje kaydetme özelliği vardır.
*   **Proxy Sertifika Yükleme**:
    1.  Burp açıkken tarayıcıdan \`http://burp\` adresine gidin.
    2.  "CA Certificate" butonuna tıklayıp sertifikayı indirin.
    3.  Tarayıcı ayarlarına gidin (Firefox: Settings > Privacy & Security > Certificates > View Certificates).
    4.  "Import" diyerek indirilen sertifikayı yükleyin ve "Trust this CA to identify websites" seçeneğini işaretleyin.

## 3. Temel Kullanım
**Varsayılan Ayarlar:**
*   Burp varsayılan olarak \`127.0.0.1:8080\` adresinde dinler.
*   **Intercept**: \`Proxy > Intercept\` sekmesinde "Intercept is on" butonu trafiği durdurur. "Forward" ile paket sunucuya gönderilir, "Drop" ile iptal edilir.
*   **HTTP History**: \`Proxy > HTTP History\` sekmesi, geçen tüm trafiği kaydeder ve analiz etmenizi sağlar.

## 4. Modüller

### Proxy
*   **Ne işe yarar?**: Tarayıcı ile sunucu arasına girer (Man-in-the-Middle).
*   **Ne zaman kullanılır?**: Trafiği canlı izlemek ve anlık müdahale etmek için.
*   **Kritik Özellik**: Match and Replace kuralları ile otomatik değişiklik yapabilir.

### Repeater
*   **Ne işe yarar?**: Tek bir isteği tekrar tekrar değiştirip göndermeyi sağlar.
*   **Ne zaman kullanılır?**: Manuel zafiyet doğrulama (SQLi, XSS denemeleri) için.
*   **Kritik Özellik**: Sekmeli yapı ile farklı payloadları karşılaştırabilirsiniz.

### Intruder
*   **Ne işe yarar?**: Bir isteğin belirli kısımlarına (payload positions) otomatik olarak farklı veriler enjekte eder.
*   **Ne zaman kullanılır?**: Brute-force, Fuzzing, Credential Stuffing.
*   **Kritik Özellik**: 4 farklı saldırı modu (Sniper, Battering Ram, Pitchfork, Cluster Bomb).

### Scanner (Pro)
*   **Ne işe yarar?**: Otomatik zafiyet taraması yapar.
*   **Ne zaman kullanılır?**: Uygulamanın genel güvenlik duruşunu hızlıca görmek için.

### Decoder
*   **Ne işe yarar?**: Verileri encode/decode eder (URL, HTML, Base64, Hex).
*   **Ne zaman kullanılır?**: Payload hazırlarken veya şifreli veriyi çözerken.

### Comparer
*   **Ne işe yarar?**: İki istek veya yanıt arasındaki farkları (byte veya kelime bazlı) gösterir.
*   **Ne zaman kullanılır?**: Farklı kullanıcıların yanıtlarını veya başarılı/başarısız login farklarını analiz ederken.

### Extender
*   **Ne işe yarar?**: Burp'e yeni özellikler ekleyen eklentileri (BApp Store) yönetir.

### Collaborator (Pro)
*   **Ne işe yarar?**: Bant dışı (Out-of-Band) etkileşimleri tespit eder (DNS, HTTP).
*   **Ne zaman kullanılır?**: Blind SQLi, Blind XSS, SSRF testlerinde.

## 5. Yaygın Kullanımlar (İleri Seviye)

**Senaryo: XSS Test**
*   **Adımlar**: Şüpheli parametreyi Repeater'a gönderin. \`<script>alert(1)</script>\` payload'ını girin.
*   **Ayar Açıklamaları**: Yanıtta payload'ın olduğu gibi (encode edilmeden) dönüp dönmediğini kontrol edin. \`Content-Type\` header'ına dikkat edin.

**Senaryo: SQL Injection Test**
*   **Adımlar**: Parametre sonuna \`'\` ekleyin. Repeater'da 500 hatası veya veritabanı hatası dönüyor mu bakın.
*   **Ayar Açıklamaları**: \`sqlmap\` ile entegre etmek için isteği dosyaya kaydedip (\`Copy to file\`) kullanabilirsiniz.

**Senaryo: IDOR Tespiti**
*   **Adımlar**: İki farklı kullanıcının (User A, User B) oturumunu açın. User A'nın isteğini Repeater'a atın. Cookie/Token kısmını User B'ninki ile değiştirin.
*   **Ayar Açıklamaları**: Eğer User A'nın verisine User B'nin oturumuyla erişebiliyorsanız IDOR vardır.

**Senaryo: Rate Limit Bypass**
*   **Adımlar**: Intruder'a gönderin. \`X-Forwarded-For\` header'ı ekleyip değerini payload pozisyonu yapın.
*   **Ayar Açıklamaları**: IP adresini sürekli değiştirerek (1.1.1.1, 1.1.1.2...) sunucuyu kandırmayı deneyin.

**Senaryo: Auth Token Manipülasyonu**
*   **Adımlar**: Token'ı Decoder'a atın. Base64 decode edin. İçeriği (örn: \`"role": "user"\` -> \`"admin"\`) değiştirip tekrar encode edin.
*   **Ayar Açıklamaları**: İmza kontrolü yoksa (JWT None Algorithm) yetki yükseltmiş olursunuz.

**Senaryo: SSRF Tespit Adımları**
*   **Adımlar**: URL alan parametreye Collaborator linkini yapıştırın.
*   **Ayar Açıklamaları**: Collaborator Client penceresinde DNS veya HTTP isteği gelirse SSRF vardır.

**Senaryo: CSRF Test Adımları**
*   **Adımlar**: Kritik bir işlem isteğini (şifre değiştirme) sağ tıklayıp "Generate CSRF PoC" deyin.
*   **Ayar Açıklamaları**: Oluşan HTML'i başka bir tarayıcıda açıp isteğin gerçekleşip gerçekleşmediğini test edin.

**Senaryo: API Testleri**
*   **Adımlar**: JSON body içeren istekleri Repeater'da manipüle edin. HTTP metodunu (GET, POST, PUT, DELETE) değiştirin.
*   **Ayar Açıklamaları**: \`Content-Type: application/json\` başlığını koruyun.

**Senaryo: WAF Testleri**
*   **Adımlar**: Intruder kullanarak WAF bypass payload listesi (örn: Seclists) yükleyin.
*   **Ayar Açıklamaları**: Yanıt kodlarına (403 vs 200) ve boyutlarına bakarak hangi payload'ın geçtiğini analiz edin.

**Senaryo: Bruteforce (Intruder)**
*   **Adımlar**: Login isteğini Intruder'a atın. Kullanıcı adı ve şifreyi işaretleyin (Cluster Bomb modu).
*   **Ayar Açıklamaları**: Payload 1: Kullanıcı listesi, Payload 2: Şifre listesi.

**Senaryo: Endpoint Keşfi**
*   **Adımlar**: \`GET /FUZZ HTTP/1.1\` isteğini Intruder'a atın.
*   **Ayar Açıklamaları**: Yaygın dosya/dizin listesini payload olarak verin. 404 olmayan yanıtları inceleyin.

**Senaryo: Response Karşılaştırması**
*   **Adımlar**: Doğru şifre ile gelen yanıtı ve yanlış şifre ile gelen yanıtı Comparer'a gönderin.
*   **Ayar Açıklamaları**: "Words" seçeneği ile aradaki farkları (örn: "Login Failed" yazısı) bulun.

## 6. Ayarlar, Filtreler ve Parametreler

| Ayar/Parametre | Açıklama | Hangi Modülde? |
| :--- | :--- | :--- |
| **Match and Replace** | İstek/yanıt içindeki veriyi otomatik değiştirir (örn: User-Agent). | Proxy > Options |
| **Intercept Client Requests** | Hangi isteklerin durdurulacağını belirleyen kurallar. | Proxy > Options |
| **Invisible Proxying** | Proxy ayarı yapılamayan (thick client) uygulamalar için şeffaf mod. | Proxy > Options |
| **TLS Pass-through** | Belirli domainler için SSL'i açmadan (intercept etmeden) geçirir. | Proxy > Options |
| **Scope Options** | Sadece hedef domain ile çalışmak için kapsam ayarı. | Target > Scope |
| **Auto Repeater** | (Eklenti) İstekleri otomatik olarak Repeater'a kopyalar ve değiştirir. | Extender |
| **Logger++ Filters** | Gelişmiş filtreleme ile logları inceler. | Logger++ (Extender) |
| **Intruder Payload Positions** | Değişkenlerin nerede olduğunu belirler (§işaretleri§). | Intruder > Positions |
| **Request Engine** | Hız ve thread ayarları. | Intruder > Options |

## 7. Intruder Kullanımı (Derin Teknik)

*   **Payload Set Türleri**:
    *   **Simple List**: Kelime listesi.
    *   **Runtime File**: Çalışma anında dosyadan okuma (büyük listeler için).
    *   **Numbers**: Sayı aralığı (ID enumeration).
    *   **Brute Forcer**: Karakter kombinasyonları üretir.
*   **Payload Processing**: Payload enjekte edilmeden önce işlemden geçirilir (örn: Base64 encode et, Hash al, Prefix ekle).
*   **Grep - Match**: Yanıtta belirli bir ifadenin (örn: "Welcome", "Error") geçip geçmediğini kontrol eder ve sonuç tablosuna sütun ekler.
*   **Grep - Extract**: Yanıttan veri (örn: CSRF token) çekip sonraki isteklerde kullanmayı sağlar.
*   **Attack Types**:
    *   **Sniper**: Tek payload seti, sırayla her pozisyona dener.
    *   **Battering Ram**: Tek payload seti, aynı anda tüm pozisyonlara aynı veriyi koyar.
    *   **Pitchfork**: Çoklu set, setleri paralel işler (1-1, 2-2).
    *   **Cluster Bomb**: Çoklu set, tüm kombinasyonları dener (1-1, 1-2, 2-1...).
*   **Rate Limit Aşım**: "Resource Pool" ayarından "Maximum concurrent requests" düşürülür ve "Delay" eklenir.

## 8. Repeater Gelişmiş Kullanım

*   **Parametre Manipülasyonu**: GET/POST parametrelerini değiştirerek iş mantığı hatalarını arayın.
*   **Header Injection**: \`Host\`, \`Referer\`, \`X-Forwarded-For\` gibi başlıkları değiştirin.
*   **Encoding Zincirleri**: WAF atlatmak için payload'ı çift URL encode veya HTML encode yapın.
*   **Cache Poisoning**: \`X-Forwarded-Host\` gibi başlıklarla cache'i zehirlemeye çalışın.

## 9. Burp Extender & BApp Store

*   **Extender API**: Java, Python (Jython) veya Ruby (JRuby) ile kendi eklentilerinizi yazmanızı sağlar.
*   **Logger++**: Standart loglamadan çok daha gelişmiş, SQL benzeri sorgularla filtreleme yapılabilen loglayıcı.
*   **Autorize**: Otomatik IDOR testi yapar. Sizin cookie'niz ile giden istekleri, yetkisiz bir kullanıcının cookie'si ile tekrar eder.
*   **Turbo Intruder**: Çok yüksek hızlı (saniyede binlerce istek) brute-force için özel bir HTTP stack kullanır.

## 10. Burp Collaborator Kullanımı

*   **DNS/HTTP OAST**: Sunucu doğrudan yanıt dönmese bile (Blind), arka planda Collaborator sunucusuna DNS veya HTTP isteği yaparsa zafiyet doğrulanır.
*   **Blind SSRF**: Sunucunun iç ağa veya dışarıya istek atıp atmadığını test eder.
*   **Blind XSS**: Payload tetiklendiğinde (örn: admin panelinde) size bildirim gelir.

## 11. Çıktı Analizi

*   **Severity (Ciddiyet)**: High, Medium, Low, Information.
*   **Confidence (Güven)**: Certain (Kesin), Firm (Güçlü), Tentative (Olası).
*   **Reported Issue**: Zafiyetin kanıtı olan istek ve yanıtı gösterir. Scanner'ın neden zafiyet dediğini buradan anlarsınız.

## 12. En İyi Uygulamalar

*   **Scope Tanımlama**: Sadece test ettiğiniz domaini Scope'a ekleyin, "Show only in scope items" diyerek gürültüyü azaltın.
*   **Auth Cookie Koruma**: "Project Options > Sessions" altından makrolar (Macros) tanımlayarak oturum düştüğünde otomatik login olmasını sağlayın.
*   **Log Yönetimi**: Projeyi kaydetmek diskte yer kaplar, gereksiz araçların (Scanner) loglarını kapatın.

## 13. Hata ve Çözümleri

*   **Sertifika Hataları**: CA sertifikasının tarayıcıya "Authority" olarak yüklendiğinden emin olun.
*   **HTTPS Interception Sorunları**: HSTS kullanan sitelerde sertifika hatası alırsanız tarayıcı geçmişini temizleyin veya gizli sekme kullanın.
*   **Proxy Loop**: Burp'ün upstream proxy ayarlarını kontrol edin, kendi kendine yönlendirme yapmadığından emin olun.
*   **Invisible Proxy**: Mobil uygulama testlerinde, uygulama proxy ayarını desteklemiyorsa DNS yönlendirmesi ve Burp'te "Support invisible proxying" açılmalıdır.
`;

const contentEN = `# Burp Suite - Web Application Security Testing

## 1. Short Definition
**Burp Suite** is an integrated platform for performing security testing of web applications. It combines a proxy, browser, vulnerability scanner, and various manual testing tools into a single interface. It is the industry standard for intercepting, modifying, and analyzing HTTP/HTTPS traffic.

## 2. Installation
*   **Windows/Linux/macOS**: Download the installer from the official PortSwigger website.
*   **JRE/JDK**: Burp is Java-based; it usually comes with its own JRE, but having an up-to-date system Java is recommended.
*   **Community vs Professional**:
    *   **Community**: Basic manual tools (Proxy, Repeater, Intruder - throttled). No Scanner or advanced extensions.
    *   **Professional**: Automated Vulnerability Scanner, unlimited Intruder speed, Collaborator, BApp Store (Pro extensions), and project saving features.
*   **Proxy Certificate Installation**:
    1.  With Burp running, go to \`http://burp\` in your browser.
    2.  Click "CA Certificate" to download.
    3.  Go to browser settings (Firefox: Settings > Privacy & Security > Certificates > View Certificates).
    4.  Click "Import", select the downloaded certificate, and check "Trust this CA to identify websites".

## 3. Basic Usage
**Default Settings:**
*   Burp listens on \`127.0.0.1:8080\` by default.
*   **Intercept**: In \`Proxy > Intercept\`, the "Intercept is on" button halts traffic. "Forward" sends the packet to the server, "Drop" discards it.
*   **HTTP History**: \`Proxy > HTTP History\` tab logs all passing traffic for analysis.

## 4. Modules

### Proxy
*   **Function**: Sits between browser and server (Man-in-the-Middle).
*   **Usage**: To monitor live traffic and intervene instantly.
*   **Critical Feature**: Match and Replace rules for automatic modification.

### Repeater
*   **Function**: Allows modifying and resending a single request repeatedly.
*   **Usage**: Manual vulnerability verification (SQLi, XSS attempts).
*   **Critical Feature**: Tabbed interface to compare different payloads.

### Intruder
*   **Function**: Automatically injects different data into specific parts (payload positions) of a request.
*   **Usage**: Brute-force, Fuzzing, Credential Stuffing.
*   **Critical Feature**: 4 attack modes (Sniper, Battering Ram, Pitchfork, Cluster Bomb).

### Scanner (Pro)
*   **Function**: Performs automated vulnerability scanning.
*   **Usage**: To quickly assess the general security posture of the application.

### Decoder
*   **Function**: Encodes/decodes data (URL, HTML, Base64, Hex).
*   **Usage**: Preparing payloads or decoding encrypted data.

### Comparer
*   **Function**: Shows differences (byte or word level) between two requests or responses.
*   **Usage**: Analyzing responses for different users or successful/failed logins.

### Extender
*   **Function**: Manages extensions (BApp Store) that add new features to Burp.

### Collaborator (Pro)
*   **Function**: Detects Out-of-Band interactions (DNS, HTTP).
*   **Usage**: Blind SQLi, Blind XSS, SSRF testing.

## 5. Common Uses (Advanced)

**Scenario: XSS Test**
*   **Steps**: Send suspicious parameter to Repeater. Enter \`<script>alert(1)</script>\` payload.
*   **Settings**: Check if payload returns as-is (unencoded) in the response. Check \`Content-Type\` header.

**Scenario: SQL Injection Test**
*   **Steps**: Add \`'\` to the end of a parameter. Check Repeater for 500 error or DB error.
*   **Settings**: Save request to file (\`Copy to file\`) to use with \`sqlmap\`.

**Scenario: IDOR Detection**
*   **Steps**: Log in as User A and User B. Send User A's request to Repeater. Replace Cookie/Token with User B's.
*   **Settings**: If you can access User A's data with User B's session, IDOR exists.

**Scenario: Rate Limit Bypass**
*   **Steps**: Send to Intruder. Add \`X-Forwarded-For\` header and mark its value as payload position.
*   **Settings**: Try to fool the server by rotating IP addresses (1.1.1.1, 1.1.1.2...).

**Scenario: Auth Token Manipulation**
*   **Steps**: Send Token to Decoder. Base64 decode. Change content (e.g., \`"role": "user"\` -> \`"admin"\`) and re-encode.
*   **Settings**: If signature check is missing (JWT None Algorithm), you escalate privileges.

**Scenario: SSRF Detection Steps**
*   **Steps**: Paste Collaborator link into a URL-accepting parameter.
*   **Settings**: If DNS or HTTP request appears in Collaborator Client, SSRF exists.

**Scenario: CSRF Test Steps**
*   **Steps**: Right-click a critical request (password change) and select "Generate CSRF PoC".
*   **Settings**: Open generated HTML in another browser to test if the request executes.

**Scenario: API Testing**
*   **Steps**: Manipulate JSON body in Repeater. Change HTTP method (GET, POST, PUT, DELETE).
*   **Settings**: Preserve \`Content-Type: application/json\` header.

**Scenario: WAF Testing**
*   **Steps**: Use Intruder to load a WAF bypass payload list (e.g., Seclists).
*   **Settings**: Analyze response codes (403 vs 200) and sizes to see which payload passed.

**Scenario: Bruteforce (Intruder)**
*   **Steps**: Send login request to Intruder. Mark username and password (Cluster Bomb mode).
*   **Settings**: Payload 1: User list, Payload 2: Password list.

**Scenario: Endpoint Discovery**
*   **Steps**: Send \`GET /FUZZ HTTP/1.1\` to Intruder.
*   **Settings**: Use common file/directory list as payload. Inspect non-404 responses.

**Scenario: Response Comparison**
*   **Steps**: Send response with correct password and wrong password to Comparer.
*   **Settings**: Use "Words" option to find differences (e.g., "Login Failed" text).

## 6. Settings, Filters, and Parameters

| Setting/Parameter | Description | Module |
| :--- | :--- | :--- |
| **Match and Replace** | Automatically modifies data in request/response (e.g., User-Agent). | Proxy > Options |
| **Intercept Client Requests** | Rules defining which requests to halt. | Proxy > Options |
| **Invisible Proxying** | Transparent mode for non-proxy-aware (thick client) apps. | Proxy > Options |
| **TLS Pass-through** | Passes SSL for specific domains without intercepting. | Proxy > Options |
| **Scope Options** | Scope settings to work only with target domain. | Target > Scope |
| **Auto Repeater** | (Extension) Automatically copies and modifies requests to Repeater. | Extender |
| **Logger++ Filters** | Advanced filtering for log analysis. | Logger++ (Extender) |
| **Intruder Payload Positions** | Defines where variables are (§markers§). | Intruder > Positions |
| **Request Engine** | Speed and thread settings. | Intruder > Options |

## 7. Intruder Usage (Deep Technical)

*   **Payload Set Types**:
    *   **Simple List**: Wordlist.
    *   **Runtime File**: Read from file at runtime (for large lists).
    *   **Numbers**: Number range (ID enumeration).
    *   **Brute Forcer**: Generates character combinations.
*   **Payload Processing**: Process payload before injection (e.g., Base64 encode, Hash, Add Prefix).
*   **Grep - Match**: Checks if a specific string (e.g., "Welcome", "Error") exists in response and adds a column.
*   **Grep - Extract**: Extracts data (e.g., CSRF token) from response to use in subsequent requests.
*   **Attack Types**:
    *   **Sniper**: Single payload set, tries each position sequentially.
    *   **Battering Ram**: Single payload set, places same data in all positions simultaneously.
    *   **Pitchfork**: Multiple sets, processes sets in parallel (1-1, 2-2).
    *   **Cluster Bomb**: Multiple sets, tries all combinations (1-1, 1-2, 2-1...).
*   **Rate Limit Bypass**: Reduce "Maximum concurrent requests" in "Resource Pool" and add "Delay".

## 8. Repeater Advanced Usage

*   **Parameter Manipulation**: Change GET/POST parameters to find business logic errors.
*   **Header Injection**: Modify headers like \`Host\`, \`Referer\`, \`X-Forwarded-For\`.
*   **Encoding Chains**: Double URL encode or HTML encode payload to bypass WAF.
*   **Cache Poisoning**: Try to poison cache using headers like \`X-Forwarded-Host\`.

## 9. Burp Extender & BApp Store

*   **Extender API**: Allows writing custom extensions in Java, Python (Jython), or Ruby (JRuby).
*   **Logger++**: Advanced logger with SQL-like query filtering capabilities.
*   **Autorize**: Performs automatic IDOR testing. Replays your requests with an unauthorized user's cookie.
*   **Turbo Intruder**: Uses a special HTTP stack for very high-speed (thousands of rps) brute-force.

## 10. Burp Collaborator Usage

*   **DNS/HTTP OAST**: Confirms vulnerability if backend makes DNS or HTTP request to Collaborator server, even if no direct response (Blind).
*   **Blind SSRF**: Tests if server makes requests to internal network or external world.
*   **Blind XSS**: Notifications arrive when payload triggers (e.g., in admin panel).

## 11. Output Analysis

*   **Severity**: High, Medium, Low, Information.
*   **Confidence**: Certain, Firm, Tentative.
*   **Reported Issue**: Shows the request and response proving the vulnerability. Helps understand why Scanner flagged it.

## 12. Best Practices

*   **Define Scope**: Add only target domain to Scope, use "Show only in scope items" to reduce noise.
*   **Auth Cookie Protection**: Define Macros under "Project Options > Sessions" to auto-login when session drops.
*   **Log Management**: Saving project takes disk space; disable logs for unnecessary tools (Scanner).

## 13. Errors and Solutions

*   **Certificate Errors**: Ensure CA certificate is installed as "Authority" in browser.
*   **HTTPS Interception Issues**: If HSTS causes cert errors, clear browser history or use incognito.
*   **Proxy Loop**: Check Burp's upstream proxy settings, ensure no self-loop.
*   **Invisible Proxy**: For mobile app testing, if app doesn't support proxy, use DNS redirection and enable "Support invisible proxying" in Burp.
`;

async function addBurpSuite() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Burp Suite cheatsheet...');

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
                tr: 'Burp Suite Cheat Sheet',
                en: 'Burp Suite Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['burp suite', 'proxy', 'web', 'security', 'xss', 'sqli', 'intruder', 'repeater']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Burp Suite Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Burp Suite cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addBurpSuite();
