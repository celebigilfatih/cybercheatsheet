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

const contentTR = `# OWASP ZAP (Zed Attack Proxy)

## 1. Kısa Tanım
**OWASP ZAP**, web uygulamalarındaki güvenlik açıklarını bulmak için kullanılan açık kaynaklı bir sızma testi aracıdır. Proxy sunucusu olarak çalışır (Man-in-the-Middle), trafiği izler, pasif tarama ile hataları tespit eder ve aktif tarama ile saldırı simülasyonları yapar. Hem manuel testler hem de CI/CD otomasyonu için idealdir.

## 2. Kurulum
*   **Windows/Linux/macOS**: Resmi siteden installer veya paket indirilir.
*   **JDK Gereksinimi**: Java 11+ gerektirir.
*   **Docker**: \`docker pull owasp/zap2docker-stable\` ile hızlıca kurulabilir.
*   **GUI vs Daemon**:
    *   **GUI**: Görsel arayüz, manuel testler için.
    *   **Daemon**: \`-daemon\` parametresi ile arayüzsüz çalışır, API üzerinden yönetilir (Otomasyon için).
*   **Browser Sertifika**: ZAP Options > Dynamic SSL Certificates > Generate > Save. Tarayıcıya "Trusted Root CA" olarak yüklenmelidir.

## 3. Temel Kullanım
*   **Proxy Ayarları**: Varsayılan \`localhost:8080\`. Tarayıcınızı bu adrese yönlendirin.
*   **Quick Start**: URL'yi girip "Attack" butonuna basarak Spider ve Active Scan'i otomatik başlatabilirsiniz.
*   **Sites & History**: Sol panelde (Sites) ziyaret edilen domainler, alt panelde (History) istek/yanıt geçmişi görünür.
*   **Passive Scan**: Trafik akarken ZAP arka planda otomatik olarak güvenlik açıklarını (örn: eksik headerlar) analiz eder.

## 4. Modüller (AYRINTILI)

### Proxy
*   **İşlevi**: Tarayıcı ve sunucu arasındaki trafiği yakalar ve değiştirir.
*   **Kullanım**: İstekleri durdurmak (Break), değiştirmek ve tekrar göndermek için.

### Spider (Classic + AJAX)
*   **Classic Spider**: HTML linklerini takip ederek site haritasını çıkarır.
*   **AJAX Spider**: Tarayıcı motoru (Selenium/HtmlUnit) kullanarak JavaScript ile oluşturulan linkleri (DOM) keşfeder.

### Active Scan
*   **İşlevi**: Belirlenen hedeflere gerçek saldırı payloadları gönderir (SQLi, XSS vb.).
*   **Kullanım**: Zafiyet doğrulaması için. Dikkat: Hedef sisteme zarar verebilir.

### Passive Scan
*   **İşlevi**: Trafiği değiştirmeden sadece izleyerek analiz eder.
*   **Kullanım**: Bilgi sızdırma, cookie güvenliği, header analizleri.

### HUD (Heads-Up Display)
*   **İşlevi**: Test edilen web sayfasına ZAP kontrollerini (butonlar, uyarılar) enjekte eder.
*   **Kullanım**: Tarayıcıdan çıkmadan ZAP'ı yönetmek için.

### Context Management
*   **İşlevi**: Test edilecek uygulamanın sınırlarını (Scope), kullanıcılarını ve oturum yönetimini tanımlar.
*   **Kullanım**: Sadece belirli bir siteye odaklanmak ve login gerektiren alanları taramak için.

### Authentication
*   **İşlevi**: ZAP'ın siteye nasıl giriş yapacağını (Form-based, JSON-based, Script-based) belirler.

### Forced Browse
*   **İşlevi**: Wordlist kullanarak gizli dosya ve dizinleri (Dirbuster gibi) arar.

### Fuzzer
*   **İşlevi**: Bir isteğin belirli kısımlarına binlerce farklı veri (payload) gönderir.
*   **Kullanım**: Girdi doğrulama hatalarını bulmak için.

### Requester
*   **İşlevi**: İstekleri manuel olarak düzenleyip gönderme aracı (Burp Repeater benzeri).

### Scripts (Zest, Python, JS)
*   **İşlevi**: ZAP'ın yeteneklerini genişletmek için script yazma motoru.

## 5. Gelişmiş Özellikler

### Advanced Spidering
*   **Context-restricted**: Sadece tanımlanan Context içindeki linkleri tarar.
*   **Auth-aware**: Oturum düştüğünde otomatik tekrar giriş yaparak taramaya devam eder.

### Authentication & Session Management
*   **Script-based Auth**: Karmaşık login süreçleri (örn: SSO, 2FA bypass) için Zest veya Python scripti yazılabilir.
*   **Session Token Tracking**: ZAP, hangi parametrenin (Cookie, Header) oturum kimliği olduğunu öğrenir ve isteklerde bunu günceller.
*   **Forced User Mode**: Tüm isteklerin belirli bir kullanıcı (örn: Admin) oturumuyla yapılmasını zorlar.

### Active Scan Policy Tuning
*   **Attack Strength**: Saldırı yoğunluğu (Low, Medium, High, Insane). Insane modu çok gürültülüdür.
*   **Alert Threshold**: Raporlama hassasiyeti. Low yaparsanız daha çok false-positive alırsınız.
*   **Scan Optimization**: WAF arkasındaki siteler için gecikme (delay) ekleyebilir veya thread sayısını düşürebilirsiniz.

### Fuzzer Gelişmiş
*   **Recursive Fuzzing**: Bulunan her yeni dizin için tekrar fuzzing başlatır.
*   **State Management**: Fuzzing sırasında oturumun açık kalmasını sağlar.

## 6. Örnek Test Senaryoları

**Senaryo: XSS Test**
*   **Adımlar**: Active Scan politikasından sadece "Cross Site Scripting" kategorisini seçin. Hedef URL'ye sağ tıklayıp "Active Scan" başlatın.
*   **Ayarlar**: Input Vectors sekmesinden sadece URL parametrelerini ve Body'yi seçerek taramayı hızlandırın.

**Senaryo: IDOR Tespiti**
*   **Adımlar**: İki farklı kullanıcı (User A, User B) oluşturun. User A'nın isteklerini Fuzzer'a atın. ID parametresini User B'ninki ile değiştirin.
*   **Ayarlar**: Http Sender script kullanarak yanıt boyutlarını karşılaştırın.

**Senaryo: Authentication Bypass**
*   **Adımlar**: Forced Browse ile \`/admin\`, \`/dashboard\` gibi dizinleri tarayın.
*   **Ayarlar**: Varsayılan wordlist yerine özel bir wordlist yükleyin.

**Senaryo: API Güvenlik Testi**
*   **Adımlar**: "Import an OpenAPI Definition from URL" eklentisi ile Swagger/OpenAPI dosyasını yükleyin. ZAP tüm endpointleri otomatik tanır.
*   **Ayarlar**: API scan için özel Active Scan kurallarını (örn: SQLi, Mass Assignment) seçin.

**Senaryo: CSRF Analizi**
*   **Adımlar**: Anti-CSRF token (örn: \`_csrf\`) kullanan bir form bulun. Options > Anti CSRF Tokens menüsüne token adını ekleyin.
*   **Ayarlar**: ZAP artık bu token'ı otomatik yakalayıp isteklerde güncelleyecektir.

## 7. ZAP CLI & Daemon Mode

**Headless Scanning (Otomasyon):**
\`\`\`bash
./zap.sh -daemon -port 8080 -config api.key=12345
\`\`\`
*   **-daemon**: Arayüzsüz mod.
*   **-config api.key**: API erişimi için güvenlik anahtarı.

**Active Scan Başlatma (API):**
\`\`\`bash
curl "http://localhost:8080/JSON/ascan/action/scan/?apikey=12345&url=http://target.com&recurse=true"
\`\`\`
API üzerinden tarama başlatır.

**Rapor Export (CLI):**
\`\`\`bash
./zap.sh -cmd -quickurl http://target.com -quickout report.html
\`\`\`
Hızlı tarama yapıp raporu kaydeder ve kapanır.

## 8. Raporlama
*   **Formatlar**: HTML (insan için), XML/JSON (makine/parser için).
*   **Risk/Confidence**:
    *   **Risk**: High, Medium, Low, Informational.
    *   **Confidence**: False Positive, Low, Medium, High, Confirmed.
*   **Alert Filtering**: Context ayarlarından gereksiz uyarıları (örn: Informational) rapordan hariç tutabilirsiniz.

## 9. En İyi Uygulamalar
*   **Context Kullanımı**: Siteyi mutlaka Context'e ekleyin ve Regex ile sınırlarını (Include/Exclude) belirleyin.
*   **Login Tanımlama**: Active Scan yapmadan önce Authentication ayarlarını yapın ve "Logged in" durumunu doğrulayın (Flag as Context > Auth Logged-in indicator).
*   **Policy Optimizasyonu**: Her taramada tüm kuralları çalıştırmayın. Teknolojiye özel (örn: sadece MySQL ve PHP) politika oluşturun.
*   **Proxy Loop Önleme**: ZAP'ı başka bir proxy'ye (örn: Burp) bağlarken portların çakışmadığından emin olun.

## 10. Sık Yapılan Hatalar
*   **Contextsiz Tarama**: Tüm interneti taramaya çalışmak (Scope dışına çıkmak).
*   **Login Olmadan Tarama**: Sadece login sayfasını ve halka açık sayfaları tarayıp, uygulamanın asıl kısmını kaçırmak.
*   **Spider Limitlerini Ayarlamamak**: Sonsuz döngüye giren sayfalarda taramanın bitmemesi (Max Depth ve Max Children ayarlanmalı).
*   **API Schema Eklememek**: API testlerinde endpointleri manuel bulmaya çalışmak yerine Swagger/WSDL import etmemek.
`;

const contentEN = `# OWASP ZAP (Zed Attack Proxy)

## 1. Short Definition
**OWASP ZAP** is an open-source penetration testing tool used to find vulnerabilities in web applications. It acts as a Proxy server (Man-in-the-Middle), monitors traffic, detects issues via passive scanning, and simulates attacks via active scanning. It is ideal for both manual testing and CI/CD automation.

## 2. Installation
*   **Windows/Linux/macOS**: Download installer or package from official site.
*   **JDK Requirement**: Requires Java 11+.
*   **Docker**: Quickly install via \`docker pull owasp/zap2docker-stable\`.
*   **GUI vs Daemon**:
    *   **GUI**: Visual interface for manual testing.
    *   **Daemon**: Runs without UI using \`-daemon\`, managed via API (for Automation).
*   **Browser Certificate**: ZAP Options > Dynamic SSL Certificates > Generate > Save. Must be installed in browser as "Trusted Root CA".

## 3. Basic Usage
*   **Proxy Settings**: Default is \`localhost:8080\`. Configure your browser to use this.
*   **Quick Start**: Enter URL and hit "Attack" to automatically start Spider and Active Scan.
*   **Sites & History**: Left panel (Sites) shows visited domains, bottom panel (History) shows request/response log.
*   **Passive Scan**: Automatically analyzes security issues (e.g., missing headers) in the background while traffic flows.

## 4. Modules (DETAILED)

### Proxy
*   **Function**: Intercepts and modifies traffic between browser and server.
*   **Usage**: To Break, modify, and resend requests.

### Spider (Classic + AJAX)
*   **Classic Spider**: Crawls HTML links to build a site map.
*   **AJAX Spider**: Uses a browser engine (Selenium/HtmlUnit) to discover JavaScript-generated links (DOM).

### Active Scan
*   **Function**: Sends real attack payloads (SQLi, XSS, etc.) to defined targets.
*   **Usage**: Vulnerability verification. Caution: Can damage the target system.

### Passive Scan
*   **Function**: Analyzes traffic by monitoring only, without modification.
*   **Usage**: Information leakage, cookie security, header analysis.

### HUD (Heads-Up Display)
*   **Function**: Injects ZAP controls (buttons, alerts) into the tested web page.
*   **Usage**: To manage ZAP without leaving the browser.

### Context Management
*   **Function**: Defines boundaries (Scope), users, and session management for the application under test.
*   **Usage**: To focus on a specific site and scan areas requiring login.

### Authentication
*   **Function**: Defines how ZAP logs into the site (Form-based, JSON-based, Script-based).

### Forced Browse
*   **Function**: Searches for hidden files and directories using wordlists (like Dirbuster).

### Fuzzer
*   **Function**: Sends thousands of different data payloads to specific parts of a request.
*   **Usage**: To find input validation errors.

### Requester
*   **Function**: Tool for manually editing and sending requests (similar to Burp Repeater).

### Scripts (Zest, Python, JS)
*   **Function**: Scripting engine to extend ZAP's capabilities.

## 5. Advanced Features

### Advanced Spidering
*   **Context-restricted**: Scans only links within the defined Context.
*   **Auth-aware**: Automatically re-logins and continues scanning when session drops.

### Authentication & Session Management
*   **Script-based Auth**: Zest or Python scripts can be written for complex login processes (e.g., SSO, 2FA bypass).
*   **Session Token Tracking**: ZAP learns which parameter (Cookie, Header) is the session ID and updates it in requests.
*   **Forced User Mode**: Forces all requests to be made with a specific user's (e.g., Admin) session.

### Active Scan Policy Tuning
*   **Attack Strength**: Intensity of attack (Low, Medium, High, Insane). Insane mode is very noisy.
*   **Alert Threshold**: Reporting sensitivity. Low results in more false positives.
*   **Scan Optimization**: Add delay or reduce threads for sites behind WAF.

### Advanced Fuzzer
*   **Recursive Fuzzing**: Starts fuzzing again for every new directory found.
*   **State Management**: Keeps the session active during fuzzing.

## 6. Example Test Scenarios

**Scenario: XSS Test**
*   **Steps**: Select only "Cross Site Scripting" category in Active Scan policy. Right-click target URL and start "Active Scan".
*   **Settings**: Speed up scan by selecting only URL parameters and Body in Input Vectors tab.

**Scenario: IDOR Detection**
*   **Steps**: Create two users (User A, User B). Send User A's requests to Fuzzer. Replace ID parameter with User B's.
*   **Settings**: Use Http Sender script to compare response sizes.

**Scenario: Authentication Bypass**
*   **Steps**: Scan directories like \`/admin\`, \`/dashboard\` using Forced Browse.
*   **Settings**: Load a custom wordlist instead of the default one.

**Scenario: API Security Test**
*   **Steps**: Load Swagger/OpenAPI file with "Import an OpenAPI Definition from URL" add-on. ZAP automatically recognizes endpoints.
*   **Settings**: Select API-specific Active Scan rules (e.g., SQLi, Mass Assignment).

**Scenario: CSRF Analysis**
*   **Steps**: Find a form using Anti-CSRF token (e.g., \`_csrf\`). Add token name to Options > Anti CSRF Tokens.
*   **Settings**: ZAP will now automatically capture and update this token in requests.

## 7. ZAP CLI & Daemon Mode

**Headless Scanning (Automation):**
\`\`\`bash
./zap.sh -daemon -port 8080 -config api.key=12345
\`\`\`
*   **-daemon**: No-GUI mode.
*   **-config api.key**: Security key for API access.

**Start Active Scan (API):**
\`\`\`bash
curl "http://localhost:8080/JSON/ascan/action/scan/?apikey=12345&url=http://target.com&recurse=true"
\`\`\`
Starts scan via API.

**Export Report (CLI):**
\`\`\`bash
./zap.sh -cmd -quickurl http://target.com -quickout report.html
\`\`\`
Performs quick scan, saves report, and exits.

## 8. Reporting
*   **Formats**: HTML (for humans), XML/JSON (for machines/parsers).
*   **Risk/Confidence**:
    *   **Risk**: High, Medium, Low, Informational.
    *   **Confidence**: False Positive, Low, Medium, High, Confirmed.
*   **Alert Filtering**: Exclude unnecessary alerts (e.g., Informational) from report via Context settings.

## 9. Best Practices
*   **Use Context**: Always add the site to a Context and define boundaries (Include/Exclude) with Regex.
*   **Define Login**: Configure Authentication settings and verify "Logged in" state (Flag as Context > Auth Logged-in indicator) before Active Scan.
*   **Policy Optimization**: Don't run all rules every time. Create technology-specific (e.g., MySQL and PHP only) policies.
*   **Prevent Proxy Loop**: Ensure ports don't clash when chaining ZAP with another proxy (e.g., Burp).

## 10. Common Mistakes
*   **Scanning without Context**: Trying to scan the entire internet (going out of Scope).
*   **Scanning without Login**: Scanning only the login page and public pages, missing the actual application.
*   **Not Setting Spider Limits**: Scan never finishing due to infinite loops (Max Depth and Max Children must be set).
*   **Not Adding API Schema**: Trying to find endpoints manually instead of importing Swagger/WSDL for API tests.
`;

async function addZap() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding OWASP ZAP cheatsheet...');

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
                tr: 'OWASP ZAP Cheat Sheet',
                en: 'OWASP ZAP Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['owasp', 'zap', 'proxy', 'web', 'security', 'scanner', 'spider', 'fuzzer']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'OWASP ZAP Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('OWASP ZAP cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addZap();
