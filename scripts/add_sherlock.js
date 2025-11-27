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

const contentTR = `# Sherlock - OSINT Username Enumeration Tool

## 1. Araç Tanımı
**Sherlock**, verilen bir kullanıcı adının yüzlerce platformda kullanım durumunu tespit eden, OSINT tabanlı username enumeration aracıdır. Kullanıcı adı kullanılma durumu, HTTP response code, redirect davranışı, error mesajları ve pattern eşleşmelerine göre analiz edilir.

## 2. Kurulum
*   **Kali Linux**: \`sudo apt install sherlock\`
*   **Source**: \`git clone https://github.com/sherlock-project/sherlock.git && cd sherlock && python3 -m pip install -r requirements.txt\`

## 3. Temel Kullanım

### Tek Kullanıcı Sorgulama
Belirtilen kullanıcı adını tüm desteklenen sitelerde arar.
\`\`\`bash
sherlock user123
\`\`\`
**Argüman Açıklamaları:**
*   **user123**: Sorgulanacak kullanıcı adı.

### Sadece Bulunanları Göster
Bulunamayan siteleri gizleyerek çıktıyı temizler.
\`\`\`bash
sherlock user123 --print-found
\`\`\`
**Argüman Açıklamaları:**
*   **--print-found**: Sadece pozitif sonuçları yazdır.

### Çıktıyı Klasöre Kaydet
Sonuçları belirtilen klasöre metin dosyası olarak kaydeder.
\`\`\`bash
sherlock user123 --folderoutput results/
\`\`\`
**Argüman Açıklamaları:**
*   **--folderoutput**: Çıktı klasörü.

### Timeout Ayarı
Yavaş siteler için bekleme süresini artırır (varsayılan değer bazen düşüktür).
\`\`\`bash
sherlock user123 --timeout 15
\`\`\`
**Argüman Açıklamaları:**
*   **--timeout**: Saniye cinsinden zaman aşımı.

### Tor Üzerinden Tarama
İstekleri Tor ağı üzerinden göndererek gizlilik sağlar.
\`\`\`bash
sherlock user123 --tor
\`\`\`
**Argüman Açıklamaları:**
*   **--tor**: Tor proxy kullanımı.

### Belirli Bir Sitede Arama
Sadece tek bir platformda sorgulama yapar.
\`\`\`bash
sherlock user123 --site instagram
\`\`\`
**Argüman Açıklamaları:**
*   **--site**: Site adı.

### CSV Çıktısı
Sonuçları analiz için CSV formatında kaydeder.
\`\`\`bash
sherlock user123 --csv
\`\`\`
**Argüman Açıklamaları:**
*   **--csv**: CSV formatı.

### NSFW Siteleri Dahil Et
Yetişkin içerikli siteleri de tarama listesine ekler.
\`\`\`bash
sherlock user123 --nsfw
\`\`\`
**Argüman Açıklamaları:**
*   **--nsfw**: NSFW filtresini kaldır.

## 4. İleri Seviye Kullanım

### Unique Tor Circuit
Her site için farklı bir Tor devresi kullanarak IP tabanlı engellemeleri aşar.
\`\`\`bash
sherlock user123 --tor --unique-tor
\`\`\`

### Proxy Chaining
Özel bir proxy sunucusu üzerinden tarama yapar.
\`\`\`bash
sherlock user123 --proxy socks5://127.0.0.1:9050
\`\`\`

### Rate Limit Bypass
İstekler arasına gecikme ekleyerek WAF veya rate-limit korumasını atlatır (bazı fork veya versiyonlarda \`--rate-limit\` parametresi gerekebilir, Sherlock varsayılan olarak hızlıdır).

### JSON Output Entegrasyonu
Otomasyon araçları veya SIEM için JSON çıktısı üretir.
\`\`\`bash
sherlock user123 --json
\`\`\`

### Debug Modu ile False-Positive Analizi
Hatalı sonuçları incelemek için HTTP istek/yanıt detaylarını görür.
\`\`\`bash
sherlock user123 --debug
\`\`\`

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar

**Komut:**
\`\`\`bash
sherlock user123 --print-found
\`\`\`
**Açıklama:**
Sadece bulunan hesapları listeler.
**Argüman Açıklamaları:**
*   **--print-found**: Bulunanları göster.

**Komut:**
\`\`\`bash
sherlock user123 --no-color
\`\`\`
**Açıklama:**
Renkli çıktıyı kapatır (loglama için uygun).
**Argüman Açıklamaları:**
*   **--no-color**: Renksiz mod.

**Komut:**
\`\`\`bash
sherlock user123 --verbose
\`\`\`
**Açıklama:**
Detaylı işlem bilgisi verir.
**Argüman Açıklamaları:**
*   **--verbose**: Verbose mod.

**Komut:**
\`\`\`bash
sherlock user123 --debug
\`\`\`
**Açıklama:**
Hata ayıklama modunu açar.
**Argüman Açıklamaları:**
*   **--debug**: Debug logları.

**Komut:**
\`\`\`bash
sherlock user123 --site twitter
\`\`\`
**Açıklama:**
Sadece Twitter üzerinde arama yapar.
**Argüman Açıklamaları:**
*   **--site**: Hedef site.

**Komut:**
\`\`\`bash
sherlock user123 --nsfw
\`\`\`
**Açıklama:**
NSFW kategorisindeki siteleri tarar.
**Argüman Açıklamaları:**
*   **--nsfw**: NSFW dahil et.

**Komut:**
\`\`\`bash
sherlock user123 --timeout 20
\`\`\`
**Açıklama:**
İstek zaman aşımını 20 saniye yapar.
**Argüman Açıklamaları:**
*   **--timeout**: Timeout süresi.

**Komut:**
\`\`\`bash
sherlock user123 --folderoutput ./logs
\`\`\`
**Açıklama:**
Çıktıları logs klasörüne yazar.
**Argüman Açıklamaları:**
*   **--folderoutput**: Klasör yolu.

**Komut:**
\`\`\`bash
sherlock user123 --json
\`\`\`
**Açıklama:**
JSON formatında rapor oluşturur.
**Argüman Açıklamaları:**
*   **--json**: JSON çıktısı.

**Komut:**
\`\`\`bash
sherlock user123 --csv
\`\`\`
**Açıklama:**
CSV formatında rapor oluşturur.
**Argüman Açıklamaları:**
*   **--csv**: CSV çıktısı.

**Komut:**
\`\`\`bash
sherlock user123 --xlsx
\`\`\`
**Açıklama:**
Excel formatında rapor oluşturur.
**Argüman Açıklamaları:**
*   **--xlsx**: Excel çıktısı.

### Proxy / Network

**Komut:**
\`\`\`bash
sherlock user123 --proxy http://127.0.0.1:8080
\`\`\`
**Açıklama:**
HTTP proxy kullanır.
**Argüman Açıklamaları:**
*   **--proxy**: Proxy adresi.

**Komut:**
\`\`\`bash
sherlock user123 --tor
\`\`\`
**Açıklama:**
Tor ağı üzerinden tarama yapar.
**Argüman Açıklamaları:**
*   **--tor**: Tor modu.

**Komut:**
\`\`\`bash
sherlock user123 --unique-tor
\`\`\`
**Açıklama:**
Her istekte Tor devresini yeniler.
**Argüman Açıklamaları:**
*   **--unique-tor**: Benzersiz Tor devresi.

### Payload & Request Manipulation (Not: Sherlock bu özellikleri kısıtlı destekler, genelde config dosyasından yönetilir)

**Komut:**
\`\`\`bash
# (Genellikle kaynak kod veya config.json üzerinden yapılır)
# Ancak bazı forklar header desteği sunabilir.
\`\`\`

### Scanning / Enumeration

**Komut:**
\`\`\`bash
sherlock user123 --site instagram --site twitter
\`\`\`
**Açıklama:**
Birden fazla spesifik siteyi tarar.
**Argüman Açıklamaları:**
*   **--site**: Site seçimi (tekrarlanabilir).

### Output

**Komut:**
\`\`\`bash
sherlock user123 --folderoutput results/ --json
\`\`\`
**Açıklama:**
JSON dosyasını results klasörüne kaydeder.
**Argüman Açıklamaları:**
*   **--folderoutput**: Klasör.
*   **--json**: JSON.

## 6. Gerçek Pentest / OSINT Senaryoları

### Username Footprinting (100+ Platform Kontrolü)
\`\`\`bash
sherlock targetuser --print-found --timeout 10
\`\`\`
**Açıklama:**
Hedef kullanıcının dijital ayak izini çıkarmak için geniş çaplı tarama yapar.

### Sadece Sosyal Medya Platformları İçin Tarama
\`\`\`bash
sherlock targetuser --site facebook --site twitter --site instagram --site linkedin
\`\`\`
**Açıklama:**
Sadece ana sosyal medya hesaplarına odaklanır.

### Anonymous OSINT İçin Tor + Unique Tor Kullanımı
\`\`\`bash
sherlock targetuser --tor --unique-tor --timeout 20
\`\`\`
**Açıklama:**
Kimliği gizleyerek ve IP engellemelerini aşarak anonim tarama yapar.

### Proxy Üzerinden Şirket İçi OSINT Tespiti
\`\`\`bash
sherlock targetuser --proxy http://corp-proxy:8080
\`\`\`
**Açıklama:**
Kurumsal proxy arkasından dış hedefleri araştırır.

### Kurumsal Hesap Sahteciliği Araştırması
\`\`\`bash
sherlock "companyname_support" --print-found
\`\`\`
**Açıklama:**
Şirket adına açılmış sahte destek hesaplarını tespit eder.

### Username + Region-Based Site Seçimi
\`\`\`bash
# (Manuel site listesi düzenleme veya --site ile)
sherlock targetuser --site vk --site ok.ru
\`\`\`
**Açıklama:**
Rusya bölgesine özel platformlarda kullanıcıyı arar.

### Debug Modda False-Positive Analizi
\`\`\`bash
sherlock targetuser --site unknown-site --debug
\`\`\`
**Açıklama:**
Şüpheli bir sonucun HTTP yanıt kodlarını ve içeriğini inceleyerek doğrulama yapar.

### Response Pattern Değişimi ile Hesap Tespiti
\`\`\`bash
sherlock targetuser --verbose
\`\`\`
**Açıklama:**
Sitelerin verdiği yanıtların (200 OK, 404 Not Found) tutarlılığını izler.

### Rate-Limit Bypass İçin Delay Ekleme
\`\`\`bash
# (Sherlock native delay parametresi yoksa timeout artırılır)
sherlock targetuser --timeout 30
\`\`\`
**Açıklama:**
Yavaş yanıt veren veya rate-limit uygulayan siteler için bekleme süresini artırır.

### Specific Site Enumeration (Tek Site)
\`\`\`bash
sherlock targetuser --site github
\`\`\`
**Açıklama:**
Sadece GitHub üzerinde kullanıcı varlığını kontrol eder.

### Yeni Platform Eklemek İçin Site JSON Override
\`\`\`bash
# (data.json dosyasına yeni site eklenir)
sherlock targetuser
\`\`\`
**Açıklama:**
Kendi özel platformunuzu Sherlock veritabanına ekleyerek tararsınız.

### Redirect Tabanlı Tespit Mekanizması
\`\`\`bash
sherlock targetuser --debug
\`\`\`
**Açıklama:**
Yönlendirme (301/302) yapan sitelerin davranışını analiz eder.

### Error-Based Enumeration (HTTP 404/500 Davranışı)
\`\`\`bash
sherlock targetuser --verbose
\`\`\`
**Açıklama:**
Hata mesajlarına göre hesabın var olup olmadığını yorumlar.

### CAPTCHA Korumalı Sitelerde Timeout Tuning
\`\`\`bash
sherlock targetuser --timeout 60
\`\`\`
**Açıklama:**
Captcha veya Cloudflare bekletmesi olan siteler için uzun timeout tanımlar.

### CDN Arkasındaki Hesap Endpoint Analizi
\`\`\`bash
sherlock targetuser --site medium
\`\`\`
**Açıklama:**
CDN kullanan blog platformlarında hesap tespiti.

### API Endpoint’leri Üzerinden Enumeration
\`\`\`bash
# (Sherlock arka planda API endpointlerini kullanır)
sherlock targetuser --site steam
\`\`\`
**Açıklama:**
Steam gibi platformların API'leri üzerinden kullanıcıyı doğrular.

### Username Değişim Takibi İçin Tekrar Eden Tarama
\`\`\`bash
sherlock targetuser --folderoutput ./history/$(date +%F)
\`\`\`
**Açıklama:**
Zaman içindeki değişimleri izlemek için tarihli klasörlere kayıt alır.

### Mail Provider Username Enumeration
\`\`\`bash
sherlock targetuser --site protonmail
\`\`\`
**Açıklama:**
ProtonMail gibi servislerde kullanıcı adının alınıp alınmadığını kontrol eder.

### Developer Platformlarında Profil Tespiti
\`\`\`bash
sherlock targetuser --site github --site gitlab --site dockerhub
\`\`\`
**Açıklama:**
Yazılımcı profillerini bulmak için kod depolarını tarar.

### NSFW Platformları Hariç Tarama
\`\`\`bash
sherlock targetuser # (Varsayılan olarak NSFW kapalıdır veya --nsfw kullanılmaz)
\`\`\`
**Açıklama:**
Kurumsal ortamda uygunsuz içerik taramasını engeller.

## 8. Best Practices (Uzman Seviye)

*   **Tor Timeout**: Tor kullanırken \`--timeout\` değerini en az 15-20 saniye yapın, ağ yavaştır.
*   **Rate-Limit**: Çok hızlı tarama IP engeline yol açabilir, gerekirse \`--timeout\` ile yavaşlatın.
*   **Verification**: Şüpheli (false-positive) sonuçları tarayıcıdan veya \`--site\` ile tekil tarayarak doğrulayın.
*   **Debug**: Beklenmedik sonuçlar için \`--debug\` loglarını mutlaka inceleyin.
*   **Clean Output**: Aynı kullanıcıyı tekrar tararken eski çıktı dosyasını silin veya \`--folderoutput\` ile ayırın.
*   **Proxy vs Tor**: Proxy ve Tor'u aynı anda kullanmak bağlantı sorunlarına yol açabilir, birini seçin.
*   **Region Specific**: Hedefin ülkesine göre yerel platformları (örn: Çin için Weibo) manuel kontrol edin veya ekleyin.
*   **JSON Reporting**: Raporlama ve veri işleme için \`--json\` formatı en esnek olanıdır.
*   **Response Analysis**: Sitenin "hesap yok" dediğinde döndürdüğü yanıt boyutu ile "hesap var" yanıtını karşılaştırın.
*   **No Color**: CI/CD veya log dosyasına yazarken \`--no-color\` kullanarak ANSI kodlarını temizleyin.

## 9. Sık Yapılan Hatalar

*   **Kör Güven**: Tek tarama sonucuna %100 güvenip manuel doğrulama yapmamak.
*   **Düşük Timeout**: Varsayılan timeout ile yavaş siteleri "bulunamadı" olarak işaretlemek.
*   **NSFW İhmali**: Hedef analizi yaparken NSFW sitelerindeki varlığı gözden kaçırmak (veya yanlışlıkla taramak).
*   **Tor Circuit**: \`--unique-tor\` kullanmadan sürekli aynı Tor IP'sinden istek atıp engellenmek.
*   **Format Hatası**: Çıktıyı ekrana basıp kaydetmemek, sonra veriyi kaybetmek.
*   **SSL Errors**: Proxy arkasında SSL sertifika hatalarını göz ardı edip bağlantı kuramamak.
*   **Local Platforms**: Sadece global siteleri tarayıp yerel sosyal ağları atlamak.
*   **Rate-Limit**: WAF'ın IP'yi blokladığını fark etmeyip taramaya devam etmek.
*   **Debug Kapalı**: Neden sonuç alamadığını anlamadan aracı suçlamak (debug açın).
*   **Redirect**: Hesabın silinmiş veya yönlendirilmiş olabileceğini hesaba katmamak.
`;

const contentEN = `# Sherlock - OSINT Username Enumeration Tool

## 1. Tool Definition
**Sherlock** is an OSINT-based username enumeration tool that detects the usage of a given username across hundreds of platforms. It analyzes username availability based on HTTP response codes, redirect behavior, error messages, and pattern matching.

## 2. Installation
*   **Kali Linux**: \`sudo apt install sherlock\`
*   **Source**: \`git clone https://github.com/sherlock-project/sherlock.git && cd sherlock && python3 -m pip install -r requirements.txt\`

## 3. Basic Usage

### Single Username Query
Searches for the specified username on all supported sites.
\`\`\`bash
sherlock user123
\`\`\`
**Argument Explanations:**
*   **user123**: Username to query.

### Show Found Only
Cleans output by hiding sites where the username was not found.
\`\`\`bash
sherlock user123 --print-found
\`\`\`
**Argument Explanations:**
*   **--print-found**: Print only positive results.

### Save Output to Folder
Saves results as a text file in the specified folder.
\`\`\`bash
sherlock user123 --folderoutput results/
\`\`\`
**Argument Explanations:**
*   **--folderoutput**: Output folder.

### Timeout Setting
Increases wait time for slow sites (default is sometimes too low).
\`\`\`bash
sherlock user123 --timeout 15
\`\`\`
**Argument Explanations:**
*   **--timeout**: Timeout in seconds.

### Scan via Tor
Provides privacy by sending requests through the Tor network.
\`\`\`bash
sherlock user123 --tor
\`\`\`
**Argument Explanations:**
*   **--tor**: Use Tor proxy.

### Search on Specific Site
Queries only on a single platform.
\`\`\`bash
sherlock user123 --site instagram
\`\`\`
**Argument Explanations:**
*   **--site**: Site name.

### CSV Output
Saves results in CSV format for analysis.
\`\`\`bash
sherlock user123 --csv
\`\`\`
**Argument Explanations:**
*   **--csv**: CSV format.

### Include NSFW Sites
Adds adult content sites to the scan list.
\`\`\`bash
sherlock user123 --nsfw
\`\`\`
**Argument Explanations:**
*   **--nsfw**: Remove NSFW filter.

## 4. Advanced Usage

### Unique Tor Circuit
Uses a different Tor circuit for each site to bypass IP-based blocks.
\`\`\`bash
sherlock user123 --tor --unique-tor
\`\`\`

### Proxy Chaining
Scans through a custom proxy server.
\`\`\`bash
sherlock user123 --proxy socks5://127.0.0.1:9050
\`\`\`

### Rate Limit Bypass
Bypasses WAF or rate-limit protection by adding delay between requests (some forks or versions may require \`--rate-limit\` parameter, Sherlock is fast by default).

### JSON Output Integration
Generates JSON output for automation tools or SIEM.
\`\`\`bash
sherlock user123 --json
\`\`\`

### False-Positive Analysis with Debug Mode
Views HTTP request/response details to investigate incorrect results.
\`\`\`bash
sherlock user123 --debug
\`\`\`

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments

**Command:**
\`\`\`bash
sherlock user123 --print-found
\`\`\`
**Description:**
Lists only found accounts.
**Argument Explanations:**
*   **--print-found**: Show found.

**Command:**
\`\`\`bash
sherlock user123 --no-color
\`\`\`
**Description:**
Disables colored output (suitable for logging).
**Argument Explanations:**
*   **--no-color**: No color mode.

**Command:**
\`\`\`bash
sherlock user123 --verbose
\`\`\`
**Description:**
Provides detailed process info.
**Argument Explanations:**
*   **--verbose**: Verbose mode.

**Command:**
\`\`\`bash
sherlock user123 --debug
\`\`\`
**Description:**
Enables debugging mode.
**Argument Explanations:**
*   **--debug**: Debug logs.

**Command:**
\`\`\`bash
sherlock user123 --site twitter
\`\`\`
**Description:**
Searches only on Twitter.
**Argument Explanations:**
*   **--site**: Target site.

**Command:**
\`\`\`bash
sherlock user123 --nsfw
\`\`\`
**Description:**
Scans sites in NSFW category.
**Argument Explanations:**
*   **--nsfw**: Include NSFW.

**Command:**
\`\`\`bash
sherlock user123 --timeout 20
\`\`\`
**Description:**
Sets request timeout to 20 seconds.
**Argument Explanations:**
*   **--timeout**: Timeout duration.

**Command:**
\`\`\`bash
sherlock user123 --folderoutput ./logs
\`\`\`
**Description:**
Writes outputs to logs folder.
**Argument Explanations:**
*   **--folderoutput**: Folder path.

**Command:**
\`\`\`bash
sherlock user123 --json
\`\`\`
**Description:**
Generates report in JSON format.
**Argument Explanations:**
*   **--json**: JSON output.

**Command:**
\`\`\`bash
sherlock user123 --csv
\`\`\`
**Description:**
Generates report in CSV format.
**Argument Explanations:**
*   **--csv**: CSV output.

**Command:**
\`\`\`bash
sherlock user123 --xlsx
\`\`\`
**Description:**
Generates report in Excel format.
**Argument Explanations:**
*   **--xlsx**: Excel output.

### Proxy / Network

**Command:**
\`\`\`bash
sherlock user123 --proxy http://127.0.0.1:8080
\`\`\`
**Description:**
Uses HTTP proxy.
**Argument Explanations:**
*   **--proxy**: Proxy address.

**Command:**
\`\`\`bash
sherlock user123 --tor
\`\`\`
**Description:**
Scans over Tor network.
**Argument Explanations:**
*   **--tor**: Tor mode.

**Command:**
\`\`\`bash
sherlock user123 --unique-tor
\`\`\`
**Description:**
Refreshes Tor circuit for each request.
**Argument Explanations:**
*   **--unique-tor**: Unique Tor circuit.

### Payload & Request Manipulation (Note: Sherlock supports this limitedly, usually managed via config)

**Command:**
\`\`\`bash
# (Usually done via source code or config.json)
# However, some forks may offer header support.
\`\`\`

### Scanning / Enumeration

**Command:**
\`\`\`bash
sherlock user123 --site instagram --site twitter
\`\`\`
**Description:**
Scans multiple specific sites.
**Argument Explanations:**
*   **--site**: Site selection (repeatable).

### Output

**Command:**
\`\`\`bash
sherlock user123 --folderoutput results/ --json
\`\`\`
**Description:**
Saves JSON file to results folder.
**Argument Explanations:**
*   **--folderoutput**: Folder.
*   **--json**: JSON.

## 6. Real Pentest / OSINT Scenarios

### Username Footprinting (100+ Platform Check)
\`\`\`bash
sherlock targetuser --print-found --timeout 10
\`\`\`
**Description:**
Performs a broad scan to map the target user's digital footprint.

### Scan Only for Social Media Platforms
\`\`\`bash
sherlock targetuser --site facebook --site twitter --site instagram --site linkedin
\`\`\`
**Description:**
Focuses only on main social media accounts.

### Tor + Unique Tor Usage for Anonymous OSINT
\`\`\`bash
sherlock targetuser --tor --unique-tor --timeout 20
\`\`\`
**Description:**
Performs anonymous scan hiding identity and bypassing IP blocks.

### Corporate Internal OSINT Detection via Proxy
\`\`\`bash
sherlock targetuser --proxy http://corp-proxy:8080
\`\`\`
**Description:**
Investigates external targets from behind a corporate proxy.

### Corporate Account Impersonation Research
\`\`\`bash
sherlock "companyname_support" --print-found
\`\`\`
**Description:**
Detects fake support accounts created in the company's name.

### Username + Region-Based Site Selection
\`\`\`bash
# (Manual site list editing or via --site)
sherlock targetuser --site vk --site ok.ru
\`\`\`
**Description:**
Searches for the user on platforms specific to the Russia region.

### False-Positive Analysis in Debug Mode
\`\`\`bash
sherlock targetuser --site unknown-site --debug
\`\`\`
**Description:**
Verifies a suspicious result by examining HTTP response codes and content.

### Account Detection via Response Pattern Change
\`\`\`bash
sherlock targetuser --verbose
\`\`\`
**Description:**
Monitors consistency of site responses (200 OK, 404 Not Found).

### Adding Delay for Rate-Limit Bypass
\`\`\`bash
# (If no native delay param, timeout is increased)
sherlock targetuser --timeout 30
\`\`\`
**Description:**
Increases wait time for slow responding or rate-limited sites.

### Specific Site Enumeration (Single Site)
\`\`\`bash
sherlock targetuser --site github
\`\`\`
**Description:**
Checks user presence only on GitHub.

### Site JSON Override to Add New Platform
\`\`\`bash
# (New site is added to data.json file)
sherlock targetuser
\`\`\`
**Description:**
You scan by adding your own custom platform to the Sherlock database.

### Redirect-Based Detection Mechanism
\`\`\`bash
sherlock targetuser --debug
\`\`\`
**Description:**
Analyzes behavior of sites performing redirects (301/302).

### Error-Based Enumeration (HTTP 404/500 Behavior)
\`\`\`bash
sherlock targetuser --verbose
\`\`\`
**Description:**
Interprets account existence based on error messages.

### Timeout Tuning for CAPTCHA Protected Sites
\`\`\`bash
sherlock targetuser --timeout 60
\`\`\`
**Description:**
Defines long timeout for sites with Captcha or Cloudflare delays.

### Account Endpoint Analysis Behind CDN
\`\`\`bash
sherlock targetuser --site medium
\`\`\`
**Description:**
Account detection on blog platforms using CDN.

### Enumeration via API Endpoints
\`\`\`bash
# (Sherlock uses API endpoints in background)
sherlock targetuser --site steam
\`\`\`
**Description:**
Verifies user via APIs of platforms like Steam.

### Recurring Scan for Username Change Tracking
\`\`\`bash
sherlock targetuser --folderoutput ./history/$(date +%F)
\`\`\`
**Description:**
Records to dated folders to track changes over time.

### Mail Provider Username Enumeration
\`\`\`bash
sherlock targetuser --site protonmail
\`\`\`
**Description:**
Checks if username is taken on services like ProtonMail.

### Profile Detection on Developer Platforms
\`\`\`bash
sherlock targetuser --site github --site gitlab --site dockerhub
\`\`\`
**Description:**
Scans code repositories to find developer profiles.

### Scan Excluding NSFW Platforms
\`\`\`bash
sherlock targetuser # (NSFW is off by default or --nsfw is not used)
\`\`\`
**Description:**
Prevents scanning inappropriate content in corporate environment.

## 8. Best Practices (Expert Level)

*   **Tor Timeout**: Set \`--timeout\` to at least 15-20 seconds when using Tor, network is slow.
*   **Rate-Limit**: Too fast scanning can lead to IP ban, slow down with \`--timeout\` if needed.
*   **Verification**: Verify suspicious (false-positive) results via browser or single scan with \`--site\`.
*   **Debug**: Always examine \`--debug\` logs for unexpected results.
*   **Clean Output**: Delete old output file or separate with \`--folderoutput\` when rescanning same user.
*   **Proxy vs Tor**: Using Proxy and Tor together may cause connection issues, choose one.
*   **Region Specific**: Manually check or add local platforms (e.g., Weibo for China) based on target's country.
*   **JSON Reporting**: \`--json\` format is most flexible for reporting and data processing.
*   **Response Analysis**: Compare response size of "no account" vs "account exists" responses.
*   **No Color**: Use \`--no-color\` to clean ANSI codes when writing to CI/CD or log files.

## 9. Common Mistakes

*   **Blind Trust**: Trusting 100% in a single scan result without manual verification.
*   **Low Timeout**: Marking slow sites as "not found" with default timeout.
*   **Ignoring NSFW**: Overlooking presence on NSFW sites during target analysis (or scanning accidentally).
*   **Tor Circuit**: Getting blocked by sending requests from same Tor IP without \`--unique-tor\`.
*   **Format Error**: Printing output to screen and not saving, losing data.
*   **SSL Errors**: Ignoring SSL certificate errors behind proxy and failing to connect.
*   **Local Platforms**: Scanning only global sites and skipping local social networks.
*   **Rate-Limit**: Continuing scan without realizing WAF blocked the IP.
*   **Debug Off**: Blaming the tool without understanding why no results were found (turn on debug).
*   **Redirect**: Not accounting for account being deleted or redirected.
`;

async function addSherlock() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Sherlock cheatsheet...');

        let category = await Category.findOne({ 'name.en': 'OSINT' });
        if (!category) {
            console.log('Category "OSINT" not found, creating...');
            category = await Category.create({
                name: { tr: 'OSINT', en: 'OSINT' },
                description: { tr: 'Açık Kaynak İstihbarat Araçları', en: 'Open Source Intelligence Tools' },
                slug: 'osint',
                icon: 'Eye'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Sherlock Cheat Sheet',
                en: 'Sherlock Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['sherlock', 'osint', 'username-enumeration', 'social-media', 'footprinting']
        };

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Sherlock Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Sherlock cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addSherlock();
