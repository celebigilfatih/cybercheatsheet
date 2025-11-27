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

const contentTR = `# Medusa - Parallel Network Login Auditor

## 1. Araç Tanımı
**Medusa**, hızlı, paralel çalışan bir brute-force aracıdır. SSH, FTP, RDP, SMB, HTTP, MySQL, MSSQL gibi çok sayıda servise karşı parola denemesi yapabilir. Modüler mimarisi ile custom modüller desteklenir ve yüksek hızda distributed saldırı için uygundur.

## 2. Kurulum
*   **Kali Linux**: \`sudo apt install medusa\`
*   **Source**: \`http://foofus.net/goons/jmk/medusa/medusa.html\`

## 3. Temel Kullanım

### Tek Hedef ve Tek Kullanıcı
Belirli bir IP ve kullanıcı için parola listesi dener.
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M ssh
\`\`\`
**Argüman Açıklamaları:**
*   **-h**: Hedef IP.
*   **-u**: Kullanıcı adı.
*   **-P**: Parola listesi.
*   **-M**: Modül adı (ssh).

### Kullanıcı Listesi ile Tarama
Kullanıcı listesi ve parola listesi kombinasyonunu dener.
\`\`\`bash
medusa -h 192.168.1.10 -U users.txt -P passwords.txt -M ftp
\`\`\`
**Argüman Açıklamaları:**
*   **-U**: Kullanıcı listesi dosyası.

### Hedef Listesi (Çoklu Host)
Birden fazla hedef üzerinde aynı anda tarama yapar.
\`\`\`bash
medusa -H hosts.txt -u root -P passwords.txt -M ssh
\`\`\`
**Argüman Açıklamaları:**
*   **-H**: Hedef listesi dosyası.

### Başarılı Girişte Durma
İlk başarılı girişi bulduğunda o host için taramayı durdurur.
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M smbnt -f
\`\`\`
**Argüman Açıklamaları:**
*   **-f**: İlk başarılı parolada dur.

### Verbose Mod
Hata ve deneme detaylarını gösterir.
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M http -v 6
\`\`\`
**Argüman Açıklamaları:**
*   **-v 6**: Detay seviyesi (6 = debug).

### Thread Ayarı
Paralel deneme sayısını belirler (Hız kontrolü).
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M ssh -t 10
\`\`\`
**Argüman Açıklamaları:**
*   **-t**: Thread sayısı.

### Çıktıyı Dosyaya Yazma
Sonuçları dosyaya kaydeder.
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M ssh -O results.txt
\`\`\`
**Argüman Açıklamaları:**
*   **-O**: Çıktı dosyası.

### Retry Ayarı
Bağlantı hatası durumunda kaç kez tekrar deneneceğini belirler.
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M ssh -R 3
\`\`\`
**Argüman Açıklamaları:**
*   **-R**: Retry sayısı.

## 4. İleri Seviye Kullanım

### Modül Parametreleri
Bazı modüller (örn: http, snmp) özel parametreler gerektirir. \`-m\` flag'i ile modüle özel ayarlar geçilebilir.
\`\`\`bash
medusa -M http -m DIR:/admin -m FORM:user=^USER^&pass=^PASS^
\`\`\`

### Boş Parola Kontrolü
Kullanıcı adı ile aynı parolayı veya boş parolayı denemek için özel listeler veya modül ayarları kullanılabilir.

### Resume Özelliği
Medusa varsayılan olarak durdurulduğu yerden devam etme özelliğine (resume) tam sahip değildir, bu yüzden büyük taramalarda çıktı dosyası (\`-O\`) ve loglama önemlidir.

### SSL/TLS Desteği
SSL kullanan servisler (HTTPS, FTPS, IMAPS) için modül genellikle otomatik algılar veya \`-s\` (bazı versiyonlarda) veya modül parametresi gerekebilir.

### Timeout Yönetimi
Ağ gecikmelerini yönetmek için \`-n\` (port) veya global timeout ayarları önemlidir.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar

**Komut:**
\`\`\`bash
medusa -h 192.168.1.10
\`\`\`
**Açıklama:**
Tek hedef belirtir.
**Argüman Açıklamaları:**
*   **-h**: Hedef host.

**Komut:**
\`\`\`bash
medusa -H targets.txt
\`\`\`
**Açıklama:**
Hedef listesi belirtir.
**Argüman Açıklamaları:**
*   **-H**: Hedef dosyası.

**Komut:**
\`\`\`bash
medusa -U users.txt
\`\`\`
**Açıklama:**
Kullanıcı listesi.
**Argüman Açıklamaları:**
*   **-U**: Kullanıcı dosyası.

**Komut:**
\`\`\`bash
medusa -u admin
\`\`\`
**Açıklama:**
Tek kullanıcı adı.
**Argüman Açıklamaları:**
*   **-u**: Kullanıcı adı.

**Komut:**
\`\`\`bash
medusa -P pass.txt
\`\`\`
**Açıklama:**
Parola listesi.
**Argüman Açıklamaları:**
*   **-P**: Parola dosyası.

**Komut:**
\`\`\`bash
medusa -p 123456
\`\`\`
**Açıklama:**
Tek parola.
**Argüman Açıklamaları:**
*   **-p**: Parola string.

**Komut:**
\`\`\`bash
medusa -M ssh
\`\`\`
**Açıklama:**
Kullanılacak modül.
**Argüman Açıklamaları:**
*   **-M**: Modül adı.

**Komut:**
\`\`\`bash
medusa -n 2222
\`\`\`
**Açıklama:**
Standart dışı port belirtimi.
**Argüman Açıklamaları:**
*   **-n**: Port numarası.

**Komut:**
\`\`\`bash
medusa -O out.txt
\`\`\`
**Açıklama:**
Çıktı dosyası.
**Argüman Açıklamaları:**
*   **-O**: Dosya yolu.

**Komut:**
\`\`\`bash
medusa -t 20
\`\`\`
**Açıklama:**
Eşzamanlı bağlantı sayısı.
**Argüman Açıklamaları:**
*   **-t**: Thread sayısı.

**Komut:**
\`\`\`bash
medusa -V
\`\`\`
**Açıklama:**
Temel verbose modu.
**Argüman Açıklamaları:**
*   **-V**: Verbose.

**Komut:**
\`\`\`bash
medusa -v 6
\`\`\`
**Açıklama:**
Maksimum detay seviyesi.
**Argüman Açıklamaları:**
*   **-v 6**: Debug level.

**Komut:**
\`\`\`bash
medusa -f
\`\`\`
**Açıklama:**
Host başına ilk başarılı girişte durur.
**Argüman Açıklamaları:**
*   **-f**: Stop on first success (per host).

**Komut:**
\`\`\`bash
medusa -F
\`\`\`
**Açıklama:**
Herhangi bir hostta başarılı giriş bulunca tüm taramayı durdurur.
**Argüman Açıklamaları:**
*   **-F**: Stop on first success (global).

**Komut:**
\`\`\`bash
medusa -R 3
\`\`\`
**Açıklama:**
Hata durumunda 3 kez tekrar dener.
**Argüman Açıklamaları:**
*   **-R**: Retry count.

### Proxy / Network

**Komut:**
\`\`\`bash
medusa --proxy http://127.0.0.1:8080
\`\`\`
**Açıklama:**
Proxy sunucusu tanımlar (destekleyen sürümlerde).
**Argüman Açıklamaları:**
*   **--proxy**: Proxy URL.

**Komut:**
\`\`\`bash
medusa --net-delay 2
\`\`\`
**Açıklama:**
İstekler arasına 2 saniye gecikme koyar.
**Argüman Açıklamaları:**
*   **--net-delay**: Gecikme süresi.

**Komut:**
\`\`\`bash
medusa --conn-timeout 10
\`\`\`
**Açıklama:**
Bağlantı zaman aşımı süresi.
**Argüman Açıklamaları:**
*   **--conn-timeout**: Timeout saniyesi.

### Scanning / Enumeration

**Komut:**
\`\`\`bash
medusa -d
\`\`\`
**Açıklama:**
Yüklü modülleri listeler.
**Argüman Açıklamaları:**
*   **-d**: Dump modules.

**Komut:**
\`\`\`bash
medusa -q
\`\`\`
**Açıklama:**
Sessiz mod (sadece başarılı girişleri gösterir).
**Argüman Açıklamaları:**
*   **-q**: Quiet mode.

## 6. Gerçek Pentest Senaryoları

### SSH Brute-Force Yüksek Hız + Thread Tuning
\`\`\`bash
medusa -h 10.10.10.5 -u root -P rockyou.txt -M ssh -t 20 -f
\`\`\`
**Açıklama:**
SSH servisine 20 thread ile hızlı bir saldırı yapar, ilk parolada durur.

### FTP Hizmetine Dictionary Saldırısı
\`\`\`bash
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M ftp -n 21
\`\`\`
**Açıklama:**
FTP servisine kullanıcı ve parola listeleriyle sözlük saldırısı düzenler.

### SMB NTLM Brute-Force (Domain + Lockout Dikkatli Kullanım)
\`\`\`bash
medusa -h 10.10.10.5 -u Administrator -P passwords.txt -M smbnt -m WORKGROUP
\`\`\`
**Açıklama:**
SMB servisine NTLM authentication ile saldırır, domain/workgroup belirtilir.

### HTTP Basic Auth Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M http -m DIR:/protected
\`\`\`
**Açıklama:**
HTTP Basic Authentication korumalı dizine saldırı yapar.

### HTTP Form Tabanlı Login Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M http -m FORM:"user=^USER^&pass=^PASS^"
\`\`\`
**Açıklama:**
Web form login sayfasına POST parametrelerini manipüle ederek saldırır.

### MySQL Root Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -u root -P passwords.txt -M mysql
\`\`\`
**Açıklama:**
MySQL veritabanı root kullanıcısı için parola dener.

### MSSQL Kullanıcı Keşfi + Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M mssql
\`\`\`
**Açıklama:**
MSSQL servisine kullanıcı listesi ile saldırır.

### RDP Brute-Force + Timeout Tuning
\`\`\`bash
medusa -h 10.10.10.5 -u Administrator -P passwords.txt -M rdp -t 1 --conn-timeout 15
\`\`\`
**Açıklama:**
RDP servisine (genellikle yavaştır) tek thread ve yüksek timeout ile saldırır.

### Proxy Üzerinden Brute-Force (Kurumsal Ağ)
\`\`\`bash
proxychains medusa -h 10.10.10.5 -u admin -P passwords.txt -M ssh
\`\`\`
**Açıklama:**
Medusa'nın native proxy desteği sınırlıysa \`proxychains\` ile kurumsal proxy üzerinden tünellenir.

### Tor Üzerinden Yüksek Gizlilikli Brute-Force
\`\`\`bash
proxychains medusa -h target.com -u admin -P passwords.txt -M ssh
\`\`\`
**Açıklama:**
Tor ağı üzerinden gizli saldırı (yavaş olacaktır).

### Rate-Limit Tespiti için Incremental Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -u admin -p 123456 -M http -r 10
\`\`\`
**Açıklama:**
Belirli aralıklarla istek göndererek rate-limit tepkisini ölçer.

### Captcha Olmayan Endpointlerde Hız Testi
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M http -t 50
\`\`\`
**Açıklama:**
Captcha koruması olmayan formlarda yüksek thread ile hız testi.

### Custom Header ile WAF Bypass Denemesi
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M http -m "HEADER:X-Forwarded-For:127.0.0.1"
\`\`\`
**Açıklama:**
HTTP isteğine özel header ekleyerek IP kısıtlamasını aşmayı dener.

### Non-Standard Port Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -u root -P passwords.txt -M ssh -n 2222
\`\`\`
**Açıklama:**
2222 portunda çalışan SSH servisine saldırır.

### Distributed Brute-Force (Çoklu IP Üzerinden)
\`\`\`bash
# (Birden fazla makinede hedef listesini bölerek çalıştırılır)
medusa -H targets_part1.txt ...
\`\`\`
**Açıklama:**
Hedef listesini parçalara bölüp farklı makinelerden tarama yaparak yükü dağıtır.

### Lockout Threshold Analizi için Düşük Hız Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M smbnt -t 1 --net-delay 30
\`\`\`
**Açıklama:**
Hesap kilitlenmesini önlemek için her deneme arasına 30 saniye koyar.

### Honeyservice Tespiti için Response Davranışı Analizi
\`\`\`bash
medusa -h 10.10.10.5 -u fakeuser -p fakepass -M ssh -v 6
\`\`\`
**Açıklama:**
Olmayan kullanıcıya verilen tepkiyi (honeypot şüphesi) debug modunda inceler.

### SSL Zorunlu Servislerde Sertifika Doğrulaması Kapatma
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M http -m SSL
\`\`\`
**Açıklama:**
SSL üzerinden bağlantı kurar (sertifika hatasını yoksaymak modüle bağlıdır).

### API Key Brute-Force (HTTP Header Üzerinden)
\`\`\`bash
medusa -h 10.10.10.5 -u key -P keys.txt -M http -m "HEADER:Authorization: Bearer ^PASS^"
\`\`\`
**Açıklama:**
Parola listesindeki değerleri Authorization header içine gömerek dener.

### VPN Portal Brute-Force Davranış İncelemesi
\`\`\`bash
medusa -h vpn.target.com -u user -P passwords.txt -M http -m DIR:/vpn/login
\`\`\`
**Açıklama:**
VPN web portalına yönelik giriş denemesi.

## 8. Best Practices (Uzman Seviye)

*   **Thread Tuning**: Servise göre thread ayarı yapın (RDP: 1-2, SSH: 4-8, FTP/HTTP: 10-20).
*   **Lockout Policy**: Active Directory ortamlarında hesap kilitlenmesini önlemek için \`--net-delay\` kullanın.
*   **Proxy/Tor**: Gizlilik veya erişim için proxychains kullanın, ancak timeout değerlerini artırın.
*   **HTTP Form Parsing**: Form parametrelerini (user, pass, hidden fields) doğru analiz edip \`-m FORM:...\` yapısına uygun yazın.
*   **SMB Domain**: Domain ortamlarında \`-m WORKGROUP\` veya \`-m DOMAIN\` parametresini unutmayın.
*   **Output**: Sonuçları kaybetmemek için her zaman \`-O\` ile dosyaya yazın.
*   **Stop on Success**: Tek bir geçerli parola yetiyorsa \`-f\` kullanarak zaman kazanın.
*   **Service Verification**: Medusa'yı çalıştırmadan önce Nmap ile portun açık ve servisin doğru olduğunu teyit edin.
*   **Rate-Limit**: Sunucunun yanıt sürelerini izleyerek thread sayısını dinamik olarak azaltın.

## 9. Sık Yapılan Hatalar

*   **Yanlış Modül**: Web formu için \`http\` modülünü parametresiz kullanmak (Basic Auth dener, form çalışmaz).
*   **Hızlı Tarama & Lockout**: AD ortamında yüksek hızda tarama yapıp tüm kullanıcıları kilitlemek.
*   **Düşük Timeout**: Yavaş ağlarda veya RDP gibi servislerde düşük timeout yüzünden geçerli parolaları kaçırmak.
*   **SSL İhmali**: HTTPS servisine düz HTTP modülü ile saldırmak.
*   **Parametre Hatası**: HTTP form saldırısında \`^USER^\` ve \`^PASS^\` yer tutucularını yanlış kullanmak.
*   **Proxy Auth**: Proxy kimlik doğrulaması gerekiyorsa bunu yapılandırmayı unutmak.
*   **Output Formatı**: Sonuçları ekrana basıp kaydetmemek, sonra analiz edememek.
*   **DoS Etkisi**: Çok yüksek thread sayısı ile eski sunucuları veya servisleri çökertmek.
`;

const contentEN = `# Medusa - Parallel Network Login Auditor

## 1. Tool Definition
**Medusa** is a speedy, parallel, and modular, login brute-forcer. It supports many services like SSH, FTP, RDP, SMB, HTTP, MySQL, MSSQL. Its modular architecture supports custom modules and is suitable for high-speed distributed attacks.

## 2. Installation
*   **Kali Linux**: \`sudo apt install medusa\`
*   **Source**: \`http://foofus.net/goons/jmk/medusa/medusa.html\`

## 3. Basic Usage

### Single Target and Single User
Tries a password list for a specific IP and user.
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M ssh
\`\`\`
**Argument Explanations:**
*   **-h**: Target IP.
*   **-u**: Username.
*   **-P**: Password list.
*   **-M**: Module name (ssh).

### Scan with User List
Tries a combination of user list and password list.
\`\`\`bash
medusa -h 192.168.1.10 -U users.txt -P passwords.txt -M ftp
\`\`\`
**Argument Explanations:**
*   **-U**: User list file.

### Target List (Multi-Host)
Scans multiple targets simultaneously.
\`\`\`bash
medusa -H hosts.txt -u root -P passwords.txt -M ssh
\`\`\`
**Argument Explanations:**
*   **-H**: Target list file.

### Stop on Success
Stops scanning for a host upon finding the first valid login.
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M smbnt -f
\`\`\`
**Argument Explanations:**
*   **-f**: Stop on first valid password.

### Verbose Mode
Shows error and attempt details.
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M http -v 6
\`\`\`
**Argument Explanations:**
*   **-v 6**: Detail level (6 = debug).

### Thread Setting
Determines the number of parallel attempts (Speed control).
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M ssh -t 10
\`\`\`
**Argument Explanations:**
*   **-t**: Number of threads.

### Write Output to File
Saves results to a file.
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M ssh -O results.txt
\`\`\`
**Argument Explanations:**
*   **-O**: Output file.

### Retry Setting
Determines how many times to retry in case of connection error.
\`\`\`bash
medusa -h 192.168.1.10 -u admin -P passwords.txt -M ssh -R 3
\`\`\`
**Argument Explanations:**
*   **-R**: Retry count.

## 4. Advanced Usage

### Module Parameters
Some modules (e.g., http, snmp) require special parameters. Module-specific settings can be passed with the \`-m\` flag.
\`\`\`bash
medusa -M http -m DIR:/admin -m FORM:user=^USER^&pass=^PASS^
\`\`\`

### Empty Password Check
Special lists or module settings can be used to try the username as the password or an empty password.

### Resume Feature
Medusa does not fully support resuming from where it left off by default, so output files (\`-O\`) and logging are important for large scans.

### SSL/TLS Support
For services using SSL (HTTPS, FTPS, IMAPS), the module usually auto-detects, or \`-s\` (in some versions) or a module parameter might be needed.

### Timeout Management
Using \`-n\` (port) or global timeout settings is important to manage network delays.

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments

**Command:**
\`\`\`bash
medusa -h 192.168.1.10
\`\`\`
**Description:**
Specifies a single target.
**Argument Explanations:**
*   **-h**: Target host.

**Command:**
\`\`\`bash
medusa -H targets.txt
\`\`\`
**Description:**
Specifies a target list.
**Argument Explanations:**
*   **-H**: Target file.

**Command:**
\`\`\`bash
medusa -U users.txt
\`\`\`
**Description:**
User list.
**Argument Explanations:**
*   **-U**: User file.

**Command:**
\`\`\`bash
medusa -u admin
\`\`\`
**Description:**
Single username.
**Argument Explanations:**
*   **-u**: Username.

**Command:**
\`\`\`bash
medusa -P pass.txt
\`\`\`
**Description:**
Password list.
**Argument Explanations:**
*   **-P**: Password file.

**Command:**
\`\`\`bash
medusa -p 123456
\`\`\`
**Description:**
Single password.
**Argument Explanations:**
*   **-p**: Password string.

**Command:**
\`\`\`bash
medusa -M ssh
\`\`\`
**Description:**
Module to use.
**Argument Explanations:**
*   **-M**: Module name.

**Command:**
\`\`\`bash
medusa -n 2222
\`\`\`
**Description:**
Non-standard port specification.
**Argument Explanations:**
*   **-n**: Port number.

**Command:**
\`\`\`bash
medusa -O out.txt
\`\`\`
**Description:**
Output file.
**Argument Explanations:**
*   **-O**: File path.

**Command:**
\`\`\`bash
medusa -t 20
\`\`\`
**Description:**
Number of concurrent connections.
**Argument Explanations:**
*   **-t**: Thread count.

**Command:**
\`\`\`bash
medusa -V
\`\`\`
**Description:**
Basic verbose mode.
**Argument Explanations:**
*   **-V**: Verbose.

**Command:**
\`\`\`bash
medusa -v 6
\`\`\`
**Description:**
Maximum detail level.
**Argument Explanations:**
*   **-v 6**: Debug level.

**Command:**
\`\`\`bash
medusa -f
\`\`\`
**Description:**
Stops on first successful login per host.
**Argument Explanations:**
*   **-f**: Stop on first success (per host).

**Command:**
\`\`\`bash
medusa -F
\`\`\`
**Description:**
Stops entire scan upon finding a successful login on any host.
**Argument Explanations:**
*   **-F**: Stop on first success (global).

**Command:**
\`\`\`bash
medusa -R 3
\`\`\`
**Description:**
Retries 3 times on error.
**Argument Explanations:**
*   **-R**: Retry count.

### Proxy / Network

**Command:**
\`\`\`bash
medusa --proxy http://127.0.0.1:8080
\`\`\`
**Description:**
Defines a proxy server (in supported versions).
**Argument Explanations:**
*   **--proxy**: Proxy URL.

**Command:**
\`\`\`bash
medusa --net-delay 2
\`\`\`
**Description:**
Adds a 2-second delay between requests.
**Argument Explanations:**
*   **--net-delay**: Delay time.

**Command:**
\`\`\`bash
medusa --conn-timeout 10
\`\`\`
**Description:**
Connection timeout duration.
**Argument Explanations:**
*   **--conn-timeout**: Timeout seconds.

### Scanning / Enumeration

**Command:**
\`\`\`bash
medusa -d
\`\`\`
**Description:**
Lists loaded modules.
**Argument Explanations:**
*   **-d**: Dump modules.

**Command:**
\`\`\`bash
medusa -q
\`\`\`
**Description:**
Quiet mode (shows only successful logins).
**Argument Explanations:**
*   **-q**: Quiet mode.

## 6. Real Pentest Scenarios

### SSH Brute-Force High Speed + Thread Tuning
\`\`\`bash
medusa -h 10.10.10.5 -u root -P rockyou.txt -M ssh -t 20 -f
\`\`\`
**Description:**
Performs a fast attack on SSH service with 20 threads, stops on first password.

### Dictionary Attack on FTP Service
\`\`\`bash
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M ftp -n 21
\`\`\`
**Description:**
Conducts a dictionary attack on FTP service with user and password lists.

### SMB NTLM Brute-Force (Domain + Careful Lockout Use)
\`\`\`bash
medusa -h 10.10.10.5 -u Administrator -P passwords.txt -M smbnt -m WORKGROUP
\`\`\`
**Description:**
Attacks SMB service with NTLM authentication, specifying domain/workgroup.

### HTTP Basic Auth Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M http -m DIR:/protected
\`\`\`
**Description:**
Attacks a directory protected by HTTP Basic Authentication.

### HTTP Form-Based Login Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M http -m FORM:"user=^USER^&pass=^PASS^"
\`\`\`
**Description:**
Attacks a web form login page by manipulating POST parameters.

### MySQL Root Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -u root -P passwords.txt -M mysql
\`\`\`
**Description:**
Tries passwords for the MySQL database root user.

### MSSQL User Discovery + Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -U users.txt -P passwords.txt -M mssql
\`\`\`
**Description:**
Attacks MSSQL service with a user list.

### RDP Brute-Force + Timeout Tuning
\`\`\`bash
medusa -h 10.10.10.5 -u Administrator -P passwords.txt -M rdp -t 1 --conn-timeout 15
\`\`\`
**Description:**
Attacks RDP service (usually slow) with single thread and high timeout.

### Brute-Force via Proxy (Corporate Network)
\`\`\`bash
proxychains medusa -h 10.10.10.5 -u admin -P passwords.txt -M ssh
\`\`\`
**Description:**
Tunnels through corporate proxy using \`proxychains\` if Medusa's native proxy support is limited.

### High Stealth Brute-Force via Tor
\`\`\`bash
proxychains medusa -h target.com -u admin -P passwords.txt -M ssh
\`\`\`
**Description:**
Stealth attack over Tor network (will be slow).

### Incremental Brute-Force for Rate-Limit Detection
\`\`\`bash
medusa -h 10.10.10.5 -u admin -p 123456 -M http -r 10
\`\`\`
**Description:**
Measures rate-limit response by sending requests at specific intervals.

### Speed Test on Non-Captcha Endpoints
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M http -t 50
\`\`\`
**Description:**
High thread speed test on forms without Captcha protection.

### WAF Bypass Attempt with Custom Header
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M http -m "HEADER:X-Forwarded-For:127.0.0.1"
\`\`\`
**Description:**
Attempts to bypass IP restriction by adding a custom header to the HTTP request.

### Non-Standard Port Brute-Force
\`\`\`bash
medusa -h 10.10.10.5 -u root -P passwords.txt -M ssh -n 2222
\`\`\`
**Description:**
Attacks SSH service running on port 2222.

### Distributed Brute-Force (Multi-IP)
\`\`\`bash
# (Run on multiple machines splitting the target list)
medusa -H targets_part1.txt ...
\`\`\`
**Description:**
Distributes load by scanning from different machines with split target lists.

### Low Speed Brute-Force for Lockout Threshold Analysis
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M smbnt -t 1 --net-delay 30
\`\`\`
**Description:**
Adds 30 seconds between attempts to prevent account lockout.

### Response Behavior Analysis for Honeyservice Detection
\`\`\`bash
medusa -h 10.10.10.5 -u fakeuser -p fakepass -M ssh -v 6
\`\`\`
**Description:**
Examines response to non-existent user (honeypot suspicion) in debug mode.

### Disabling Certificate Verification on SSL Mandatory Services
\`\`\`bash
medusa -h 10.10.10.5 -u admin -P passwords.txt -M http -m SSL
\`\`\`
**Description:**
Connects via SSL (ignoring certificate errors depends on the module).

### API Key Brute-Force (via HTTP Header)
\`\`\`bash
medusa -h 10.10.10.5 -u key -P keys.txt -M http -m "HEADER:Authorization: Bearer ^PASS^"
\`\`\`
**Description:**
Tries values from password list embedded in Authorization header.

### VPN Portal Brute-Force Behavior Analysis
\`\`\`bash
medusa -h vpn.target.com -u user -P passwords.txt -M http -m DIR:/vpn/login
\`\`\`
**Description:**
Login attempt against VPN web portal.

## 8. Best Practices (Expert Level)

*   **Thread Tuning**: Adjust threads according to service (RDP: 1-2, SSH: 4-8, FTP/HTTP: 10-20).
*   **Lockout Policy**: Use \`--net-delay\` in Active Directory environments to prevent account lockout.
*   **Proxy/Tor**: Use proxychains for privacy or access, but increase timeout values.
*   **HTTP Form Parsing**: Correctly parse form parameters (user, pass, hidden fields) and write in \`-m FORM:...\` format.
*   **SMB Domain**: Don't forget \`-m WORKGROUP\` or \`-m DOMAIN\` parameter in domain environments.
*   **Output**: Always write to file with \`-O\` to avoid losing results.
*   **Stop on Success**: Use \`-f\` to save time if a single valid password is enough.
*   **Service Verification**: Confirm port is open and service is correct with Nmap before running Medusa.
*   **Rate-Limit**: Dynamically reduce thread count by monitoring server response times.

## 9. Common Mistakes

*   **Wrong Module**: Using \`http\` module without parameters for web form (tries Basic Auth, form won't work).
*   **Fast Scan & Lockout**: Locking out all users by scanning at high speed in AD environment.
*   **Low Timeout**: Missing valid passwords due to low timeout on slow networks or services like RDP.
*   **SSL Neglect**: Attacking HTTPS service with plain HTTP module.
*   **Parameter Error**: Incorrect use of \`^USER^\` and \`^PASS^\` placeholders in HTTP form attack.
*   **Proxy Auth**: Forgetting to configure proxy authentication if required.
*   **Output Format**: Printing results to screen and not saving, failing to analyze later.
*   **DoS Effect**: Crashing old servers or services with very high thread counts.
`;

async function addMedusa() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Medusa cheatsheet...');

        // Using "Password Attacks" category as consolidated previously
        let category = await Category.findOne({ 'name.en': 'Password Attacks' });
        if (!category) {
            console.log('Category "Password Attacks" not found, creating...');
            category = await Category.create({
                name: { tr: 'Parola Saldırıları', en: 'Password Attacks' },
                description: { tr: 'Parola kırma ve brute-force araçları', en: 'Password cracking and brute-force tools' },
                slug: 'password-attacks',
                icon: 'Lock'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Medusa Cheat Sheet',
                en: 'Medusa Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['medusa', 'brute-force', 'password-cracking', 'ssh', 'ftp', 'rdp', 'smb', 'http']
        };

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Medusa Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Medusa cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addMedusa();
