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

const contentTR = `# Ncrack - Network Authentication Cracking Tool

## 1. Kısa Tanım
**Ncrack**, Nmap projesinin bir parçası olarak geliştirilen, yüksek hızlı, modüler ve olay tabanlı (event-driven) bir ağ kimlik doğrulama kırma (brute-force) aracıdır. Büyük ağlarda birden fazla servise aynı anda saldırı düzenlemek için optimize edilmiştir.

## 2. Kurulum
**Linux (Kali/Debian):**
\`\`\`bash
sudo apt update && sudo apt install ncrack
\`\`\`
**Windows:**
Nmap resmi sitesinden Windows installer indirilebilir veya kaynak koddan derlenebilir.

## 3. Temel Kullanım

**Tek Bir Hedefe Basit Tarama:**
\`\`\`bash
ncrack -u admin -P /usr/share/wordlists/rockyou.txt 192.168.1.10
\`\`\`
**Açıklama:**
192.168.1.10 hedefindeki varsayılan portlarda çalışan servislere (SSH, RDP, FTP vb.) "admin" kullanıcısı ve belirtilen parola listesi ile saldırır.
**Argümanlar:**
*   **-u**: Tekil kullanıcı adı.
*   **-P**: Parola listesi dosyası.

## 4. Yaygın Kullanılan Komutlar

**Komut:**
\`\`\`bash
ncrack -p 22 --user root -P pass.txt 192.168.1.10
\`\`\`
**Açıklama:**
Sadece SSH servisine (port 22) root kullanıcısı ile brute-force yapar.
**Argüman Açıklamaları:**
*   **-p 22**: Hedef portu belirtir (SSH).
*   **--user**: Kullanıcı adı.

**Komut:**
\`\`\`bash
ncrack -v -u Administrator -P pass.txt rdp://192.168.1.50
\`\`\`
**Açıklama:**
Windows sunucusuna RDP protokolü üzerinden saldırır ve detaylı çıktı verir.
**Argüman Açıklamaları:**
*   **rdp://**: Protokolü açıkça belirtir.
*   **-v**: Verbose (detaylı) mod.

**Komut:**
\`\`\`bash
ncrack -U users.txt -P pass.txt 192.168.1.10
\`\`\`
**Açıklama:**
Kullanıcı listesi ve parola listesini kombinleyerek saldırır.
**Argüman Açıklamaları:**
*   **-U**: Kullanıcı listesi dosyası.

**Komut:**
\`\`\`bash
ncrack -iL hosts.txt -p 21,22,3389 -U users.txt -P pass.txt
\`\`\`
**Açıklama:**
Dosyadaki IP listesine, belirtilen portlarda (FTP, SSH, RDP) toplu saldırı yapar.
**Argüman Açıklamaları:**
*   **-iL**: Hedef IP listesi dosyası.

**Komut:**
\`\`\`bash
ncrack -T5 192.168.1.10
\`\`\`
**Açıklama:**
En agresif zamanlama şablonunu kullanarak çok hızlı tarama yapar.
**Argüman Açıklamaları:**
*   **-T5**: Insane modu (en hızlı, en az bekleme).

**Komut:**
\`\`\`bash
ncrack --user admin --pass 123456 smb://192.168.1.20
\`\`\`
**Açıklama:**
SMB servisine tek bir kullanıcı ve parola ile giriş denemesi yapar (Credential Testing).
**Argüman Açıklamaları:**
*   **--pass**: Tekil parola.

**Komut:**
\`\`\`bash
ncrack -g connection-limit=10 192.168.1.10
\`\`\`
**Açıklama:**
Eşzamanlı bağlantı sayısını sınırlar (Servisi çökertmemek için).
**Argüman Açıklamaları:**
*   **-g**: Global opsiyonlar.
*   **connection-limit**: Maksimum paralel bağlantı.

**Komut:**
\`\`\`bash
ncrack --resume ncrack.restore
\`\`\`
**Açıklama:**
Yarıda kesilen bir taramayı kaldığı yerden devam ettirir.
**Argüman Açıklamaları:**
*   **--resume**: Restore dosyasından devam et.

**Komut:**
\`\`\`bash
ncrack -p 5900 -u admin -P pass.txt 192.168.1.10,192.168.1.11
\`\`\`
**Açıklama:**
Birden fazla IP adresine VNC (5900) saldırısı yapar.

**Komut:**
\`\`\`bash
ncrack -m ssh:key=id_rsa 192.168.1.10
\`\`\`
**Açıklama:**
SSH modülüne özel parametre vererek private key ile deneme yapar.
**Argüman Açıklamaları:**
*   **-m**: Modül spesifik opsiyonlar.

## 5. Gelişmiş Kullanımlar (Uzman Seviye)

**Nmap ile Entegre Kullanım:**
\`\`\`bash
nmap -oX output.xml 192.168.1.0/24
ncrack -iX output.xml -U users.txt -P pass.txt
\`\`\`
Nmap tarama sonucunu (XML) girdi olarak alıp sadece açık servislere saldırır.

**Pairwise (Kullanıcı-Parola Eşleşmesi):**
\`\`\`bash
ncrack --pairwise 192.168.1.10 -U users.txt -P pass.txt
\`\`\`
Her kullanıcıyı sadece listedeki karşılık gelen parola ile dener (User1:Pass1, User2:Pass2). Credential Stuffing için idealdir.

**WinRM Brute-Force:**
\`\`\`bash
ncrack -p 5985 --user Administrator -P pass.txt winrm://10.0.0.5
\`\`\`
Windows Remote Management servisine saldırır.

**MSSQL SA Hesabı Kırma:**
\`\`\`bash
ncrack -p 1433 --user sa -P pass.txt mssql://192.168.1.100
\`\`\`
Veritabanı sunucusunun yetkili hesabını hedefler.

**Zamanlama ve Throttling Optimizasyonu:**
\`\`\`bash
ncrack -g connection-limit=5,auth-limit=2 192.168.1.10
\`\`\`
IDS/IPS'e yakalanmamak için bağlantı ve dakika başına deneme sayısını sınırlar.

## 6. Sık Kullanılan Argümanlar

| Argüman | Açıklama | Tipik Örnek |
| :--- | :--- | :--- |
| **-u / --user** | Tekil kullanıcı adı | \`-u root\` |
| **-U** | Kullanıcı listesi dosyası | \`-U users.txt\` |
| **-p / --pass** | Tekil parola | \`--pass 123456\` |
| **-P** | Parola listesi dosyası | \`-P rockyou.txt\` |
| **-iL** | Hedef IP listesi | \`-iL hosts.txt\` |
| **-iX** | Nmap XML girdisi | \`-iX scan.xml\` |
| **-T (0-5)** | Zamanlama şablonu | \`-T4\` (Aggressive) |
| **-oN / -oX** | Çıktı dosyası (Normal/XML) | \`-oN results.txt\` |
| **-f** | İlk bulguda dur (host başına) | \`-f\` |
| **-g** | Global ayarlar | \`-g connection-limit=10\` |
| **-m** | Modül ayarları | \`-m ssh:nofirsttime\` |

## 7. Çıktı Analizi

*   **Discovered credentials**: Başarılı giriş denemeleri bu başlık altında listelenir.
    *   Format: \`192.168.1.10 22/tcp ssh: 'root' 'toor'\`
*   **Authentication Errors**: Hedefin kimlik doğrulamayı reddettiği durumlar.
*   **Connection Errors**: Bağlantı zaman aşımı veya reddedilmesi (RST).

## 8. En İyi Uygulamalar

*   **Nmap Entegrasyonu**: Asla körü körüne tarama yapmayın, önce Nmap ile açık portları belirleyip \`-iX\` kullanın.
*   **Hız Ayarı**: Yerel ağda \`-T4\` veya \`-T5\` kullanın, internet üzerinden taramalarda \`-T3\` idealdir.
*   **Servis Önceliği**: Önce SSH ve RDP gibi yönetim servislerini hedefleyin, veritabanları daha yavaş yanıt verir.
*   **Log Analizi**: Başarılı sonuçları kaçırmamak için daima \`-oN\` ile dosyaya yazın.

## 9. Hatalar ve Çözümleri

*   **"Connection Refused"**: Hedef port kapalı veya firewall engelliyor. Nmap ile portu doğrulayın.
*   **"Timeout"**: Ağ yavaş veya \`-T5\` fazla agresif. \`-T3\`'e düşürün veya \`-g connection-limit\` azaltın.
*   **"Module not found"**: Desteklenmeyen bir protokol belirttiniz. \`ncrack -V\` ile modülleri kontrol edin.
`;

const contentEN = `# Ncrack - Network Authentication Cracking Tool

## 1. Short Definition
**Ncrack** is a high-speed, modular, event-driven network authentication cracking (brute-force) tool designed as part of the Nmap project. It is optimized for conducting simultaneous attacks on multiple services across large networks.

## 2. Installation
**Linux (Kali/Debian):**
\`\`\`bash
sudo apt update && sudo apt install ncrack
\`\`\`
**Windows:**
Download the installer from the official Nmap website or compile from source.

## 3. Basic Usage

**Simple Scan on a Single Target:**
\`\`\`bash
ncrack -u admin -P /usr/share/wordlists/rockyou.txt 192.168.1.10
\`\`\`
**Description:**
Attacks default services (SSH, RDP, FTP, etc.) on 192.168.1.10 using the user "admin" and the specified password list.
**Arguments:**
*   **-u**: Single username.
*   **-P**: Password list file.

## 4. Common Commands

**Command:**
\`\`\`bash
ncrack -p 22 --user root -P pass.txt 192.168.1.10
\`\`\`
**Description:**
Brute-forces only the SSH service (port 22) with the root user.
**Argument Explanations:**
*   **-p 22**: Specifies target port (SSH).
*   **--user**: Username.

**Command:**
\`\`\`bash
ncrack -v -u Administrator -P pass.txt rdp://192.168.1.50
\`\`\`
**Description:**
Attacks a Windows server via RDP protocol with verbose output.
**Argument Explanations:**
*   **rdp://**: Explicitly specifies the protocol.
*   **-v**: Verbose mode.

**Command:**
\`\`\`bash
ncrack -U users.txt -P pass.txt 192.168.1.10
\`\`\`
**Description:**
Attacks using a combination of a user list and a password list.
**Argument Explanations:**
*   **-U**: User list file.

**Command:**
\`\`\`bash
ncrack -iL hosts.txt -p 21,22,3389 -U users.txt -P pass.txt
\`\`\`
**Description:**
Bulk attack on a list of IPs for specified ports (FTP, SSH, RDP).
**Argument Explanations:**
*   **-iL**: Target IP list file.

**Command:**
\`\`\`bash
ncrack -T5 192.168.1.10
\`\`\`
**Description:**
Performs a very fast scan using the most aggressive timing template.
**Argument Explanations:**
*   **-T5**: Insane mode (fastest, least waiting).

**Command:**
\`\`\`bash
ncrack --user admin --pass 123456 smb://192.168.1.20
\`\`\`
**Description:**
Attempts login to SMB service with a single user and password (Credential Testing).
**Argument Explanations:**
*   **--pass**: Single password.

**Command:**
\`\`\`bash
ncrack -g connection-limit=10 192.168.1.10
\`\`\`
**Description:**
Limits the number of concurrent connections (to avoid crashing the service).
**Argument Explanations:**
*   **-g**: Global options.
*   **connection-limit**: Max parallel connections.

**Command:**
\`\`\`bash
ncrack --resume ncrack.restore
\`\`\`
**Description:**
Resumes an interrupted scan from where it left off.
**Argument Explanations:**
*   **--resume**: Continue from restore file.

**Command:**
\`\`\`bash
ncrack -p 5900 -u admin -P pass.txt 192.168.1.10,192.168.1.11
\`\`\`
**Description:**
VNC (5900) attack on multiple IP addresses.

**Command:**
\`\`\`bash
ncrack -m ssh:key=id_rsa 192.168.1.10
\`\`\`
**Description:**
Uses a private key for SSH authentication by passing module-specific parameters.
**Argument Explanations:**
*   **-m**: Module specific options.

## 5. Advanced Usage (Expert Level)

**Integrated Use with Nmap:**
\`\`\`bash
nmap -oX output.xml 192.168.1.0/24
ncrack -iX output.xml -U users.txt -P pass.txt
\`\`\`
Takes Nmap scan result (XML) as input and attacks only open services.

**Pairwise (User-Pass Matching):**
\`\`\`bash
ncrack --pairwise 192.168.1.10 -U users.txt -P pass.txt
\`\`\`
Tries each user only with the corresponding password in the list (User1:Pass1, User2:Pass2). Ideal for Credential Stuffing.

**WinRM Brute-Force:**
\`\`\`bash
ncrack -p 5985 --user Administrator -P pass.txt winrm://10.0.0.5
\`\`\`
Attacks Windows Remote Management service.

**MSSQL SA Account Cracking:**
\`\`\`bash
ncrack -p 1433 --user sa -P pass.txt mssql://192.168.1.100
\`\`\`
Targets the privileged account of a database server.

**Timing and Throttling Optimization:**
\`\`\`bash
ncrack -g connection-limit=5,auth-limit=2 192.168.1.10
\`\`\`
Limits connections and attempts per minute to avoid IDS/IPS detection.

## 6. Common Arguments

| Argument | Description | Typical Example |
| :--- | :--- | :--- |
| **-u / --user** | Single username | \`-u root\` |
| **-U** | User list file | \`-U users.txt\` |
| **-p / --pass** | Single password | \`--pass 123456\` |
| **-P** | Password list file | \`-P rockyou.txt\` |
| **-iL** | Target IP list | \`-iL hosts.txt\` |
| **-iX** | Nmap XML input | \`-iX scan.xml\` |
| **-T (0-5)** | Timing template | \`-T4\` (Aggressive) |
| **-oN / -oX** | Output file (Normal/XML) | \`-oN results.txt\` |
| **-f** | Stop at first found (per host) | \`-f\` |
| **-g** | Global settings | \`-g connection-limit=10\` |
| **-m** | Module settings | \`-m ssh:nofirsttime\` |

## 7. Output Analysis

*   **Discovered credentials**: Successful login attempts are listed under this header.
    *   Format: \`192.168.1.10 22/tcp ssh: 'root' 'toor'\`
*   **Authentication Errors**: Cases where the target rejected authentication.
*   **Connection Errors**: Connection timeouts or refusals (RST).

## 8. Best Practices

*   **Nmap Integration**: Never scan blindly; first identify open ports with Nmap and use \`-iX\`.
*   **Speed Setting**: Use \`-T4\` or \`-T5\` on local networks, \`-T3\` is ideal for internet scans.
*   **Service Priority**: Target management services like SSH and RDP first; databases respond slower.
*   **Log Analysis**: Always write to a file with \`-oN\` to avoid missing successful results.

## 9. Errors and Solutions

*   **"Connection Refused"**: Target port is closed or blocked by firewall. Verify with Nmap.
*   **"Timeout"**: Network is slow or \`-T5\` is too aggressive. Drop to \`-T3\` or reduce \`-g connection-limit\`.
*   **"Module not found"**: You specified an unsupported protocol. Check modules with \`ncrack -V\`.
`;

async function addNcrack() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Ncrack cheatsheet...');

        // 1. Find or create the category
        let category = await Category.findOne({ 'name.en': 'Password Attacks' });
        if (!category) {
            console.log('Category "Password Attacks" not found, creating...');
            category = await Category.create({
                name: { tr: 'Parola Saldırıları', en: 'Password Attacks' },
                description: { tr: 'Kaba kuvvet ve parola kırma araçları', en: 'Brute-force and password cracking tools' },
                slug: 'password-attacks',
                icon: 'Lock'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Ncrack Cheat Sheet',
                en: 'Ncrack Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['ncrack', 'brute-force', 'password', 'cracking', 'ssh', 'rdp', 'ftp']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Ncrack Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Ncrack cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addNcrack();
