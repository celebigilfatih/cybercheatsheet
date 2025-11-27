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

const contentTR = `# Amap - Application Mapper

## 3. Temel Kullanım

**Temel Çalışma Mantığı:**
Amap, port taramasından ziyade, açık portlarda çalışan servisleri (application layer) tanımlamak için kullanılır. Port numarasına bakmaz, servise özel paketler gönderip gelen yanıtları (banner/signature) veritabanıyla eşleştirir.

**Temel Servis Tespiti:**
\`\`\`bash
amap 192.168.1.1 80
\`\`\`
192.168.1.1 IP'sinin 80. portunda çalışan servisi tespit eder.

**Banner Grabbing:**
\`\`\`bash
amap -b 192.168.1.1 21
\`\`\`
→ **-b**: Sadece banner bilgisini çeker (signature eşleşmesi yapmaz).

**TCP Scanning:**
\`\`\`bash
amap -T 192.168.1.1 1-1024
\`\`\`
→ **-T**: Belirtilen port aralığında TCP connect scan yapar ve servisleri tanımlar.

**UDP Scanning:**
\`\`\`bash
amap -U 192.168.1.1 53
\`\`\`
→ **-U**: UDP portunda servis tespiti yapar.

## 4. İleri Seviye Kullanım

### TCP/UDP Advanced Fingerprinting
*   **TCP Fingerprinting**: Amap, servise özel trigger'lar gönderir (örn: HTTP GET, SMTP HELO). Gelen yanıtı \`appdefs.trig\` dosyasındaki imzalarla karşılaştırır.
*   **UDP Fingerprinting**: UDP stateless olduğu için daha zordur, Amap özel UDP payloadları göndererek yanıt almaya çalışır.

### Aggressive Mode Kullanım Stratejisi
*   Amap varsayılan olarak sadece portun beklediği protokolü dener. Ancak servisler standart dışı portlarda çalışabilir (örn: SSH 80. portta).
*   Tüm triggerları denemek için agresif mod kullanılmaz, ancak tüm portları tararken \`amap -A\` (Nmap'teki gibi değil, Amap'te map mode) yerine doğrudan IP ve Port verilir.

### Banner-based ve Pattern-based Match
*   **Banner-based (-b)**: Servisin "Welcome" mesajını okur. Hızlıdır ama değiştirilebilir.
*   **Pattern-based**: Gelen paketin hex içeriğinde belirli byte dizilerini arar. Daha güvenilirdir.

### Sessiz Fingerprinting (-q)
\`\`\`bash
amap -q 192.168.1.1 80
\`\`\`
→ **-q**: Kapalı portları veya tanımlanamayan servisleri ekrana basmaz, sadece kesinleşenleri gösterir.

### Özel Signature Ekleme
*   **Signature Dosyası**: \`appdefs.resp\` (yanıtlar) ve \`appdefs.trig\` (tetikleyiciler).
*   **Format**: \`protocol:port:response_regex:app_name\`
*   Kendi imzanızı ekleyerek özel uygulamaları (kurum içi yazılımlar) tanıtabilirsiniz.

### Amapcrack ile Brute-force
Amap paketi içinde gelen \`amapcrap\` aracı, servislere rastgele veri göndererek (fuzzing) çökme veya farklı yanıtlar arar, bu da fingerprinting için yeni imzalar oluşturabilir.

### Honeypot Tespiti
Honeypotlar genellikle her porta aynı standart banner'ı döner veya tüm triggerlara cevap verir. Amap ile bir portun birden fazla protokole (hem SSH, hem HTTP, hem FTP gibi) yanıt verip vermediğini kontrol ederek honeypot olduğu anlaşılabilir.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

**Komut:**
\`\`\`bash
amap -b -q -v 192.168.1.10 20-100
\`\`\`
**Açıklama:**
192.168.1.10 hedefinin 20-100 arası portlarını tarar, banner bilgilerini çeker, sessiz modda çalışır ancak verbose detay verir.

**Argüman Açıklamaları:**
*   **-b**: Banner grabbing modu.
*   **-q**: Quiet (sessiz) mod.
*   **-v**: Verbose (detaylı) çıktı.

**Temel Argümanlar:**
*   **-b**: Sadece banner bilgisini al (ASCII).
*   **-q**: Tanımlanamayan portları gösterme.
*   **-i**: Hedef listesi dosyası (Nmap grepable formatı destekler).
*   **-o**: Çıktı dosyası (örn: \`-o output.txt\`).
*   **-6**: IPv6 taraması yap.
*   **-U**: UDP portlarını tara.
*   **-T**: TCP portlarını tara (varsayılan).
*   **-v**: Verbose (detay seviyesini artır).
*   **-d**: Debug modu (tüm paket içeriğini dök).
*   **-S**: Özel signature dosyası yolu.
*   **-C**: Connect timeout (bağlantı zaman aşımı).
*   **-R**: Read timeout (okuma zaman aşımı).
*   **--resolve**: IP adreslerini hostname'e çözümler (Reverse DNS).

**Performans / Zamanlama Argümanları:**
*   **--max-parallel**: Aynı anda yapılacak maksimum bağlantı sayısı (varsayılan 32).
*   **--delay**: İstekler arası gecikme (saniye).
*   **--rand-dest**: Hedef IP listesini karıştırır.
*   **--rand-src-port**: Kaynak portu rastgele seçer.
*   **--retry**: Yanıt alınamazsa tekrar deneme sayısı.

**Stealth & Evasion:**
*   **--source-port**: Kaynak portu sabitler (örn: 53).
*   **--data-length**: Gönderilen paketlerin boyutunu değiştirir.
*   **--spoof-mac**: Kaynak MAC adresini değiştirir.
*   **--ttl**: IP paketlerinin TTL (Time To Live) değerini değiştirir.
*   **--fragment**: Paketleri parçalar (IDS atlatma).

**Çıktı ve Loglama:**
*   **-o**: Normal metin çıktısı.
*   **--xml**: Sonuçları XML formatında kaydeder.
*   **--grepable**: Grep ile aranabilir tek satırlık format.
*   **--append-output**: Dosyanın üzerine yazmak yerine sonuna ekler.

## 6. Gerçek Pentest Senaryoları

**Güvenlik Duvarı Arkasındaki Servisleri Fingerprint Etme:**
\`\`\`bash
amap -P -T 192.168.1.1 80,443,8080
\`\`\`
Portlar açık görünse bile firewall arkasında servis olmayabilir. Amap uygulama katmanında yanıt alarak servisin gerçekten orada olduğunu doğrular.

**Sahte Servis/Honeypot Ayıklama:**
\`\`\`bash
amap -v 192.168.1.1 1-65535
\`\`\`
Eğer binlerce port açık ve hepsi aynı banner'ı veriyorsa (örn: "Welcome"), bu bir honeypot'tur.

**Nmap'in Yanıldığı Durumlarda Doğrulama:**
Nmap bazen servisi "unknown" olarak işaretler. Amap'in farklı imza veritabanı bu durumda servisi tanıyabilir.
\`\`\`bash
amap 192.168.1.1 8888
\`\`\`

**UDP Servislerinin Agresif Fingerprinting'i:**
\`\`\`bash
amap -U -v 192.168.1.1 161,162,500
\`\`\`
SNMP ve IKE gibi UDP servislerini tanımlar.

**Kurumsal Network'te Port/Service Mapping:**
\`\`\`bash
amap -i nmap_results.gnmap -o amap_services.txt
\`\`\`
Nmap tarama sonucunu girdi olarak alıp, sadece açık portlarda detaylı servis analizi yapar.

**Web Servisleri ve Özel Portlar:**
\`\`\`bash
amap 192.168.1.10 8000,8080,8443
\`\`\`
Standart dışı portlarda çalışan web sunucularını (Apache, Nginx, IIS) tespit eder.

**SSL/TLS Dışındaki Protokollerin Banner Analizi:**
\`\`\`bash
amap -b 192.168.1.1 465,993,995
\`\`\`
SMTPS, IMAPS, POP3S gibi şifreli servislerin bannerlarını (sertifika öncesi) okur.

## 8. Best Practices (Uzman Seviye)

*   **Amap + Nmap Birlikte Kullanma:** Önce Nmap ile hızlı port taraması (\`-sS\`), sonra Amap ile detaylı servis analizi. Nmap'in \`-sV\`'si yavaştır, Amap bazen daha hızlı sonuç verir.
*   **UDP Fingerprinting:** UDP paketleri sıkça kaybolur, \`--retry\` sayısını artırın ve \`--delay\` ekleyin.
*   **Signature Optimize Etme:** Sadece ilgilendiğiniz servislerin imzalarını içeren özel bir dosya (\`-S\`) kullanarak taramayı hızlandırın.
*   **Paralellik Ayarı:** \`--max-parallel\` değerini ağın kapasitesine göre artırın (örn: 100), ancak firewall limitlerine dikkat edin.
*   **False-Positive Azaltma:** \`-v\` (verbose) modunda çalışarak eşleşme oranlarını ve nedenlerini inceleyin.
*   **Timeout Yönetimi:** \`-C\` (connect timeout) değerini düşürerek (örn: 2sn) ölü portlarda zaman kaybetmeyin.

## 9. Sık Yapılan Hatalar

*   **Yanlış Timeout Ayarları:** Yavaş servisler (örn: SMTP) yanıt vermeden bağlantı kesilirse servis kaçırılır.
*   **Sadece TCP Kullanıp UDP'yi Atlamak:** Kritik altyapı servisleri (DNS, SNMP, NTP) UDP kullanır, \`-U\` parametresini unutmayın.
*   **Banner-only Tespitine Güvenmek:** Bannerlar sysadminler tarafından kolayca değiştirilebilir ("Apache" yerine "Microsoft-IIS" yazılabilir).
*   **Çok Agresif Modda Yakalanmak:** Çok fazla paralel bağlantı IDS/IPS tarafından "port scan" olarak işaretlenir ve IP bloklanır.
*   **Output Kaydetmeyi Unutmak:** Uzun süren analizlerin sonucunu kaybetmemek için \`-o\` veya \`--xml\` kullanın.
*   **Nmap Sonuçlarını Valide Etmemek:** Nmap'in "open|filtered" dediği portları Amap ile doğrulamadan raporlamayın.
`;

const contentEN = `# Amap - Application Mapper

## 3. Basic Usage

**Basic Working Principle:**
Amap is used to identify services (application layer) running on open ports, rather than just port scanning. It doesn't rely on port numbers; it sends service-specific packets and matches the responses (banner/signature) against a database.

**Basic Service Detection:**
\`\`\`bash
amap 192.168.1.1 80
\`\`\`
Identifies the service running on port 80 of IP 192.168.1.1.

**Banner Grabbing:**
\`\`\`bash
amap -b 192.168.1.1 21
\`\`\`
→ **-b**: Fetches only the banner information (no signature matching).

**TCP Scanning:**
\`\`\`bash
amap -T 192.168.1.1 1-1024
\`\`\`
→ **-T**: Performs TCP connect scan on the specified range and identifies services.

**UDP Scanning:**
\`\`\`bash
amap -U 192.168.1.1 53
\`\`\`
→ **-U**: Performs service detection on UDP port.

## 4. Advanced Usage

### TCP/UDP Advanced Fingerprinting
*   **TCP Fingerprinting**: Amap sends service-specific triggers (e.g., HTTP GET, SMTP HELO). It compares the response with signatures in \`appdefs.trig\`.
*   **UDP Fingerprinting**: Harder since UDP is stateless; Amap sends specific UDP payloads to elicit a response.

### Aggressive Mode Strategy
*   By default, Amap only tries the protocol expected for that port. However, services can run on non-standard ports (e.g., SSH on port 80).
*   To test all triggers, you don't use a specific aggressive flag, but rather target the IP and Port directly to force identification.

### Banner-based vs Pattern-based Match
*   **Banner-based (-b)**: Reads the service's "Welcome" message. Fast but can be spoofed.
*   **Pattern-based**: Searches for specific byte sequences in the hex content of the response. More reliable.

### Quiet Fingerprinting (-q)
\`\`\`bash
amap -q 192.168.1.1 80
\`\`\`
→ **-q**: Does not display closed ports or unidentified services, only shows confirmed matches.

### Custom Signature Addition
*   **Signature Files**: \`appdefs.resp\` (responses) and \`appdefs.trig\` (triggers).
*   **Format**: \`protocol:port:response_regex:app_name\`
*   You can add your own signatures to identify custom applications (e.g., internal software).

### Brute-force with Amapcrack
The \`amapcrap\` tool included with Amap sends random data (fuzzing) to services to look for crashes or unique responses, which can help create new signatures.

### Honeypot Detection
Honeypots often return the same standard banner for every port or respond to all triggers. Amap can identify a honeypot if a port responds to multiple unrelated protocols (e.g., SSH, HTTP, and FTP simultaneously).

## 5. Annotated Commands (EXTENDED LIST)

**Command:**
\`\`\`bash
amap -b -q -v 192.168.1.10 20-100
\`\`\`
**Description:**
Scans ports 20-100 on target 192.168.1.10, grabs banners, runs in quiet mode but provides verbose details.

**Argument Explanations:**
*   **-b**: Banner grabbing mode.
*   **-q**: Quiet mode.
*   **-v**: Verbose output.

**Basic Arguments:**
*   **-b**: Get banner info only (ASCII).
*   **-q**: Do not show unidentified ports.
*   **-i**: Target list file (supports Nmap grepable format).
*   **-o**: Output file (e.g., \`-o output.txt\`).
*   **-6**: IPv6 scan.
*   **-U**: Scan UDP ports.
*   **-T**: Scan TCP ports (default).
*   **-v**: Verbose (increase detail level).
*   **-d**: Debug mode (dump all packet content).
*   **-S**: Custom signature file path.
*   **-C**: Connect timeout.
*   **-R**: Read timeout.
*   **--resolve**: Resolve IP addresses to hostnames (Reverse DNS).

**Performance / Timing Arguments:**
*   **--max-parallel**: Max parallel connections (default 32).
*   **--delay**: Delay between requests (seconds).
*   **--rand-dest**: Randomize target IP list.
*   **--rand-src-port**: Randomize source port.
*   **--retry**: Number of retries if no response.

**Stealth & Evasion:**
*   **--source-port**: Fix source port (e.g., 53).
*   **--data-length**: Change payload length.
*   **--spoof-mac**: Spoof source MAC address.
*   **--ttl**: Modify IP TTL (Time To Live).
*   **--fragment**: Fragment packets (IDS evasion).

**Output and Logging:**
*   **-o**: Normal text output.
*   **--xml**: Save results in XML format.
*   **--grepable**: Grepable one-line format.
*   **--append-output**: Append to file instead of overwriting.

## 6. Real Pentest Scenarios

**Fingerprinting Services Behind Firewall:**
\`\`\`bash
amap -P -T 192.168.1.1 80,443,8080
\`\`\`
Even if ports look open, there might be no service behind a firewall. Amap verifies the service is really there by getting an application-layer response.

**Filtering Fake Services/Honeypots:**
\`\`\`bash
amap -v 192.168.1.1 1-65535
\`\`\`
If thousands of ports are open and all give the same banner (e.g., "Welcome"), it's a honeypot.

**Verifying Nmap Uncertainties:**
Nmap sometimes marks a service as "unknown". Amap's different signature database might identify it.
\`\`\`bash
amap 192.168.1.1 8888
\`\`\`

**Aggressive UDP Service Fingerprinting:**
\`\`\`bash
amap -U -v 192.168.1.1 161,162,500
\`\`\`
Identifies UDP services like SNMP and IKE.

**Port/Service Mapping in Corporate Network:**
\`\`\`bash
amap -i nmap_results.gnmap -o amap_services.txt
\`\`\`
Takes Nmap scan results as input and performs detailed service analysis only on open ports.

**Web Services and Custom Ports:**
\`\`\`bash
amap 192.168.1.10 8000,8080,8443
\`\`\`
Detects web servers (Apache, Nginx, IIS) running on non-standard ports.

**Banner Analysis of Non-SSL/TLS Protocols:**
\`\`\`bash
amap -b 192.168.1.1 465,993,995
\`\`\`
Reads banners of encrypted services (SMTPS, IMAPS, POP3S) before SSL handshake.

## 8. Best Practices (Expert Level)

*   **Combine Amap + Nmap:** Use Nmap for fast port scanning (\`-sS\`), then Amap for detailed service analysis. Nmap's \`-sV\` is slow; Amap can be faster.
*   **UDP Fingerprinting:** UDP packets are often dropped; increase \`--retry\` and add \`--delay\`.
*   **Optimize Signatures:** Use a custom file (\`-S\`) with only relevant signatures to speed up scanning.
*   **Parallelism:** Increase \`--max-parallel\` (e.g., 100) based on network capacity, but watch out for firewall limits.
*   **Reduce False-Positives:** Run in \`-v\` (verbose) mode to inspect match rates and reasons.
*   **Timeout Management:** Lower \`-C\` (connect timeout) (e.g., 2s) to avoid wasting time on dead ports.

## 9. Common Mistakes

*   **Wrong Timeout Settings:** Slow services (e.g., SMTP) might be missed if connection cuts too early.
*   **Skipping UDP:** Critical infrastructure services (DNS, SNMP, NTP) use UDP; don't forget \`-U\`.
*   **Relying on Banners Only:** Banners are easily changed by sysadmins (e.g., writing "Microsoft-IIS" on Apache).
*   **Getting Caught by Aggressive Mode:** Too many parallel connections are flagged as "port scan" by IDS/IPS.
*   **Forgetting Output:** Use \`-o\` or \`--xml\` to save results of long analyses.
*   **Not Validating Nmap Results:** Don't report Nmap's "open|filtered" ports without verifying with Amap.
`;

async function addAmap() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Amap cheatsheet...');

        // 1. Find or create the category
        let category = await Category.findOne({ 'name.en': 'Network Scanning' });
        if (!category) {
            console.log('Category "Network Scanning" not found, creating...');
            category = await Category.create({
                name: { tr: 'Ağ Taraması', en: 'Network Scanning' },
                description: { tr: 'Ağ keşif ve port tarama araçları', en: 'Network discovery and port scanning tools' },
                slug: 'network-scanning',
                icon: 'Radar'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Amap Cheat Sheet',
                en: 'Amap Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['amap', 'fingerprinting', 'service', 'banner', 'scanning']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Amap Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Amap cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addAmap();
