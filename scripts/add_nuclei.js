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

const contentTR = `# Nuclei - Template Based Vulnerability Scanner

## 1. Araç Tanımı
**Nuclei**, hedef üzerinde template-tabanlı zafiyet taraması, misconfiguration tespiti, HTTP/DNS/Network/Cloud servis analizleri ve geniş ölçekli otomasyon sağlar. YAML tabanlı template yapısı sayesinde topluluk tarafından sürekli güncellenen binlerce zafiyet imzasına sahiptir ve CI/CD süreçlerine kolayca entegre edilebilir.

## 2. Kurulum
*   **Go**: \`go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest\`
*   **Binary**: GitHub release sayfasından indirilebilir.
*   **Docker**: \`docker pull projectdiscovery/nuclei\`

## 3. Temel Kullanım

### Temel Web Server Scanning
Hedef URL üzerinde varsayılan template'ler ile tarama yapar.
\`\`\`bash
nuclei -u https://target.com
\`\`\`
**Argüman Açıklamaları:**
*   **-u**: Hedef URL.

### Çoklu Hedef Testi
Bir dosyadaki URL listesini tarar.
\`\`\`bash
nuclei -list targets.txt
\`\`\`
**Argüman Açıklamaları:**
*   **-list**: Hedef listesi dosyası.

### Template Seçimi
Belirli bir template veya template dizini ile tarama yapar.
\`\`\`bash
nuclei -u target.com -t cves/2023/
\`\`\`
**Argüman Açıklamaları:**
*   **-t**: Template veya dizin yolu.

### Severity Filtreleme
Sadece belirli kritik seviyedeki (Critical, High) zafiyetleri tarar.
\`\`\`bash
nuclei -u target.com -severity critical,high
\`\`\`
**Argüman Açıklamaları:**
*   **-severity**: Zafiyet seviyesi.

### Etiket (Tag) Bazlı Tarama
Belirli etiketlere sahip template'leri çalıştırır (örn: cve, panel, exposure).
\`\`\`bash
nuclei -u target.com -tags cve,osint
\`\`\`
**Argüman Açıklamaları:**
*   **-tags**: Template etiketleri.

### Çıktı Formatı
Sonuçları JSON formatında dosyaya kaydeder.
\`\`\`bash
nuclei -u target.com -json -o results.json
\`\`\`
**Argüman Açıklamaları:**
*   **-json**: JSON çıktısı üret.
*   **-o**: Çıktı dosyası.

### Proxy Kullanımı
Trafiği bir proxy (örn: Burp Suite) üzerinden geçirir.
\`\`\`bash
nuclei -u target.com -proxy http://127.0.0.1:8080
\`\`\`
**Argüman Açıklamaları:**
*   **-proxy**: Proxy URL.

### Rate Limit Ayarı
Saniyede gönderilecek istek sayısını sınırlar.
\`\`\`bash
nuclei -u target.com -rate-limit 50
\`\`\`
**Argüman Açıklamaları:**
*   **-rate-limit**: Saniyedeki istek sayısı.

### Custom Header Ekleme
İsteklere özel header ekler.
\`\`\`bash
nuclei -u target.com -header "X-Bug-Bounty: user123"
\`\`\`
**Argüman Açıklamaları:**
*   **-header**: Header bilgisi.

### Template Güncelleme
Nuclei template veritabanını günceller.
\`\`\`bash
nuclei -update-templates
\`\`\`

## 4. İleri Seviye Kullanım

### Nuclei Fingerprinting Metodolojisi
Nuclei, HTTP yanıtlarındaki header, body, status code ve süre gibi metrikleri YAML kuralları ile eşleştirerek fingerprinting yapar.

### Banner-based Detection
Servis bannerlarını (SSH, FTP, SMTP) regex ile analiz ederek versiyon tespiti yapar.

### Heuristic Scanning Mantığı
Bilinmeyen parametreler veya yollar için fuzzing benzeri davranışlar sergileyerek anomali tespiti yapar.

### Signature-based Analiz
Bilinen CVE ve zafiyet imzalarını (matcher) kullanarak kesin tespitler yapar.

### Anti-WAF/IPS Modları
\`-unsafe\` modu ile raw HTTP istekleri göndererek veya \`-header\` manipülasyonu ile WAF atlatmayı dener.

### False-Positive Engelleme
Template içindeki \`matchers-condition: and\` yapısı ile birden fazla koşulun sağlanmasını bekleyerek hatalı tespitleri azaltır.

### Tam Manuel Payload Gönderme
Workflow ve dynamic template özellikleri ile karmaşık saldırı senaryoları (login -> extract token -> attack) oluşturulabilir.

### Custom Scan DB Tanımlama
Kendi yazdığınız template'leri \`~/nuclei-templates/custom\` dizininde saklayarak taramalara dahil edebilirsiniz.

### Custom Plugin Kullanımı
Nuclei Go kütüphanesi olarak kullanılarak özel araçlara entegre edilebilir.

### CDN Arkasındaki Gerçek Server Tespiti
DNS ve SSL sertifika analiz template'leri ile origin IP sızıntılarını arar.

### SSL Cipher Enumeration
SSL/TLS el sıkışma (handshake) template'leri ile zayıf şifreleme algoritmalarını tespit eder.

### Rate Limiting Davranışı Gözlemleme
Sunucunun yanıt sürelerini ve hata kodlarını (429) izleyerek tarama hızını dinamik olarak ayarlayabilir (bazı flagler ile).

### User-Agent Spoofing
\`-header "User-Agent: ..."\` ile tarayıcı taklidi yapılır.

### Header Manipulation
WAF bypass veya host header injection testleri için özel headerlar kullanılır.

### Evasion Teknikleri
Parçalanmış paketler veya HTTP smuggling teknikleri (template bazlı) ile güvenlik cihazlarını atlatır.

### Passive vs Active Detection Farkı
Nuclei varsayılan olarak aktiftir ancak \`-passive\` flag'i ile sadece yanıtları analiz edebilir (desteklenen template'lerde).

### Nuclei → Burp / Proxy Chaining Entegrasyonu
Tüm trafiği Burp'e yönlendirerek zafiyetlerin manuel doğrulanmasını sağlar.

### Nuclei → Nmap / Masscan Veri Birleştirme Mantığı
Port tarama araçlarının çıktısını (IP:Port) Nuclei'ye pipe (\`|\`) ile vererek servis bazlı tarama yapılır.

### Web Server Anomaly Detection Mantığı
Beklenmeyen içerik tipleri veya boyutları üzerinden anomali tespiti yapar.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar

**Komut:**
\`\`\`bash
nuclei -u https://target.com
\`\`\`
**Açıklama:**
Tek bir hedef üzerinde varsayılan tarama.
**Argüman Açıklamaları:**
*   **-u**: Hedef URL.

**Komut:**
\`\`\`bash
nuclei -list urls.txt
\`\`\`
**Açıklama:**
Listeden toplu tarama.
**Argüman Açıklamaları:**
*   **-list**: Hedef dosyası.

**Komut:**
\`\`\`bash
nuclei -u target.com -t cves/
\`\`\`
**Açıklama:**
Sadece CVE template'lerini kullanır.
**Argüman Açıklamaları:**
*   **-t**: Template dizini.

**Komut:**
\`\`\`bash
nuclei -u target.com -templates custom-templates/
\`\`\`
**Açıklama:**
Özel template dizinini kullanır.
**Argüman Açıklamaları:**
*   **-templates**: Template dizini (alternatif).

**Komut:**
\`\`\`bash
nuclei -u target.com -severity critical,high
\`\`\`
**Açıklama:**
Kritik ve yüksek seviyeli zafiyetleri tarar.
**Argüman Açıklamaları:**
*   **-severity**: Seviye filtresi.

**Komut:**
\`\`\`bash
nuclei -u target.com -tags cve,rce
\`\`\`
**Açıklama:**
CVE ve RCE etiketli template'leri çalıştırır.
**Argüman Açıklamaları:**
*   **-tags**: Etiket filtresi.

**Komut:**
\`\`\`bash
nuclei -project
\`\`\`
**Açıklama:**
Proje bazlı tarama yaparak tekrar eden istekleri engeller.
**Argüman Açıklamaları:**
*   **-project**: Proje modunu açar.

**Komut:**
\`\`\`bash
nuclei -project-path ./myproject
\`\`\`
**Açıklama:**
Proje verilerinin saklanacağı dizini belirtir.
**Argüman Açıklamaları:**
*   **-project-path**: Proje yolu.

**Komut:**
\`\`\`bash
nuclei -u target.com -include-templates specific.yaml
\`\`\`
**Açıklama:**
Sadece belirtilen template'i dahil eder.
**Argüman Açıklamaları:**
*   **-include-templates**: Dahil edilecek template.

**Komut:**
\`\`\`bash
nuclei -u target.com -exclude-templates fuzzing/
\`\`\`
**Açıklama:**
Fuzzing template'lerini hariç tutar.
**Argüman Açıklamaları:**
*   **-exclude-templates**: Hariç tutulacaklar.

### Proxy / Network

**Komut:**
\`\`\`bash
nuclei -u target.com -proxy http://127.0.0.1:8080
\`\`\`
**Açıklama:**
HTTP proxy kullanır.
**Argüman Açıklamaları:**
*   **-proxy**: Proxy adresi.

**Komut:**
\`\`\`bash
nuclei -u target.com -proxy-socks socks5://127.0.0.1:9050
\`\`\`
**Açıklama:**
SOCKS proxy (Tor vb.) kullanır.
**Argüman Açıklamaları:**
*   **-proxy-socks**: SOCKS proxy adresi.

**Komut:**
\`\`\`bash
nuclei -u target.com -interface eth0
\`\`\`
**Açıklama:**
Belirli bir ağ arayüzünü kullanır.
**Argüman Açıklamaları:**
*   **-interface**: Ağ arayüzü.

**Komut:**
\`\`\`bash
nuclei -u target.com -ip-version 6
\`\`\`
**Açıklama:**
IPv6 kullanmaya zorlar.
**Argüman Açıklamaları:**
*   **-ip-version**: IP versiyonu (4 veya 6).

**Komut:**
\`\`\`bash
nuclei -u target.com -rate-limit 100
\`\`\`
**Açıklama:**
Saniyede 100 istek gönderir.
**Argüman Açıklamaları:**
*   **-rate-limit**: İstek hızı.

**Komut:**
\`\`\`bash
nuclei -u target.com -bulk-size 50
\`\`\`
**Açıklama:**
Aynı anda 50 paralel template çalıştırır.
**Argüman Açıklamaları:**
*   **-bulk-size**: Paralellik sayısı.

**Komut:**
\`\`\`bash
nuclei -u target.com -unsafe
\`\`\`
**Açıklama:**
Raw HTTP istekleri kullanarak bazı kısıtlamaları aşar.
**Argüman Açıklamaları:**
*   **-unsafe**: Unsafe modu.

### Payload & Request Manipulation

**Komut:**
\`\`\`bash
nuclei -u target.com -header "Authorization: Bearer token"
\`\`\`
**Açıklama:**
Özel header ekler.
**Argüman Açıklamaları:**
*   **-header**: Header string.

**Komut:**
\`\`\`bash
nuclei -u target.com -metadata
\`\`\`
**Açıklama:**
Template metadata bilgilerini gösterir.
**Argüman Açıklamaları:**
*   **-metadata**: Metadata gösterimi.

**Komut:**
\`\`\`bash
nuclei -u target.com -var username=admin
\`\`\`
**Açıklama:**
Template içindeki değişkenlere değer atar.
**Argüman Açıklamaları:**
*   **-var**: Değişken tanımlama.

**Komut:**
\`\`\`bash
nuclei -u target.com -var-file vars.txt
\`\`\`
**Açıklama:**
Dosyadan değişken değerleri okur.
**Argüman Açıklamaları:**
*   **-var-file**: Değişken dosyası.

**Komut:**
\`\`\`bash
nuclei -u target.com -body "json_data"
\`\`\`
**Açıklama:**
İstek gövdesine veri ekler (bazı durumlarda).
**Argüman Açıklamaları:**
*   **-body**: Body içeriği.

### Scanning / Enumeration

**Komut:**
\`\`\`bash
nuclei -update-templates
\`\`\`
**Açıklama:**
Template'leri günceller.
**Argüman Açıklamaları:**
*   **-update-templates**: Güncelleme komutu.

**Komut:**
\`\`\`bash
nuclei -update
\`\`\`
**Açıklama:**
Nuclei motorunu günceller.
**Argüman Açıklamaları:**
*   **-update**: Motor güncelleme.

**Komut:**
\`\`\`bash
nuclei -validate
\`\`\`
**Açıklama:**
Template'lerin sözdizimini doğrular.
**Argüman Açıklamaları:**
*   **-validate**: Doğrulama modu.

**Komut:**
\`\`\`bash
nuclei -templates-version
\`\`\`
**Açıklama:**
Yüklü template versiyonunu gösterir.
**Argüman Açıklamaları:**
*   **-templates-version**: Versiyon bilgisi.

**Komut:**
\`\`\`bash
nuclei -headless
\`\`\`
**Açıklama:**
Headless (tarayıcı tabanlı) tarama yapar.
**Argüman Açıklamaları:**
*   **-headless**: Headless modu.

**Komut:**
\`\`\`bash
nuclei -verbose
\`\`\`
**Açıklama:**
Detaylı çıktı verir.
**Argüman Açıklamaları:**
*   **-verbose**: Verbose modu.

### Output

**Komut:**
\`\`\`bash
nuclei -u target.com -o output.txt
\`\`\`
**Açıklama:**
Sonuçları dosyaya yazar.
**Argüman Açıklamaları:**
*   **-o**: Dosya adı.

**Komut:**
\`\`\`bash
nuclei -u target.com -json
\`\`\`
**Açıklama:**
JSON formatında çıktı verir.
**Argüman Açıklamaları:**
*   **-json**: JSON formatı.

**Komut:**
\`\`\`bash
nuclei -u target.com -markdown-export report_dir/
\`\`\`
**Açıklama:**
Markdown formatında rapor oluşturur.
**Argüman Açıklamaları:**
*   **-markdown-export**: Rapor dizini.

**Komut:**
\`\`\`bash
nuclei -u target.com -no-color
\`\`\`
**Açıklama:**
Renkli çıktıyı kapatır.
**Argüman Açıklamaları:**
*   **-no-color**: Renksiz mod.

**Komut:**
\`\`\`bash
nuclei -u target.com -silent
\`\`\`
**Açıklama:**
Sadece bulunan zafiyetleri ekrana basar.
**Argüman Açıklamaları:**
*   **-silent**: Sessiz mod.

## 6. Gerçek Pentest Senaryoları

### CDN Arkasındaki Gerçek IP Tespiti
\`\`\`bash
nuclei -u target.com -tags cdn,origin -verbose
\`\`\`
**Açıklama:**
CDN ve origin tespitiyle ilgili etiketlenmiş template'leri kullanarak gerçek IP'yi bulmaya çalışır.

### Reverse Proxy Arkasında Servis Fingerprinting
\`\`\`bash
nuclei -u target.com -tags tech-detect,fingerprint
\`\`\`
**Açıklama:**
Teknoloji tespiti template'leri ile proxy arkasındaki backend servislerini (Java, Python, IIS vb.) belirler.

### WAF Karşısında Payload Evasion + Header Manipulation
\`\`\`bash
nuclei -u target.com -t cves/ -header "X-Forwarded-For: 127.0.0.1" -unsafe
\`\`\`
**Açıklama:**
Unsafe modu ve header manipülasyonu ile WAF kurallarını atlatarak CVE taraması yapar.

### Rate-Limit Analizi ile WAF Davranışı Çözümleme
\`\`\`bash
nuclei -u target.com -rate-limit 150 -verbose
\`\`\`
**Açıklama:**
Yüksek hızda istek göndererek WAF'ın ne zaman blokladığını (429/403) analiz eder.

### Custom Template ile Misconfiguration Tespiti
\`\`\`bash
nuclei -u target.com -t my-custom-templates/misconfigs/
\`\`\`
**Açıklama:**
Kendi yazdığınız özel template'ler ile spesifik yanlış yapılandırmaları arar.

### SSL/TLS Misconfiguration & Cipher Enumeration
\`\`\`bash
nuclei -u target.com -tags ssl,tls
\`\`\`
**Açıklama:**
SSL/TLS konfigürasyonlarını ve zayıf şifreleme algoritmalarını denetler.

### HSTS Kontrolü
\`\`\`bash
nuclei -u target.com -t http/misconfiguration/hsts-missing.yaml
\`\`\`
**Açıklama:**
Strict-Transport-Security başlığının eksikliğini kontrol eder.

### Default Admin Panel Discovery
\`\`\`bash
nuclei -u target.com -tags panel,admin
\`\`\`
**Açıklama:**
Bilinen admin panellerini ve giriş sayfalarını tespit eder.

### Directory Traversal + Özel Template Taraması
\`\`\`bash
nuclei -u target.com -tags lfi,traversal
\`\`\`
**Açıklama:**
LFI ve Directory Traversal zafiyetlerine odaklanmış template'leri çalıştırır.

### Basic Auth Brute-Force Davranış Analizi
\`\`\`bash
nuclei -u target.com -t http/exposures/basic-auth.yaml
\`\`\`
**Açıklama:**
Basic Auth korumalı alanları tespit eder (Brute-force için Hydra kullanın).

### Proxy Üzerinden Tarama (Kurumsal Ağ)
\`\`\`bash
nuclei -u target.com -proxy http://proxy.corp:8080
\`\`\`
**Açıklama:**
Kurumsal proxy üzerinden dış hedefleri tarar.

### Tor Üzerinden Stealth Scanning
\`\`\`bash
nuclei -u target.com -proxy-socks socks5://127.0.0.1:9050
\`\`\`
**Açıklama:**
Tor ağı üzerinden anonim tarama yapar.

### Cookie Manipulation ile Oturum Güvenliği Testi
\`\`\`bash
nuclei -u target.com -header "Cookie: session=test" -tags cookie
\`\`\`
**Açıklama:**
Özel cookie değeri ile oturum yönetimi zafiyetlerini test eder.

### Reflected Response Farklılıkları ile Fingerprinting
\`\`\`bash
nuclei -u target.com -tags reflection
\`\`\`
**Açıklama:**
Gönderilen girdilerin yanıta yansımasını analiz eder.

### Large Request Göndererek Throttle Testi
\`\`\`bash
nuclei -u target.com -t http/dos/
\`\`\`
**Açıklama:**
DoS potansiyeli olan endpointleri (dikkatli kullanın) test eder.

### Weird Header Injection ile Server Behavior Analizi
\`\`\`bash
nuclei -u target.com -tags header-injection
\`\`\`
**Açıklama:**
Anlamsız veya özel headerlar ile sunucu tepkisini ölçer.

### Web Server Signature Spoofing Tespiti
\`\`\`bash
nuclei -u target.com -tags fingerprint
\`\`\`
**Açıklama:**
Sunucu imzası ile gerçek davranış arasındaki farkları arar.

### CORS Misconfiguration Analizi
\`\`\`bash
nuclei -u target.com -tags cors
\`\`\`
**Açıklama:**
Cross-Origin Resource Sharing (CORS) yapılandırma hatalarını tespit eder.

### Information Leak Tespiti
\`\`\`bash
nuclei -u target.com -tags exposure,token
\`\`\`
**Açıklama:**
API key, token veya hassas bilgi sızıntılarını arar.

### Passive vs Active Fingerprinting Farkı
\`\`\`bash
nuclei -u target.com -passive
\`\`\`
**Açıklama:**
Sadece pasif bilgi toplama yapar (desteklenen template'ler ile).

### Nuclei + Burp + Nmap Korelasyonu (Gerçek Senaryo)
\`\`\`bash
nmap -p80,443 target.com -oG - | nuclei -proxy http://127.0.0.1:8080
\`\`\`
**Açıklama:**
Nmap çıktısını Nuclei'ye verir, Nuclei de trafiği Burp'e yönlendirir.

## 8. Best Practices (Uzman Seviye)

*   **Güncel Template**: Her zaman \`nuclei -update-templates\` ile en son imzaları alın.
*   **Severity Filtresi**: Gereksiz gürültüyü önlemek için \`-severity critical,high,medium\` kullanın.
*   **Rate-Limit Ayarı**: WAF veya hassas sunucular için \`-rate-limit\` ve \`-bulk-size\` değerlerini düşürün.
*   **Proxy Analizi**: \`-proxy\` kullanarak Nuclei'nin ne yaptığını Burp üzerinden izleyin ve öğrenin.
*   **Headless Mode**: Sadece DOM tabanlı XSS veya JS analizi gerekiyorsa \`-headless\` kullanın (yavaştır).
*   **Custom Headers**: Hedefin davranışını anlamak için \`-header\` ile özel başlıklar ekleyin.
*   **Project Path**: Büyük taramalarda \`-project\` kullanarak durumu kaydedin ve kaldığınız yerden devam edin.
*   **Cloud Templates**: AWS/Azure/GCP taramaları için \`-tags cloud\` kullanın.
*   **DNS vs Network**: DNS taramalarını (\`-t dns/\`) network taramalarından ayırın.
*   **Tuning**: Hedefe özel template seti oluşturmak için \`-tags\` ve \`-severity\` kombinasyonlarını iyi yapın.

## 9. Sık Yapılan Hatalar

*   **Tek Template**: Sadece tek bir template ile tüm sistemi tarayıp "temiz" sanmak.
*   **Rate-Limit İhmali**: Varsayılan hızda WAF korumalı siteyi tarayıp IP ban yemek.
*   **Proxy Unutmak**: Kurumsal ağda proxy ayarı yapmadan dışarı çıkmaya çalışmak.
*   **Eski Template**: Güncelleme yapmadan eski imzalarla tarama yapmak.
*   **Yanlış Severity**: Info seviyesini açıp binlerce önemsiz bulgu içinde kaybolmak.
*   **Unsafe Unutmak**: WAF veya filtre olan yerlerde \`-unsafe\` kullanmayıp sonuç alamamak.
*   **Gürültü**: Tüm template'leri (\`-t /\`) çalıştırıp sunucuyu veya logları şişirmek.
*   **JSON İhmali**: Otomasyon veya raporlama için \`-json\` kullanmayıp text çıktısını parse etmeye çalışmak.
`;

const contentEN = `# Nuclei - Template Based Vulnerability Scanner

## 1. Tool Definition
**Nuclei** provides template-based vulnerability scanning, misconfiguration detection, HTTP/DNS/Network/Cloud service analysis, and large-scale automation on targets. Thanks to its YAML-based template structure, it has thousands of vulnerability signatures constantly updated by the community and can be easily integrated into CI/CD processes.

## 2. Installation
*   **Go**: \`go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest\`
*   **Binary**: Can be downloaded from the GitHub release page.
*   **Docker**: \`docker pull projectdiscovery/nuclei\`

## 3. Basic Usage

### Basic Web Server Scanning
Scans the target URL with default templates.
\`\`\`bash
nuclei -u https://target.com
\`\`\`
**Argument Explanations:**
*   **-u**: Target URL.

### Multi-Target Test
Scans a list of URLs from a file.
\`\`\`bash
nuclei -list targets.txt
\`\`\`
**Argument Explanations:**
*   **-list**: Target list file.

### Template Selection
Scans with a specific template or template directory.
\`\`\`bash
nuclei -u target.com -t cves/2023/
\`\`\`
**Argument Explanations:**
*   **-t**: Template or directory path.

### Severity Filtering
Scans only for vulnerabilities of specific severity levels (Critical, High).
\`\`\`bash
nuclei -u target.com -severity critical,high
\`\`\`
**Argument Explanations:**
*   **-severity**: Vulnerability severity.

### Tag-Based Scanning
Runs templates with specific tags (e.g., cve, panel, exposure).
\`\`\`bash
nuclei -u target.com -tags cve,osint
\`\`\`
**Argument Explanations:**
*   **-tags**: Template tags.

### Output Format
Saves results to a file in JSON format.
\`\`\`bash
nuclei -u target.com -json -o results.json
\`\`\`
**Argument Explanations:**
*   **-json**: Generate JSON output.
*   **-o**: Output file.

### Proxy Usage
Routes traffic through a proxy (e.g., Burp Suite).
\`\`\`bash
nuclei -u target.com -proxy http://127.0.0.1:8080
\`\`\`
**Argument Explanations:**
*   **-proxy**: Proxy URL.

### Rate Limit Setting
Limits the number of requests sent per second.
\`\`\`bash
nuclei -u target.com -rate-limit 50
\`\`\`
**Argument Explanations:**
*   **-rate-limit**: Requests per second.

### Adding Custom Headers
Adds custom headers to requests.
\`\`\`bash
nuclei -u target.com -header "X-Bug-Bounty: user123"
\`\`\`
**Argument Explanations:**
*   **-header**: Header info.

### Template Update
Updates the Nuclei template database.
\`\`\`bash
nuclei -update-templates
\`\`\`

## 4. Advanced Usage

### Nuclei Fingerprinting Methodology
Nuclei fingerprints by matching metrics like headers, body, status code, and duration in HTTP responses with YAML rules.

### Banner-based Detection
Detects versions by analyzing service banners (SSH, FTP, SMTP) with regex.

### Heuristic Scanning Logic
Detects anomalies by exhibiting fuzzing-like behaviors for unknown parameters or paths.

### Signature-based Analysis
Makes precise detections using known CVE and vulnerability signatures (matchers).

### Anti-WAF/IPS Modes
Attempts to bypass WAF by sending raw HTTP requests with \`-unsafe\` mode or via \`-header\` manipulation.

### False-Positive Prevention
Reduces false positives by waiting for multiple conditions to be met using the \`matchers-condition: and\` structure in templates.

### Full Manual Payload Sending
Complex attack scenarios (login -> extract token -> attack) can be created with workflow and dynamic template features.

### Custom Scan DB Definition
You can include your own templates in scans by storing them in the \`~/nuclei-templates/custom\` directory.

### Custom Plugin Usage
Nuclei can be integrated into custom tools by using it as a Go library.

### Detecting Real Server behind CDN
Searches for origin IP leaks with DNS and SSL certificate analysis templates.

### SSL Cipher Enumeration
Detects weak encryption algorithms with SSL/TLS handshake templates.

### Observing Rate Limiting Behavior
Can dynamically adjust scan speed by monitoring server response times and error codes (429) (with some flags).

### User-Agent Spoofing
Mimics browsers with \`-header "User-Agent: ..."\`.

### Header Manipulation
Uses custom headers for WAF bypass or host header injection tests.

### Evasion Techniques
Bypasses security devices with fragmented packets or HTTP smuggling techniques (template-based).

### Passive vs Active Detection Difference
Nuclei is active by default but can analyze only responses with the \`-passive\` flag (in supported templates).

### Nuclei → Burp / Proxy Chaining Integration
Allows manual verification of vulnerabilities by routing all traffic to Burp.

### Nuclei → Nmap / Masscan Data Merging Logic
Service-based scanning is performed by piping (\`|\`) the output of port scanning tools (IP:Port) to Nuclei.

### Web Server Anomaly Detection Logic
Detects anomalies based on unexpected content types or sizes.

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments

**Command:**
\`\`\`bash
nuclei -u https://target.com
\`\`\`
**Description:**
Default scan on a single target.
**Argument Explanations:**
*   **-u**: Target URL.

**Command:**
\`\`\`bash
nuclei -list urls.txt
\`\`\`
**Description:**
Bulk scan from list.
**Argument Explanations:**
*   **-list**: Target file.

**Command:**
\`\`\`bash
nuclei -u target.com -t cves/
\`\`\`
**Description:**
Uses only CVE templates.
**Argument Explanations:**
*   **-t**: Template directory.

**Command:**
\`\`\`bash
nuclei -u target.com -templates custom-templates/
\`\`\`
**Description:**
Uses custom template directory.
**Argument Explanations:**
*   **-templates**: Template directory (alternative).

**Command:**
\`\`\`bash
nuclei -u target.com -severity critical,high
\`\`\`
**Description:**
Scans for critical and high severity vulnerabilities.
**Argument Explanations:**
*   **-severity**: Severity filter.

**Command:**
\`\`\`bash
nuclei -u target.com -tags cve,rce
\`\`\`
**Description:**
Runs templates tagged with CVE and RCE.
**Argument Explanations:**
*   **-tags**: Tag filter.

**Command:**
\`\`\`bash
nuclei -project
\`\`\`
**Description:**
Enables project mode to prevent duplicate requests.
**Argument Explanations:**
*   **-project**: Enables project mode.

**Command:**
\`\`\`bash
nuclei -project-path ./myproject
\`\`\`
**Description:**
Specifies the directory to store project data.
**Argument Explanations:**
*   **-project-path**: Project path.

**Command:**
\`\`\`bash
nuclei -u target.com -include-templates specific.yaml
\`\`\`
**Description:**
Includes only the specified template.
**Argument Explanations:**
*   **-include-templates**: Template to include.

**Command:**
\`\`\`bash
nuclei -u target.com -exclude-templates fuzzing/
\`\`\`
**Description:**
Excludes fuzzing templates.
**Argument Explanations:**
*   **-exclude-templates**: Excluded templates.

### Proxy / Network

**Command:**
\`\`\`bash
nuclei -u target.com -proxy http://127.0.0.1:8080
\`\`\`
**Description:**
Uses HTTP proxy.
**Argument Explanations:**
*   **-proxy**: Proxy address.

**Command:**
\`\`\`bash
nuclei -u target.com -proxy-socks socks5://127.0.0.1:9050
\`\`\`
**Description:**
Uses SOCKS proxy (Tor etc.).
**Argument Explanations:**
*   **-proxy-socks**: SOCKS proxy address.

**Command:**
\`\`\`bash
nuclei -u target.com -interface eth0
\`\`\`
**Description:**
Uses a specific network interface.
**Argument Explanations:**
*   **-interface**: Network interface.

**Command:**
\`\`\`bash
nuclei -u target.com -ip-version 6
\`\`\`
**Description:**
Forces IPv6 usage.
**Argument Explanations:**
*   **-ip-version**: IP version (4 or 6).

**Command:**
\`\`\`bash
nuclei -u target.com -rate-limit 100
\`\`\`
**Description:**
Sends 100 requests per second.
**Argument Explanations:**
*   **-rate-limit**: Request rate.

**Command:**
\`\`\`bash
nuclei -u target.com -bulk-size 50
\`\`\`
**Description:**
Runs 50 parallel templates at the same time.
**Argument Explanations:**
*   **-bulk-size**: Parallelism count.

**Command:**
\`\`\`bash
nuclei -u target.com -unsafe
\`\`\`
**Description:**
Bypasses some restrictions using raw HTTP requests.
**Argument Explanations:**
*   **-unsafe**: Unsafe mode.

### Payload & Request Manipulation

**Command:**
\`\`\`bash
nuclei -u target.com -header "Authorization: Bearer token"
\`\`\`
**Description:**
Adds custom header.
**Argument Explanations:**
*   **-header**: Header string.

**Command:**
\`\`\`bash
nuclei -u target.com -metadata
\`\`\`
**Description:**
Shows template metadata info.
**Argument Explanations:**
*   **-metadata**: Metadata display.

**Command:**
\`\`\`bash
nuclei -u target.com -var username=admin
\`\`\`
**Description:**
Assigns values to variables in the template.
**Argument Explanations:**
*   **-var**: Variable definition.

**Command:**
\`\`\`bash
nuclei -u target.com -var-file vars.txt
\`\`\`
**Description:**
Reads variable values from file.
**Argument Explanations:**
*   **-var-file**: Variable file.

**Command:**
\`\`\`bash
nuclei -u target.com -body "json_data"
\`\`\`
**Description:**
Adds data to request body (in some cases).
**Argument Explanations:**
*   **-body**: Body content.

### Scanning / Enumeration

**Command:**
\`\`\`bash
nuclei -update-templates
\`\`\`
**Description:**
Updates templates.
**Argument Explanations:**
*   **-update-templates**: Update command.

**Command:**
\`\`\`bash
nuclei -update
\`\`\`
**Description:**
Updates Nuclei engine.
**Argument Explanations:**
*   **-update**: Engine update.

**Command:**
\`\`\`bash
nuclei -validate
\`\`\`
**Description:**
Validates template syntax.
**Argument Explanations:**
*   **-validate**: Validation mode.

**Command:**
\`\`\`bash
nuclei -templates-version
\`\`\`
**Description:**
Shows installed template version.
**Argument Explanations:**
*   **-templates-version**: Version info.

**Command:**
\`\`\`bash
nuclei -headless
\`\`\`
**Description:**
Performs headless (browser-based) scan.
**Argument Explanations:**
*   **-headless**: Headless mode.

**Command:**
\`\`\`bash
nuclei -verbose
\`\`\`
**Description:**
Provides detailed output.
**Argument Explanations:**
*   **-verbose**: Verbose mode.

### Output

**Command:**
\`\`\`bash
nuclei -u target.com -o output.txt
\`\`\`
**Description:**
Writes results to file.
**Argument Explanations:**
*   **-o**: Filename.

**Command:**
\`\`\`bash
nuclei -u target.com -json
\`\`\`
**Description:**
Outputs in JSON format.
**Argument Explanations:**
*   **-json**: JSON format.

**Command:**
\`\`\`bash
nuclei -u target.com -markdown-export report_dir/
\`\`\`
**Description:**
Creates report in Markdown format.
**Argument Explanations:**
*   **-markdown-export**: Report directory.

**Command:**
\`\`\`bash
nuclei -u target.com -no-color
\`\`\`
**Description:**
Disables colored output.
**Argument Explanations:**
*   **-no-color**: No color mode.

**Command:**
\`\`\`bash
nuclei -u target.com -silent
\`\`\`
**Description:**
Prints only found vulnerabilities to screen.
**Argument Explanations:**
*   **-silent**: Silent mode.

## 6. Real Pentest Scenarios

### Real IP Detection behind CDN
\`\`\`bash
nuclei -u target.com -tags cdn,origin -verbose
\`\`\`
**Description:**
Attempts to find real IP using templates tagged for CDN and origin detection.

### Service Fingerprinting behind Reverse Proxy
\`\`\`bash
nuclei -u target.com -tags tech-detect,fingerprint
\`\`\`
**Description:**
Identifies backend services (Java, Python, IIS, etc.) behind proxy with technology detection templates.

### Payload Evasion + Header Manipulation against WAF
\`\`\`bash
nuclei -u target.com -t cves/ -header "X-Forwarded-For: 127.0.0.1" -unsafe
\`\`\`
**Description:**
Performs CVE scan bypassing WAF rules with Unsafe mode and header manipulation.

### Analyzing WAF Behavior via Rate-Limit
\`\`\`bash
nuclei -u target.com -rate-limit 150 -verbose
\`\`\`
**Description:**
Analyzes when WAF blocks (429/403) by sending requests at high speed.

### Misconfiguration Detection with Custom Template
\`\`\`bash
nuclei -u target.com -t my-custom-templates/misconfigs/
\`\`\`
**Description:**
Searches for specific misconfigurations with your own custom templates.

### SSL/TLS Misconfiguration & Cipher Enumeration
\`\`\`bash
nuclei -u target.com -tags ssl,tls
\`\`\`
**Description:**
Audits SSL/TLS configurations and weak encryption algorithms.

### HSTS Check
\`\`\`bash
nuclei -u target.com -t http/misconfiguration/hsts-missing.yaml
\`\`\`
**Description:**
Checks for missing Strict-Transport-Security header.

### Default Admin Panel Discovery
\`\`\`bash
nuclei -u target.com -tags panel,admin
\`\`\`
**Description:**
Detects known admin panels and login pages.

### Directory Traversal + Special Template Scan
\`\`\`bash
nuclei -u target.com -tags lfi,traversal
\`\`\`
**Description:**
Runs templates focused on LFI and Directory Traversal vulnerabilities.

### Basic Auth Brute-Force Behavior Analysis
\`\`\`bash
nuclei -u target.com -t http/exposures/basic-auth.yaml
\`\`\`
**Description:**
Detects Basic Auth protected areas (Use Hydra for Brute-force).

### Scanning via Proxy (Corporate Network)
\`\`\`bash
nuclei -u target.com -proxy http://proxy.corp:8080
\`\`\`
**Description:**
Scans external targets through corporate proxy.

### Stealth Scanning over Tor
\`\`\`bash
nuclei -u target.com -proxy-socks socks5://127.0.0.1:9050
\`\`\`
**Description:**
Performs anonymous scan over Tor network.

### Session Security Test with Cookie Manipulation
\`\`\`bash
nuclei -u target.com -header "Cookie: session=test" -tags cookie
\`\`\`
**Description:**
Tests session management vulnerabilities with custom cookie value.

### Fingerprinting with Reflected Response Differences
\`\`\`bash
nuclei -u target.com -tags reflection
\`\`\`
**Description:**
Analyzes reflection of sent inputs in the response.

### Throttle Test by Sending Large Request
\`\`\`bash
nuclei -u target.com -t http/dos/
\`\`\`
**Description:**
Tests endpoints with DoS potential (use with caution).

### Server Behavior Analysis with Weird Header Injection
\`\`\`bash
nuclei -u target.com -tags header-injection
\`\`\`
**Description:**
Measures server reaction with nonsensical or special headers.

### Web Server Signature Spoofing Detection
\`\`\`bash
nuclei -u target.com -tags fingerprint
\`\`\`
**Description:**
Looks for differences between server signature and actual behavior.

### CORS Misconfiguration Analysis
\`\`\`bash
nuclei -u target.com -tags cors
\`\`\`
**Description:**
Detects Cross-Origin Resource Sharing (CORS) configuration errors.

### Information Leak Detection
\`\`\`bash
nuclei -u target.com -tags exposure,token
\`\`\`
**Description:**
Searches for API key, token, or sensitive information leaks.

### Passive vs Active Fingerprinting Difference
\`\`\`bash
nuclei -u target.com -passive
\`\`\`
**Description:**
Performs only passive information gathering (with supported templates).

### Nuclei + Burp + Nmap Correlation (Real Scenario)
\`\`\`bash
nmap -p80,443 target.com -oG - | nuclei -proxy http://127.0.0.1:8080
\`\`\`
**Description:**
Feeds Nmap output to Nuclei, and Nuclei routes traffic to Burp.

## 8. Best Practices (Expert Level)

*   **Update Templates**: Always get latest signatures with \`nuclei -update-templates\`.
*   **Severity Filter**: Use \`-severity critical,high,medium\` to prevent unnecessary noise.
*   **Rate-Limit Setting**: Lower \`-rate-limit\` and \`-bulk-size\` values for WAF or sensitive servers.
*   **Proxy Analysis**: Use \`-proxy\` to watch and learn what Nuclei does via Burp.
*   **Headless Mode**: Use \`-headless\` only if DOM-based XSS or JS analysis is needed (slow).
*   **Custom Headers**: Add special headers with \`-header\` to understand target behavior.
*   **Project Path**: Use \`-project\` in large scans to save state and resume later.
*   **Cloud Templates**: Use \`-tags cloud\` for AWS/Azure/GCP scans.
*   **DNS vs Network**: Separate DNS scans (\`-t dns/\`) from network scans.
*   **Tuning**: Combine \`-tags\` and \`-severity\` well to create target-specific template sets.

## 9. Common Mistakes

*   **Single Template**: Scanning entire system with just one template and thinking it's "clean".
*   **Ignoring Rate-Limit**: Scanning WAF-protected site at default speed and getting IP banned.
*   **Forgetting Proxy**: Trying to go out without proxy setting in corporate network.
*   **Old Template**: Scanning with old signatures without updating.
*   **Wrong Severity**: Turning on Info level and getting lost in thousands of trivial findings.
*   **Forgetting Unsafe**: Not using \`-unsafe\` where WAF or filters exist and getting no results.
*   **Noise**: Running all templates (\`-t /\`) and bloating server or logs.
*   **Ignoring JSON**: Trying to parse text output instead of using \`-json\` for automation or reporting.
`;

async function addNuclei() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Nuclei cheatsheet...');

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
                tr: 'Nuclei Cheat Sheet',
                en: 'Nuclei Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['nuclei', 'vulnerability-scanner', 'automation', 'templates', 'cve', 'misconfiguration']
        };

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Nuclei Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Nuclei cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addNuclei();
