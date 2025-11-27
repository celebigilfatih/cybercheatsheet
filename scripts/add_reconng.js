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

const contentTR = `# recon-ng - Advanced Web Reconnaissance Framework

## 1. Araç Tanımı
**recon-ng**, Python ile yazılmış, modüler yapıda, Metasploit benzeri bir arayüze sahip, tam kapsamlı bir OSINT (Open Source Intelligence) ve keşif framework'üdür. Web tabanlı bilgi toplama işlemlerini otomatize eder, veritabanı tabanlı çalışır ve API entegrasyonları ile çok derinlemesine analiz yapabilir.

## 2. Kurulum
*   **Kali Linux**: \`sudo apt install recon-ng\`
*   **Github**: \`git clone https://github.com/lanmaster53/recon-ng.git\`
*   **Bağımlılıklar**: \`pip install -r REQUIREMENTS\`

## 3. Temel Kullanım
*   **Başlatma**: Terminalde \`recon-ng\` yazarak konsola girilir.
*   **Workspace Oluşturma**: Her proje için ayrı bir veritabanı alanı oluşturulur (\`workspaces create proje_adi\`).
*   **Modül Sorgulama**: Marketplace üzerinden modüller aranır (\`marketplace search\`).
*   **Basit Mantık**: Modül yükle -> Parametreleri ayarla -> Çalıştır -> Veritabanını görüntüle.

## 4. İleri Seviye Kullanım

### Workspace Yönetimi
*   **Create**: \`workspaces create <isim>\` ile yeni proje açılır. Veriler izole edilir.
*   **Select**: \`workspaces load <isim>\` ile projeler arası geçiş yapılır.
*   **Delete**: \`workspaces remove <isim>\` ile proje silinir.

### Module Ekosistemi
*   **Recon**: Bilgi toplama modülleri (domains, hosts, contacts).
*   **Reporting**: Rapor oluşturma modülleri (html, csv, xml).
*   **Exploitation**: Basit zafiyet sömürme modülleri.
*   **Import/Export**: Veri transferi modülleri.

### Module Argüman Sistematiği
*   **Required**: Çalışması için zorunlu alanlar (genellikle SOURCE).
*   **Optional**: İsteğe bağlı filtreler veya ayarlar.
*   **Global Options**: Tüm modülleri etkileyen ayarlar (User-Agent, Proxy).

### API Key Yönetimi
*   **Keys Add**: \`keys add <api_name> <key_value>\` (Örn: shodan_api).
*   **Keys List**: \`keys list\` ile ekli anahtarlar görülür.
*   **Keys Remove**: \`keys remove <api_name>\`.
*   **Önemli**: API anahtarları olmadan birçok modül (Shodan, Hunter, Github) çalışmaz.

### İleri Seviye Veri Toplama Zinciri
1.  **Domains** tablosuna hedef domain eklenir.
2.  **recon/domains-hosts/** modülleri ile subdomainler bulunur (Hosts tablosuna işlenir).
3.  **recon/hosts-hosts/** modülleri ile IP'ler çözülür (Hosts tablosu güncellenir).
4.  **recon/domains-contacts/** ile e-postalar bulunur (Contacts tablosuna işlenir).
5.  **recon/contacts-creds/** ile sızdırılmış şifreler aranır.

### Veritabanı Tabloları
*   **domains**: Hedef alan adları.
*   **hosts**: Subdomainler, IP adresleri, ülke, enlem/boylam.
*   **contacts**: İsim, soyisim, e-posta, unvan.
*   **creds**: Kullanıcı adı, şifre (hash veya plain), sızıntı kaynağı.
*   **leaks**: Sızdırılmış veriler.
*   **ports**: Açık portlar ve banner bilgileri.

## 5. Açıklamalı Komutlar (Geniş Liste)

**Komut:**
\`\`\`bash
workspaces create hedef_sirket
\`\`\`
**Açıklama:**
"hedef_sirket" adında yeni, izole bir çalışma alanı ve veritabanı oluşturur.

**Komut:**
\`\`\`bash
marketplace search whois
\`\`\`
**Açıklama:**
Marketplace'de isminde "whois" geçen modülleri arar.

**Komut:**
\`\`\`bash
marketplace install recon/domains-hosts/hackertarget
\`\`\`
**Açıklama:**
Hackertarget servisini kullanan subdomain bulma modülünü indirir ve kurar.

**Komut:**
\`\`\`bash
modules load recon/domains-hosts/hackertarget
\`\`\`
**Açıklama:**
Belirtilen modülü aktif hale getirir ve kullanıma hazırlar.

**Komut:**
\`\`\`bash
info
\`\`\`
**Açıklama:**
Yüklü olan modül hakkında bilgi, yazar, açıklama ve gerekli parametreleri gösterir.

**Komut:**
\`\`\`bash
options set SOURCE hedef.com
\`\`\`
**Açıklama:**
Modülün hedef parametresini (SOURCE) "hedef.com" olarak ayarlar.

**Komut:**
\`\`\`bash
run
\`\`\`
**Açıklama:**
Ayarları yapılmış aktif modülü çalıştırır.

**Komut:**
\`\`\`bash
show hosts
\`\`\`
**Açıklama:**
Veritabanındaki "hosts" tablosunu (bulunan subdomain ve IP'leri) listeler.

**Komut:**
\`\`\`bash
db insert domains
\`\`\`
**Açıklama:**
Domains tablosuna manuel veri ekleme moduna girer (domain, notlar vb.).

**Komut:**
\`\`\`bash
keys add shodan_api H4s...
\`\`\`
**Açıklama:**
Shodan API anahtarını sisteme ekler.

**Komut:**
\`\`\`bash
keys list
\`\`\`
**Açıklama:**
Kayıtlı tüm API anahtarlarını ve durumlarını gösterir.

**Komut:**
\`\`\`bash
back
\`\`\`
**Açıklama:**
Aktif modülden çıkıp ana menüye döner.

**Komut:**
\`\`\`bash
options set VERBOSE true
\`\`\`
**Açıklama:**
Hata ayıklama için detaylı çıktı modunu açar.

**Komut:**
\`\`\`bash
modules load reporting/html
\`\`\`
**Açıklama:**
HTML raporlama modülünü yükler.

**Komut:**
\`\`\`bash
options set FILENAME rapor.html
\`\`\`
**Açıklama:**
Rapor çıktısının ismini belirler.

**Komut:**
\`\`\`bash
options set CREATOR "Pentest Team"
\`\`\`
**Açıklama:**
Raporda görünecek oluşturan kişi bilgisini ayarlar.

**Komut:**
\`\`\`bash
query SELECT * FROM hosts WHERE country LIKE 'TR'
\`\`\`
**Açıklama:**
Veritabanında SQL sorgusu çalıştırarak Türkiye lokasyonlu hostları listeler.

**Komut:**
\`\`\`bash
spool start log.txt
\`\`\`
**Açıklama:**
Konsol çıktısını bir dosyaya kaydetmeye başlar.

**Komut:**
\`\`\`bash
dashboard
\`\`\`
**Açıklama:**
Workspace özetini (kaç host, kaç contact bulundu vb.) gösterir.

**Komut:**
\`\`\`bash
exit
\`\`\`
**Açıklama:**
Programdan çıkar.

## 6. Gerçek Pentest Senaryoları

**Senaryo: Şirket Domain Footprint**
1.  \`workspaces create sirket_analiz\`
2.  \`db insert domains\` -> \`sirket.com\`
3.  \`modules load recon/domains-hosts/bing_domain_web\` -> \`run\` (Subdomainleri bul)
4.  \`modules load recon/domains-hosts/hackertarget\` -> \`run\` (Daha fazla subdomain)
5.  \`modules load recon/hosts-hosts/resolve\` -> \`run\` (IP'leri çöz)
6.  \`show hosts\` (Sonuçları incele)

**Senaryo: Çalışan E-posta Zinciri**
1.  \`modules load recon/domains-contacts/hunter_io\`
2.  \`run\` (API key gerekir, e-postaları çeker)
3.  \`modules load recon/contacts-profiles/fullcontact\`
4.  \`run\` (E-postalardan sosyal medya profillerini bul)
5.  \`show contacts\`

**Senaryo: Leak Credential Analizi**
1.  \`modules load recon/domains-contacts/whois_pocs\` (Whois'den admin mailini bul)
2.  \`modules load recon/contacts-creds/haveibeenpwned\`
3.  \`run\` (Sızıntı veritabanlarında arat)
4.  \`show creds\` (Sızan bilgileri listele)

## 8. Best Practices (Uzman Seviye)

*   **Modül Zincirleme**: Veriyi bir modülden diğerine aktaracak şekilde pipeline kurun (Domain -> Host -> IP -> Location).
*   **Workspace İzolasyonu**: Asla "default" workspace kullanmayın. Her müşteri için yeni workspace açın.
*   **Veritabanı Temizliği**: Yanlış veya gereksiz verileri \`db delete\` veya SQL sorgusu ile temizleyin, raporu kirletmesin.
*   **API Rate-Limit**: Ücretsiz API anahtarlarının limitlerini kontrol edin, gereksiz yere modül çalıştırmayın.
*   **Doğru Modül Seçimi**: Çalışmayan veya eski modülleri marketplace'den takip edin, sadece güvenilir olanları kullanın.
*   **Dışa Aktarım**: recon-ng veritabanını CSV veya XML olarak dışarı aktarıp Nmap veya Maltego'ya import edin.

## 9. Sık Yapılan Hatalar

*   **Wrong SOURCE**: Modülün beklediği girdi tipini (domain mi, host mu, contact mı) kontrol etmemek.
*   **Yanlış Workspace**: Bir müşterinin verilerini diğerine karıştırmak.
*   **API Key Unutmak**: "Modül çalıştı ama sonuç dönmedi" şikayetinin bir numaralı sebebi.
*   **Export Etmeden Silmek**: Workspace'i silince veriler kalıcı olarak gider.
*   **Duplicate Data**: Aynı modülü defalarca çalıştırıp veritabanını şişirmek (gerçi recon-ng duplicate'leri genelde engeller ama dikkatli olunmalı).
`;

const contentEN = `# recon-ng - Advanced Web Reconnaissance Framework

## 1. Tool Definition
**recon-ng** is a full-featured Web Reconnaissance framework written in Python. It has a modular structure and an interface similar to Metasploit. It automates web-based information gathering, works with a database backend, and can perform deep analysis via API integrations.

## 2. Installation
*   **Kali Linux**: \`sudo apt install recon-ng\`
*   **Github**: \`git clone https://github.com/lanmaster53/recon-ng.git\`
*   **Dependencies**: \`pip install -r REQUIREMENTS\`

## 3. Basic Usage
*   **Start**: Type \`recon-ng\` in terminal.
*   **Create Workspace**: Create a separate DB area for each project (\`workspaces create project_name\`).
*   **Search Modules**: Find modules via Marketplace (\`marketplace search\`).
*   **Basic Logic**: Install module -> Set parameters -> Run -> View database.

## 4. Advanced Usage

### Workspace Management
*   **Create**: \`workspaces create <name>\` opens a new project. Data is isolated.
*   **Select**: \`workspaces load <name>\` switches between projects.
*   **Delete**: \`workspaces remove <name>\` deletes a project.

### Module Ecosystem
*   **Recon**: Information gathering modules (domains, hosts, contacts).
*   **Reporting**: Report generation modules (html, csv, xml).
*   **Exploitation**: Simple vulnerability exploitation modules.
*   **Import/Export**: Data transfer modules.

### Module Argument System
*   **Required**: Mandatory fields for execution (usually SOURCE).
*   **Optional**: Optional filters or settings.
*   **Global Options**: Settings affecting all modules (User-Agent, Proxy).

### API Key Management
*   **Keys Add**: \`keys add <api_name> <key_value>\` (e.g., shodan_api).
*   **Keys List**: \`keys list\` shows stored keys.
*   **Keys Remove**: \`keys remove <api_name>\`.
*   **Important**: Many modules (Shodan, Hunter, Github) won't work without API keys.

### Advanced Data Collection Chain
1.  Add target domain to **domains** table.
2.  Find subdomains via **recon/domains-hosts/** modules (Populates Hosts table).
3.  Resolve IPs via **recon/hosts-hosts/** modules (Updates Hosts table).
4.  Find emails via **recon/domains-contacts/** (Populates Contacts table).
5.  Search leaked passwords via **recon/contacts-creds/**.

### Database Tables
*   **domains**: Target domain names.
*   **hosts**: Subdomains, IP addresses, country, lat/long.
*   **contacts**: First name, last name, email, title.
*   **creds**: Username, password (hash or plain), leak source.
*   **leaks**: Leaked data snippets.
*   **ports**: Open ports and banner info.

## 5. Annotated Commands (Extended List)

**Command:**
\`\`\`bash
workspaces create target_company
\`\`\`
**Description:**
Creates a new, isolated workspace and database named "target_company".

**Command:**
\`\`\`bash
marketplace search whois
\`\`\`
**Description:**
Searches for modules containing "whois" in the Marketplace.

**Command:**
\`\`\`bash
marketplace install recon/domains-hosts/hackertarget
\`\`\`
**Description:**
Downloads and installs the subdomain discovery module using Hackertarget service.

**Command:**
\`\`\`bash
modules load recon/domains-hosts/hackertarget
\`\`\`
**Description:**
Loads the specified module and prepares it for use.

**Command:**
\`\`\`bash
info
\`\`\`
**Description:**
Shows info, author, description, and required parameters for the loaded module.

**Command:**
\`\`\`bash
options set SOURCE target.com
\`\`\`
**Description:**
Sets the target parameter (SOURCE) of the module to "target.com".

**Command:**
\`\`\`bash
run
\`\`\`
**Description:**
Executes the configured active module.

**Command:**
\`\`\`bash
show hosts
\`\`\`
**Description:**
Lists the "hosts" table (found subdomains and IPs) in the database.

**Command:**
\`\`\`bash
db insert domains
\`\`\`
**Description:**
Enters manual data entry mode for the domains table.

**Command:**
\`\`\`bash
keys add shodan_api H4s...
\`\`\`
**Description:**
Adds a Shodan API key to the system.

**Command:**
\`\`\`bash
keys list
\`\`\`
**Description:**
Shows all registered API keys and their status.

**Command:**
\`\`\`bash
back
\`\`\`
**Description:**
Exits the active module and returns to the main menu.

**Command:**
\`\`\`bash
options set VERBOSE true
\`\`\`
**Description:**
Enables detailed output mode for debugging.

**Command:**
\`\`\`bash
modules load reporting/html
\`\`\`
**Description:**
Loads the HTML reporting module.

**Command:**
\`\`\`bash
options set FILENAME report.html
\`\`\`
**Description:**
Sets the name of the report output file.

**Command:**
\`\`\`bash
options set CREATOR "Pentest Team"
\`\`\`
**Description:**
Sets the creator information to appear in the report.

**Command:**
\`\`\`bash
query SELECT * FROM hosts WHERE country LIKE 'TR'
\`\`\`
**Description:**
Runs a SQL query to list hosts located in Turkey.

**Command:**
\`\`\`bash
spool start log.txt
\`\`\`
**Description:**
Starts logging console output to a file.

**Command:**
\`\`\`bash
dashboard
\`\`\`
**Description:**
Shows workspace summary (count of hosts, contacts found, etc.).

**Command:**
\`\`\`bash
exit
\`\`\`
**Description:**
Exits the program.

## 6. Real Pentest Scenarios

**Scenario: Company Domain Footprint**
1.  \`workspaces create company_analysis\`
2.  \`db insert domains\` -> \`company.com\`
3.  \`modules load recon/domains-hosts/bing_domain_web\` -> \`run\` (Find subdomains)
4.  \`modules load recon/domains-hosts/hackertarget\` -> \`run\` (More subdomains)
5.  \`modules load recon/hosts-hosts/resolve\` -> \`run\` (Resolve IPs)
6.  \`show hosts\` (Inspect results)

**Scenario: Employee Email Chain**
1.  \`modules load recon/domains-contacts/hunter_io\`
2.  \`run\` (Requires API key, fetches emails)
3.  \`modules load recon/contacts-profiles/fullcontact\`
4.  \`run\` (Find social media profiles from emails)
5.  \`show contacts\`

**Scenario: Leak Credential Analysis**
1.  \`modules load recon/domains-contacts/whois_pocs\` (Find admin email from Whois)
2.  \`modules load recon/contacts-creds/haveibeenpwned\`
3.  \`run\` (Search in leak databases)
4.  \`show creds\` (List leaked info)

## 8. Best Practices (Expert Level)

*   **Module Chaining**: Design a pipeline to pass data from one module to another (Domain -> Host -> IP -> Location).
*   **Workspace Isolation**: Never use the "default" workspace. Create a new one for each client.
*   **Database Hygiene**: Clean wrong or unnecessary data with \`db delete\` or SQL queries to keep reports clean.
*   **API Rate-Limit**: Check limits of free API keys, don't run modules unnecessarily.
*   **Correct Module Selection**: Track working/deprecated modules in the marketplace, use only reliable ones.
*   **Exporting**: Export recon-ng DB as CSV or XML to import into Nmap or Maltego.

## 9. Common Mistakes

*   **Wrong SOURCE**: Not checking the input type expected by the module (domain vs host vs contact).
*   **Wrong Workspace**: Mixing data from different clients.
*   **Forgetting API Keys**: The #1 reason for "Module ran but returned no results".
*   **Deleting without Export**: Data is gone forever if workspace is removed.
*   **Duplicate Data**: Running the same module repeatedly and bloating the database (though recon-ng usually handles dupes, be careful).
`;

async function addReconNg() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding recon-ng cheatsheet...');

        // 1. Find or create the category
        let category = await Category.findOne({ 'name.en': 'Information Gathering' });
        if (!category) {
            console.log('Category "Information Gathering" not found, creating...');
            category = await Category.create({
                name: { tr: 'Bilgi Toplama', en: 'Information Gathering' },
                description: { tr: 'OSINT ve keşif araçları', en: 'OSINT and reconnaissance tools' },
                slug: 'information-gathering',
                icon: 'Search'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'recon-ng Cheat Sheet',
                en: 'recon-ng Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['recon-ng', 'osint', 'recon', 'framework', 'database', 'api']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'recon-ng Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('recon-ng cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addReconNg();
