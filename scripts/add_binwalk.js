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

const contentTR = `# Binwalk - Firmware Analysis Tool

## 1. Araç Tanımı
**Binwalk**, firmware, binary, image, executable ve gömülü sistem dosyalarında gömülü içerik, sıkıştırılmış bloklar, imzalar, filesystem’ler, entropy anomalileri, packed bölümler ve kod segmentlerini tespit eden bir analiz aracıdır. Firmware reverse engineering, IoT güvenlik testi ve exploit araştırmalarında kullanılır.

## 2. Kurulum
*   **Kali Linux**: \`sudo apt install binwalk\`
*   **Source**: \`git clone https://github.com/ReFirmLabs/binwalk.git\`

## 3. Temel Kullanım

### Otomatik Extraction
Firmware içindeki dosya sistemlerini ve sıkıştırılmış dosyaları otomatik olarak çıkarır.
\`\`\`bash
binwalk -e firmware.bin
\`\`\`
**Argüman Açıklamaları:**
*   **-e**: Extract (çıkartma) modunu açar.

### Recursive Extraction (Matryoshka)
İç içe geçmiş dosyaları (örn: zip içinde gzip içinde fs) sonuna kadar tarar ve çıkarır.
\`\`\`bash
binwalk -Me firmware.bin
\`\`\`
**Argüman Açıklamaları:**
*   **-M**: Matryoshka (recursive) modu.
*   **-e**: Extraction modu.

### Entropy Analizi
Dosyanın entropy grafiğini oluşturarak şifreli veya sıkıştırılmış alanları tespit eder.
\`\`\`bash
binwalk -E firmware.bin
\`\`\`
**Argüman Açıklamaları:**
*   **-E**: Entropy analizi.

### Signature Taraması (Varsayılan)
Dosya içindeki bilinen imzaları (magic bytes) tarar.
\`\`\`bash
binwalk -B firmware.bin
\`\`\`
**Argüman Açıklamaları:**
*   **-B**: Signature scan (varsayılan).

### String Arama
Dosya içindeki okunabilir metinleri bulur (strings komutuna benzer ama daha detaylı).
\`\`\`bash
binwalk -W firmware.bin
\`\`\`
**Argüman Açıklamaları:**
*   **-W**: String taraması.

### Özel Signature Dosyası Kullanma
Kendi oluşturduğunuz imza dosyası ile tarama yapar.
\`\`\`bash
binwalk -r my_sigs firmware.bin
\`\`\`
**Argüman Açıklamaları:**
*   **-r**: Özel imza dosyası yükle.

### Hex + ASCII Dump
Dosyanın hex ve ASCII dökümünü yan yana gösterir.
\`\`\`bash
binwalk -d firmware.bin
\`\`\`
**Argüman Açıklamaları:**
*   **-d**: Hex dump modu.

### RAW Extraction
Tanımlanamayan blokları da ham veri olarak çıkarır.
\`\`\`bash
binwalk -R firmware.bin
\`\`\`
**Argüman Açıklamaları:**
*   **-R**: Raw extraction.

## 4. İleri Seviye Kullanım

### Extraction Handler Tanımı
Belirli bir dosya türü için özel bir çıkarma komutu tanımlar.
\`\`\`bash
binwalk -D 'png image:png-extractor %e' firmware.bin
\`\`\`
**Argüman Açıklamaları:**
*   **-D**: Özel handler tanımı (<type>:<cmd>).

### Offset ve Uzunluk Belirtme
Analizi dosyanın belirli bir bölümüyle sınırlar.
\`\`\`bash
binwalk --offset=100 --length=500 firmware.bin
\`\`\`
**Argüman Açıklamaları:**
*   **--offset**: Başlangıç baytı.
*   **--length**: Okunacak uzunluk.

### Opcode Taraması
Belirli mimariler (ARM, MIPS vb.) için makine kodu talimatlarını arar.
\`\`\`bash
binwalk -A firmware.bin
\`\`\`

### Dosya Sistemi Doğrulama
Çıkarılan dosya sistemlerini mount etmeden önce bütünlüğünü kontrol etmek için \`sasquatch\` (squashfs için) veya \`jefferson\` (jffs2 için) gibi yardımcı araçların kurulu olması gerekir. Binwalk bunları otomatik kullanır.

### Entropy Grafiği Kaydetme
Entropy analiz sonucunu görsel (PNG) olarak kaydeder (GUI gerektirebilir veya parametre ile).
\`\`\`bash
binwalk -E --save firmware.bin
\`\`\`

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar

**Komut:**
\`\`\`bash
binwalk -e firmware.bin
\`\`\`
**Açıklama:**
Otomatik dosya çıkarma.
**Argüman Açıklamaları:**
*   **-e**: Extract.

**Komut:**
\`\`\`bash
binwalk -M firmware.bin
\`\`\`
**Açıklama:**
Recursive (iç içe) tarama modu.
**Argüman Açıklamaları:**
*   **-M**: Matryoshka.

**Komut:**
\`\`\`bash
binwalk -r signatures.magic firmware.bin
\`\`\`
**Açıklama:**
Özel imza dosyası kullanır.
**Argüman Açıklamaları:**
*   **-r**: Signature file.

**Komut:**
\`\`\`bash
binwalk -d firmware.bin
\`\`\`
**Açıklama:**
Hex dökümü alır.
**Argüman Açıklamaları:**
*   **-d**: Hex dump.

**Komut:**
\`\`\`bash
binwalk -B firmware.bin
\`\`\`
**Açıklama:**
Standart imza taraması yapar.
**Argüman Açıklamaları:**
*   **-B**: Binwalk scan.

**Komut:**
\`\`\`bash
binwalk -E firmware.bin
\`\`\`
**Açıklama:**
Entropy analizi yapar.
**Argüman Açıklamaları:**
*   **-E**: Entropy.

**Komut:**
\`\`\`bash
binwalk -R firmware.bin
\`\`\`
**Açıklama:**
Raw (ham) çıkarma yapar.
**Argüman Açıklamaları:**
*   **-R**: Raw extract.

**Komut:**
\`\`\`bash
binwalk -W firmware.bin
\`\`\`
**Açıklama:**
String taraması yapar.
**Argüman Açıklamaları:**
*   **-W**: Strings.

**Komut:**
\`\`\`bash
binwalk -y filesystem firmware.bin
\`\`\`
**Açıklama:**
Sadece belirli imzaları (örn: filesystem) arar.
**Argüman Açıklamaları:**
*   **-y**: Include filter.

**Komut:**
\`\`\`bash
binwalk -I firmware.bin
\`\`\`
**Açıklama:**
Geçersiz imzaları da gösterir.
**Argüman Açıklamaları:**
*   **-I**: Invalid signatures.

**Komut:**
\`\`\`bash
binwalk --depth 5 firmware.bin
\`\`\`
**Açıklama:**
Recursive tarama derinliğini sınırlar.
**Argüman Açıklamaları:**
*   **--depth**: Derinlik.

**Komut:**
\`\`\`bash
binwalk --offset 0x100 firmware.bin
\`\`\`
**Açıklama:**
Belirtilen offsetten başlar.
**Argüman Açıklamaları:**
*   **--offset**: Başlangıç.

**Komut:**
\`\`\`bash
binwalk --length 1024 firmware.bin
\`\`\`
**Açıklama:**
Sadece belirtilen bayt kadar okur.
**Argüman Açıklamaları:**
*   **--length**: Uzunluk.

**Komut:**
\`\`\`bash
binwalk --dd="png image:png" firmware.bin
\`\`\`
**Açıklama:**
Belirli bir imzayı bulup çıkarır (dd kuralı).
**Argüman Açıklamaları:**
*   **--dd**: Dump definition.

### Proxy / Network (Binwalk network kullanmaz)

**Komut:**
\`\`\`bash
binwalk --no-update
\`\`\`
**Açıklama:**
Otomatik güncellemeyi kapatır (varsa).
**Argüman Açıklamaları:**
*   **--no-update**: Güncelleme yok.

### Payload & Request Manipulation

**Komut:**
\`\`\`bash
binwalk -D 'zip archive:unzip %e' firmware.bin
\`\`\`
**Açıklama:**
Zip dosyaları için özel çıkarma komutu tanımlar.
**Argüman Açıklamaları:**
*   **-D**: Define handler.

**Komut:**
\`\`\`bash
binwalk --matryoshka firmware.bin
\`\`\`
**Açıklama:**
Recursive extraction (kısa hali -M).
**Argüman Açıklamaları:**
*   **--matryoshka**: Recursive.

**Komut:**
\`\`\`bash
binwalk --raw firmware.bin
\`\`\`
**Açıklama:**
Raw extraction (kısa hali -R).
**Argüman Açıklamaları:**
*   **--raw**: Raw.

**Komut:**
\`\`\`bash
binwalk --carve firmware.bin
\`\`\`
**Açıklama:**
Veriyi çıkarmadan sadece kesip ayırır.
**Argüman Açıklamaları:**
*   **--carve**: Carve data.

**Komut:**
\`\`\`bash
binwalk --preserve-symlinks firmware.bin
\`\`\`
**Açıklama:**
Sembolik linkleri koruyarak çıkarır.
**Argüman Açıklamaları:**
*   **--preserve-symlinks**: Linkleri koru.

### Scanning / Enumeration

**Komut:**
\`\`\`bash
binwalk --signature firmware.bin
\`\`\`
**Açıklama:**
İmza taraması (kısa hali -B).
**Argüman Açıklamaları:**
*   **--signature**: Signature scan.

**Komut:**
\`\`\`bash
binwalk --entropy firmware.bin
\`\`\`
**Açıklama:**
Entropy analizi (kısa hali -E).
**Argüman Açıklamaları:**
*   **--entropy**: Entropy scan.

**Komut:**
\`\`\`bash
binwalk --hexdump firmware.bin
\`\`\`
**Açıklama:**
Hex dökümü (kısa hali -d).
**Argüman Açıklamaları:**
*   **--hexdump**: Hex dump.

**Komut:**
\`\`\`bash
binwalk --strings firmware.bin
\`\`\`
**Açıklama:**
String taraması (kısa hali -W).
**Argüman Açıklamaları:**
*   **--strings**: Strings scan.

**Komut:**
\`\`\`bash
binwalk --opcodes firmware.bin
\`\`\`
**Açıklama:**
Opcode (makine kodu) imzalarını arar.
**Argüman Açıklamaları:**
*   **--opcodes**: Opcode scan.

### Output

**Komut:**
\`\`\`bash
binwalk --directory extracted/ firmware.bin
\`\`\`
**Açıklama:**
Çıkarma işlemini özel dizine yapar.
**Argüman Açıklamaları:**
*   **--directory**: Hedef dizin.

**Komut:**
\`\`\`bash
binwalk --log scan.log firmware.bin
\`\`\`
**Açıklama:**
Sonuçları log dosyasına yazar.
**Argüman Açıklamaları:**
*   **--log**: Log dosyası.

**Komut:**
\`\`\`bash
binwalk --csv firmware.bin
\`\`\`
**Açıklama:**
CSV formatında çıktı verir.
**Argüman Açıklamaları:**
*   **--csv**: CSV formatı.

**Komut:**
\`\`\`bash
binwalk --json firmware.bin
\`\`\`
**Açıklama:**
JSON formatında çıktı verir (destekleniyorsa).
**Argüman Açıklamaları:**
*   **--json**: JSON formatı.

**Komut:**
\`\`\`bash
binwalk --quiet firmware.bin
\`\`\`
**Açıklama:**
Sessiz mod, çıktı vermez.
**Argüman Açıklamaları:**
*   **--quiet**: Quiet mode.

## 6. Gerçek Pentest Senaryoları

### IoT Firmware Üzerinde Filesystem Extraction
\`\`\`bash
binwalk -e firmware.bin
\`\`\`
**Açıklama:**
Firmware içindeki dosya sistemlerini (squashfs, jffs2 vb.) otomatik olarak tespit edip çıkarır.

### Router Firmware İçinde Squashfs / Cramfs Çıkarma
\`\`\`bash
binwalk -Me router_update.bin
\`\`\`
**Açıklama:**
Recursive mod ile sıkıştırılmış dosya sistemlerini sonuna kadar açar.

### U-Boot Image İçindeki Kernel + Rootfs Ayrıştırma
\`\`\`bash
binwalk -e uboot_image.img
\`\`\`
**Açıklama:**
U-Boot başlıklarını analiz edip kernel ve root dosya sistemini ayırır.

### APK İçinde Gömülü SO File Discovery
\`\`\`bash
binwalk -e application.apk
\`\`\`
**Açıklama:**
Android APK dosyası içindeki native kütüphaneleri (.so) ve diğer gömülü dosyaları çıkarır.

### Gömülü Cihazda Hidden Partition Tespiti
\`\`\`bash
binwalk -B flash_dump.bin
\`\`\`
**Açıklama:**
Flash dökümü üzerinde imza taraması yaparak gizli veya bilinmeyen bölümleri (partition) bulur.

### Entropy Analizi ile Packed/Obfuscated Kod Bulma
\`\`\`bash
binwalk -E firmware.bin
\`\`\`
**Açıklama:**
Entropy grafiğindeki yüksek düzlükler (high flatline) şifreli veya sıkıştırılmış alanları gösterir.

### Gömülü Sertifika & Private Key Arama
\`\`\`bash
binwalk -R firmware.bin | grep -i "private key"
\`\`\`
**Açıklama:**
Raw extraction veya string analizi ile gömülü SSL anahtarlarını arar.

### Static Web UI Dosyalarını Ayıklama
\`\`\`bash
binwalk -e firmware.bin --dd="html:html"
\`\`\`
**Açıklama:**
Firmware içindeki HTML/JS dosyalarını ayıklayarak web arayüzünü inceler.

### Embedded ELF Binary İnceleme
\`\`\`bash
binwalk -y elf firmware.bin
\`\`\`
**Açıklama:**
Sadece ELF (Executable and Linkable Format) imzalarını arar.

### Firmware İçindeki Config Dosyalarını Bulma
\`\`\`bash
binwalk -e firmware.bin
\`\`\`
**Açıklama:**
Dosya sistemi çıkarıldıktan sonra \`/etc/\` veya \`/var/\` altındaki konfigürasyonları inceler.

### Password Hash ve Shadow-like Dosya Extraction
\`\`\`bash
binwalk -Me firmware.bin
\`\`\`
**Açıklama:**
Recursive extraction sonrası \`/etc/shadow\` veya \`passwd\` dosyalarını arar.

### Bootloader İçindeki Environment Değişkenleri Bulma
\`\`\`bash
binwalk -W uboot.bin
\`\`\`
**Açıklama:**
Bootloader binary'si içindeki okunabilir boot argümanlarını (bootargs) bulur.

### Firmware Upgrade Dosyasında XOR/Obfuscation Tespiti
\`\`\`bash
binwalk -E upgrade.bin
\`\`\`
**Açıklama:**
Entropy grafiğinde dalgalanma yerine sabit yüksek değer varsa XOR veya şifreleme olabilir.

### Offset Tabanlı Manual Extraction
\`\`\`bash
dd if=firmware.bin bs=1 skip=1024 count=500 of=part.bin
\`\`\`
**Açıklama:**
Binwalk ile bulunan offset (1024) bilgisini kullanarak \`dd\` ile manuel çıkarma yapılır.

### USB Kamera Firmware Reverse Engineering
\`\`\`bash
binwalk -Me camera_fw.bin
\`\`\`
**Açıklama:**
Kamera firmware'ini analiz edip video işleme binary'lerini çıkarır.

### Smart TV Firmware Paketleme Analizi
\`\`\`bash
binwalk -B tv_update.pkg
\`\`\`
**Açıklama:**
TV güncelleme paketinin yapısını (header, compression) analiz eder.

### Multi-layered Firmware (Matryoshka) Analizi
\`\`\`bash
binwalk -M firmware_complex.bin
\`\`\`
**Açıklama:**
Çok katmanlı (zip içinde tar içinde gzip) yapıları tamamen açar.

### Entropy Spike ile Encrypted Data Section Bulma
\`\`\`bash
binwalk -E firmware.bin
\`\`\`
**Açıklama:**
Ani entropy yükselmeleri (spikes) şifreli veri bloklarını işaret edebilir.

### Malware Dropper Gömülü Payload Tespiti
\`\`\`bash
binwalk -e suspicious.exe
\`\`\`
**Açıklama:**
Executable içine gizlenmiş zararlı payload'ları çıkarır.

### OTA Update Paketinde Manipulation Tespiti
\`\`\`bash
binwalk -B ota_update.zip
\`\`\`
**Açıklama:**
OTA paketinin imza ve bütünlük yapısını kontrol eder.

## 8. Best Practices (Uzman Seviye)

*   **Hash Kontrolü**: Analize başlamadan önce dosyanın MD5/SHA256 özetini alın.
*   **Entropy Grafiği**: \`-E\` ile şifreli bölgeleri tespit edip zaman kaybetmeyin.
*   **Recursive Extraction**: \`-M\` (Matryoshka) modunu büyük firmware'lerde varsayılan olarak kullanın.
*   **Custom Signatures**: Bilinmeyen formatlar için kendi imza dosyanızı (\`-r\`) oluşturun.
*   **Manual Carving**: Binwalk başarısız olursa offset bilgisini alıp \`dd\` ile manuel çıkarın.
*   **Verification**: Çıkarılan dosya sistemlerini \`file\` komutu ve mount araçları ile doğrulayın.
*   **Magic Verification**: Hex editör ile dosya başlıklarını (magic bytes) manuel teyit edin.
*   **Layer Analysis**: Firmware'i katman katman (bootloader, kernel, fs) ayırıp inceleyin.
*   **Correlation**: Sonuçları Ghidra veya Strings çıktıları ile karşılaştırın.

## 9. Sık Yapılan Hatalar

*   **Sadece -e Kullanmak**: Recursive (\`-M\`) kullanmayıp iç içe dosyaları kaçırmak.
*   **Entropy İhmali**: Şifreli bir dosyayı açmaya çalışıp vakit kaybetmek.
*   **Default Handler Güveni**: Binwalk'un her şeyi otomatik çıkaracağını varsaymak (bazen manuel müdahale gerekir).
*   **No Custom Sig**: Tanınmayan bir dosya formatı için imza yazmamak.
*   **Offset Hatası**: Manuel çıkarmada hex/decimal dönüşüm hatası yapmak.
*   **Extract Dizini**: Çıkarma dizinini belirtmeyip (\`--directory\`) dosyaları karıştırmak.
*   **Output Format**: Raporlama için CSV/JSON kullanmayıp text çıktısında kaybolmak.
*   **Root Yetkisi**: Bazı extraction araçları (mount vb.) root yetkisi gerektirebilir, unutmak.
`;

const contentEN = `# Binwalk - Firmware Analysis Tool

## 1. Tool Definition
**Binwalk** is an analysis tool for detecting embedded content, compressed blocks, signatures, filesystems, entropy anomalies, packed sections, and code segments in firmware, binaries, images, executables, and embedded system files. It is used in firmware reverse engineering, IoT security testing, and exploit research.

## 2. Installation
*   **Kali Linux**: \`sudo apt install binwalk\`
*   **Source**: \`git clone https://github.com/ReFirmLabs/binwalk.git\`

## 3. Basic Usage

### Automatic Extraction
Automatically extracts filesystems and compressed files within the firmware.
\`\`\`bash
binwalk -e firmware.bin
\`\`\`
**Argument Explanations:**
*   **-e**: Enables extraction mode.

### Recursive Extraction (Matryoshka)
Scans and extracts nested files (e.g., fs inside gzip inside zip) recursively.
\`\`\`bash
binwalk -Me firmware.bin
\`\`\`
**Argument Explanations:**
*   **-M**: Matryoshka (recursive) mode.
*   **-e**: Extraction mode.

### Entropy Analysis
Generates an entropy graph of the file to detect encrypted or compressed areas.
\`\`\`bash
binwalk -E firmware.bin
\`\`\`
**Argument Explanations:**
*   **-E**: Entropy analysis.

### Signature Scan (Default)
Scans for known signatures (magic bytes) within the file.
\`\`\`bash
binwalk -B firmware.bin
\`\`\`
**Argument Explanations:**
*   **-B**: Signature scan (default).

### String Search
Finds readable text within the file (similar to strings command but more detailed).
\`\`\`bash
binwalk -W firmware.bin
\`\`\`
**Argument Explanations:**
*   **-W**: String scan.

### Using Custom Signature File
Scans with your own custom signature file.
\`\`\`bash
binwalk -r my_sigs firmware.bin
\`\`\`
**Argument Explanations:**
*   **-r**: Load custom signature file.

### Hex + ASCII Dump
Shows hex and ASCII dump of the file side-by-side.
\`\`\`bash
binwalk -d firmware.bin
\`\`\`
**Argument Explanations:**
*   **-d**: Hex dump mode.

### RAW Extraction
Extracts unidentified blocks as raw data.
\`\`\`bash
binwalk -R firmware.bin
\`\`\`
**Argument Explanations:**
*   **-R**: Raw extraction.

## 4. Advanced Usage

### Defining Extraction Handler
Defines a custom extraction command for a specific file type.
\`\`\`bash
binwalk -D 'png image:png-extractor %e' firmware.bin
\`\`\`
**Argument Explanations:**
*   **-D**: Define custom handler (<type>:<cmd>).

### Specifying Offset and Length
Limits analysis to a specific section of the file.
\`\`\`bash
binwalk --offset=100 --length=500 firmware.bin
\`\`\`
**Argument Explanations:**
*   **--offset**: Start byte.
*   **--length**: Length to read.

### Opcode Scan
Searches for machine code instructions for specific architectures (ARM, MIPS, etc.).
\`\`\`bash
binwalk -A firmware.bin
\`\`\`

### Filesystem Verification
To verify integrity of extracted filesystems before mounting, helper tools like \`sasquatch\` (for squashfs) or \`jefferson\` (for jffs2) must be installed. Binwalk uses them automatically.

### Saving Entropy Graph
Saves entropy analysis result as an image (PNG) (may require GUI or parameter).
\`\`\`bash
binwalk -E --save firmware.bin
\`\`\`

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments

**Command:**
\`\`\`bash
binwalk -e firmware.bin
\`\`\`
**Description:**
Automatic file extraction.
**Argument Explanations:**
*   **-e**: Extract.

**Command:**
\`\`\`bash
binwalk -M firmware.bin
\`\`\`
**Description:**
Recursive scan mode.
**Argument Explanations:**
*   **-M**: Matryoshka.

**Command:**
\`\`\`bash
binwalk -r signatures.magic firmware.bin
\`\`\`
**Description:**
Uses custom signature file.
**Argument Explanations:**
*   **-r**: Signature file.

**Command:**
\`\`\`bash
binwalk -d firmware.bin
\`\`\`
**Description:**
Takes hex dump.
**Argument Explanations:**
*   **-d**: Hex dump.

**Command:**
\`\`\`bash
binwalk -B firmware.bin
\`\`\`
**Description:**
Performs standard signature scan.
**Argument Explanations:**
*   **-B**: Binwalk scan.

**Command:**
\`\`\`bash
binwalk -E firmware.bin
\`\`\`
**Description:**
Performs entropy analysis.
**Argument Explanations:**
*   **-E**: Entropy.

**Command:**
\`\`\`bash
binwalk -R firmware.bin
\`\`\`
**Description:**
Performs raw extraction.
**Argument Explanations:**
*   **-R**: Raw extract.

**Command:**
\`\`\`bash
binwalk -W firmware.bin
\`\`\`
**Description:**
Performs string scan.
**Argument Explanations:**
*   **-W**: Strings.

**Command:**
\`\`\`bash
binwalk -y filesystem firmware.bin
\`\`\`
**Description:**
Searches only for specific signatures (e.g., filesystem).
**Argument Explanations:**
*   **-y**: Include filter.

**Command:**
\`\`\`bash
binwalk -I firmware.bin
\`\`\`
**Description:**
Shows invalid signatures as well.
**Argument Explanations:**
*   **-I**: Invalid signatures.

**Command:**
\`\`\`bash
binwalk --depth 5 firmware.bin
\`\`\`
**Description:**
Limits recursive scan depth.
**Argument Explanations:**
*   **--depth**: Depth.

**Command:**
\`\`\`bash
binwalk --offset 0x100 firmware.bin
\`\`\`
**Description:**
Starts from specified offset.
**Argument Explanations:**
*   **--offset**: Start.

**Command:**
\`\`\`bash
binwalk --length 1024 firmware.bin
\`\`\`
**Description:**
Reads only specified bytes.
**Argument Explanations:**
*   **--length**: Length.

**Command:**
\`\`\`bash
binwalk --dd="png image:png" firmware.bin
\`\`\`
**Description:**
Finds and extracts a specific signature (dd rule).
**Argument Explanations:**
*   **--dd**: Dump definition.

### Proxy / Network (Binwalk does not use network)

**Command:**
\`\`\`bash
binwalk --no-update
\`\`\`
**Description:**
Disables automatic update (if available).
**Argument Explanations:**
*   **--no-update**: No update.

### Payload & Request Manipulation

**Command:**
\`\`\`bash
binwalk -D 'zip archive:unzip %e' firmware.bin
\`\`\`
**Description:**
Defines custom extraction command for zip files.
**Argument Explanations:**
*   **-D**: Define handler.

**Command:**
\`\`\`bash
binwalk --matryoshka firmware.bin
\`\`\`
**Description:**
Recursive extraction (short -M).
**Argument Explanations:**
*   **--matryoshka**: Recursive.

**Command:**
\`\`\`bash
binwalk --raw firmware.bin
\`\`\`
**Description:**
Raw extraction (short -R).
**Argument Explanations:**
*   **--raw**: Raw.

**Command:**
\`\`\`bash
binwalk --carve firmware.bin
\`\`\`
**Description:**
Carves data without extracting.
**Argument Explanations:**
*   **--carve**: Carve data.

**Command:**
\`\`\`bash
binwalk --preserve-symlinks firmware.bin
\`\`\`
**Description:**
Extracts preserving symbolic links.
**Argument Explanations:**
*   **--preserve-symlinks**: Preserve links.

### Scanning / Enumeration

**Command:**
\`\`\`bash
binwalk --signature firmware.bin
\`\`\`
**Description:**
Signature scan (short -B).
**Argument Explanations:**
*   **--signature**: Signature scan.

**Command:**
\`\`\`bash
binwalk --entropy firmware.bin
\`\`\`
**Description:**
Entropy analysis (short -E).
**Argument Explanations:**
*   **--entropy**: Entropy scan.

**Command:**
\`\`\`bash
binwalk --hexdump firmware.bin
\`\`\`
**Description:**
Hex dump (short -d).
**Argument Explanations:**
*   **--hexdump**: Hex dump.

**Command:**
\`\`\`bash
binwalk --strings firmware.bin
\`\`\`
**Description:**
String scan (short -W).
**Argument Explanations:**
*   **--strings**: Strings scan.

**Command:**
\`\`\`bash
binwalk --opcodes firmware.bin
\`\`\`
**Description:**
Searches for opcode (machine code) signatures.
**Argument Explanations:**
*   **--opcodes**: Opcode scan.

### Output

**Command:**
\`\`\`bash
binwalk --directory extracted/ firmware.bin
\`\`\`
**Description:**
Extracts to custom directory.
**Argument Explanations:**
*   **--directory**: Target directory.

**Command:**
\`\`\`bash
binwalk --log scan.log firmware.bin
\`\`\`
**Description:**
Writes results to log file.
**Argument Explanations:**
*   **--log**: Log file.

**Command:**
\`\`\`bash
binwalk --csv firmware.bin
\`\`\`
**Description:**
Outputs in CSV format.
**Argument Explanations:**
*   **--csv**: CSV format.

**Command:**
\`\`\`bash
binwalk --json firmware.bin
\`\`\`
**Description:**
Outputs in JSON format (if supported).
**Argument Explanations:**
*   **--json**: JSON format.

**Command:**
\`\`\`bash
binwalk --quiet firmware.bin
\`\`\`
**Description:**
Quiet mode, no output.
**Argument Explanations:**
*   **--quiet**: Quiet mode.

## 6. Real Pentest Scenarios

### IoT Firmware Filesystem Extraction
\`\`\`bash
binwalk -e firmware.bin
\`\`\`
**Description:**
Automatically detects and extracts filesystems (squashfs, jffs2, etc.) inside firmware.

### Extracting Squashfs / Cramfs in Router Firmware
\`\`\`bash
binwalk -Me router_update.bin
\`\`\`
**Description:**
Fully unpacks compressed filesystems using recursive mode.

### Kernel + Rootfs Separation in U-Boot Image
\`\`\`bash
binwalk -e uboot_image.img
\`\`\`
**Description:**
Analyzes U-Boot headers and separates kernel and root filesystem.

### Embedded SO File Discovery in APK
\`\`\`bash
binwalk -e application.apk
\`\`\`
**Description:**
Extracts native libraries (.so) and other embedded files inside Android APK.

### Hidden Partition Detection in Embedded Device
\`\`\`bash
binwalk -B flash_dump.bin
\`\`\`
**Description:**
Finds hidden or unknown partitions by signature scanning on flash dump.

### Finding Packed/Obfuscated Code with Entropy Analysis
\`\`\`bash
binwalk -E firmware.bin
\`\`\`
**Description:**
High flatlines in entropy graph indicate encrypted or compressed areas.

### Embedded Certificate & Private Key Search
\`\`\`bash
binwalk -R firmware.bin | grep -i "private key"
\`\`\`
**Description:**
Searches for embedded SSL keys via raw extraction or string analysis.

### Extracting Static Web UI Files
\`\`\`bash
binwalk -e firmware.bin --dd="html:html"
\`\`\`
**Description:**
Extracts HTML/JS files inside firmware to inspect web interface.

### Embedded ELF Binary Inspection
\`\`\`bash
binwalk -y elf firmware.bin
\`\`\`
**Description:**
Searches only for ELF (Executable and Linkable Format) signatures.

### Finding Config Files in Firmware
\`\`\`bash
binwalk -e firmware.bin
\`\`\`
**Description:**
Inspects configurations under \`/etc/\` or \`/var/\` after filesystem extraction.

### Password Hash and Shadow-like File Extraction
\`\`\`bash
binwalk -Me firmware.bin
\`\`\`
**Description:**
Searches for \`/etc/shadow\` or \`passwd\` files after recursive extraction.

### Finding Environment Variables in Bootloader
\`\`\`bash
binwalk -W uboot.bin
\`\`\`
**Description:**
Finds readable boot arguments (bootargs) inside bootloader binary.

### XOR/Obfuscation Detection in Firmware Upgrade File
\`\`\`bash
binwalk -E upgrade.bin
\`\`\`
**Description:**
Constant high value instead of fluctuation in entropy graph may indicate XOR or encryption.

### Offset Based Manual Extraction
\`\`\`bash
dd if=firmware.bin bs=1 skip=1024 count=500 of=part.bin
\`\`\`
**Description:**
Manual extraction using \`dd\` with offset (1024) found by Binwalk.

### USB Camera Firmware Reverse Engineering
\`\`\`bash
binwalk -Me camera_fw.bin
\`\`\`
**Description:**
Analyzes camera firmware and extracts video processing binaries.

### Smart TV Firmware Packaging Analysis
\`\`\`bash
binwalk -B tv_update.pkg
\`\`\`
**Description:**
Analyzes structure (header, compression) of TV update package.

### Multi-layered Firmware (Matryoshka) Analysis
\`\`\`bash
binwalk -M firmware_complex.bin
\`\`\`
**Description:**
Fully unpacks multi-layered (tar inside zip inside gzip) structures.

### Finding Encrypted Data Section with Entropy Spike
\`\`\`bash
binwalk -E firmware.bin
\`\`\`
**Description:**
Sudden entropy spikes may indicate encrypted data blocks.

### Malware Dropper Embedded Payload Detection
\`\`\`bash
binwalk -e suspicious.exe
\`\`\`
**Description:**
Extracts malicious payloads hidden inside executable.

### Manipulation Detection in OTA Update Package
\`\`\`bash
binwalk -B ota_update.zip
\`\`\`
**Description:**
Checks signature and integrity structure of OTA package.

## 8. Best Practices (Expert Level)

*   **Hash Check**: Get MD5/SHA256 hash of the file before starting analysis.
*   **Entropy Graph**: Use \`-E\` to detect encrypted areas and avoid wasting time.
*   **Recursive Extraction**: Use \`-M\` (Matryoshka) mode by default on large firmware.
*   **Custom Signatures**: Create your own signature file (\`-r\`) for unknown formats.
*   **Manual Carving**: If Binwalk fails, get offset info and extract manually with \`dd\`.
*   **Verification**: Verify extracted filesystems with \`file\` command and mount tools.
*   **Magic Verification**: Manually confirm file headers (magic bytes) with hex editor.
*   **Layer Analysis**: Separate and analyze firmware layer by layer (bootloader, kernel, fs).
*   **Correlation**: Compare results with Ghidra or Strings outputs.

## 9. Common Mistakes

*   **Using Only -e**: Missing nested files by not using recursive (\`-M\`).
*   **Ignoring Entropy**: Wasting time trying to open an encrypted file.
*   **Trusting Default Handler**: Assuming Binwalk will extract everything automatically (sometimes manual intervention is needed).
*   **No Custom Sig**: Not writing signatures for an unrecognized file format.
*   **Offset Error**: Making hex/decimal conversion errors in manual extraction.
*   **Extract Directory**: Not specifying extraction directory (\`--directory\`) and mixing files.
*   **Output Format**: Getting lost in text output instead of using CSV/JSON for reporting.
*   **Root Privilege**: Forgetting that some extraction tools (mount etc.) may require root privileges.
`;

async function addBinwalk() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Binwalk cheatsheet...');

        let category = await Category.findOne({ 'name.en': 'Firmware Analysis' });
        if (!category) {
            console.log('Category "Firmware Analysis" not found, creating...');
            category = await Category.create({
                name: { tr: 'Firmware Analizi', en: 'Firmware Analysis' },
                description: { tr: 'Firmware ve gömülü sistem analiz araçları', en: 'Firmware and embedded system analysis tools' },
                slug: 'firmware-analysis',
                icon: 'Chip'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Binwalk Cheat Sheet',
                en: 'Binwalk Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['binwalk', 'firmware', 'reverse-engineering', 'iot', 'extraction', 'entropy']
        };

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Binwalk Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Binwalk cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addBinwalk();
