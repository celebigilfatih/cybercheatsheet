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

const contentTR = `# Wifite - Automated Wireless Auditor

## 1. Araç Tanımı
**Wifite**, kablosuz ağlar üzerinde automated attack, handshake capture, WPS cracking, PMKID toplama, evil twin hazırlığı ve genel wireless auditing işlemlerini gerçekleştirir. Python tabanlıdır ve Aircrack-ng, Reaver, Pyrit gibi araçları otomatikleştirir.

## 2. Kurulum
*   **Kali Linux**: \`sudo apt install wifite\`
*   **Source**: \`git clone https://github.com/derv82/wifite2.git && cd wifite2 && sudo python3 setup.py install\`

## 3. Temel Kullanım

### Otomatik Tarama ve Saldırı
Arayüz seçimi sonrası çevredeki ağları tarar ve hedef seçimi bekler.
\`\`\`bash
sudo wifite
\`\`\`

### Belirli Bir Arayüz ile Başlatma
Monitor moda alınmış arayüzü doğrudan belirterek başlatır.
\`\`\`bash
sudo wifite -i wlan0mon
\`\`\`
**Argüman Açıklamaları:**
*   **-i**: Kablosuz arayüz (interface).

### Sadece WPA Ağlarını Hedefleme
WEP ve açık ağları atlayarak sadece WPA/WPA2 şifreli ağlara odaklanır.
\`\`\`bash
sudo wifite --wpa
\`\`\`
**Argüman Açıklamaları:**
*   **--wpa**: Sadece WPA ağlarını tara.

### Sadece WPS Açık Ağları Hedefleme
WPS (Wi-Fi Protected Setup) özelliği açık olan modemleri hedefler (Pixie Dust vb.).
\`\`\`bash
sudo wifite --wps
\`\`\`
**Argüman Açıklamaları:**
*   **--wps**: Sadece WPS ağlarını tara.

### PMKID Saldırısı (Clientless)
İstemciye (client) ihtiyaç duymadan PMKID hash'ini yakalamaya çalışır.
\`\`\`bash
sudo wifite --pmkid
\`\`\`
**Argüman Açıklamaları:**
*   **--pmkid**: PMKID yakalama modunu aç.

### Servisleri Durdurma (Kill)
Çakışan ağ yöneticilerini (NetworkManager, wpa_supplicant) durdurur.
\`\`\`bash
sudo wifite --kill
\`\`\`
**Argüman Açıklamaları:**
*   **--kill**: Çakışan işlemleri öldür.

### Belirli MAC Adreslerini Yok Sayma
Kendi ağınızı veya test dışı ağları tarama listesinden çıkarır.
\`\`\`bash
sudo wifite --ignore 00:11:22:33:44:55
\`\`\`
**Argüman Açıklamaları:**
*   **--ignore**: Belirtilen MAC adresini atla.

### Sinyal Gücü Filtresi
Belirli bir sinyal gücünün (dBm) altındaki uzak ağları listelemez.
\`\`\`bash
sudo wifite --power 70
\`\`\`
**Argüman Açıklamaları:**
*   **--power**: Minimum sinyal gücü (> 70).

## 4. İleri Seviye Kullanım

### Dictionary (Sözlük) Belirtme
Yakalanan handshake'leri kırmak için özel wordlist kullanır.
\`\`\`bash
sudo wifite --dict /usr/share/wordlists/rockyou.txt
\`\`\`
**Argüman Açıklamaları:**
*   **--dict**: Wordlist yolu.

### Kanal Sabitleme
Taramayı sadece belirli kanallarda yaparak hızı artırır.
\`\`\`bash
sudo wifite --channels 1,6,11
\`\`\`
**Argüman Açıklamaları:**
*   **--channels**: Taranacak kanallar.

### Saldırı Zaman Aşımı (Timeout)
Her bir hedef için maksimum saldırı süresini belirler.
\`\`\`bash
sudo wifite --timeout 300
\`\`\`
**Argüman Açıklamaları:**
*   **--timeout**: Saniye cinsinden süre.

### PMKID Bekleme Süresi
PMKID yakalamak için beklenecek süreyi ayarlar.
\`\`\`bash
sudo wifite --pmkid-time 60
\`\`\`
**Argüman Açıklamaları:**
*   **--pmkid-time**: PMKID bekleme süresi.

### Dependency Kontrolü
Gerekli araçların (aircrack-ng, reaver, tshark vb.) yüklü olup olmadığını kontrol eder.
\`\`\`bash
sudo wifite --check
\`\`\`

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar

**Komut:**
\`\`\`bash
sudo wifite -i wlan0mon
\`\`\`
**Açıklama:**
Arayüz seçimi.
**Argüman Açıklamaları:**
*   **-i**: Interface.

**Komut:**
\`\`\`bash
sudo wifite --check
\`\`\`
**Açıklama:**
Bağımlılık kontrolü.
**Argüman Açıklamaları:**
*   **--check**: Check dependencies.

**Komut:**
\`\`\`bash
sudo wifite --kill
\`\`\`
**Açıklama:**
Network servislerini durdurur.
**Argüman Açıklamaları:**
*   **--kill**: Kill processes.

**Komut:**
\`\`\`bash
sudo wifite --wpa
\`\`\`
**Açıklama:**
WPA filtreleme.
**Argüman Açıklamaları:**
*   **--wpa**: WPA only.

**Komut:**
\`\`\`bash
sudo wifite --wps
\`\`\`
**Açıklama:**
WPS filtreleme.
**Argüman Açıklamaları:**
*   **--wps**: WPS only.

**Komut:**
\`\`\`bash
sudo wifite --pmkid
\`\`\`
**Açıklama:**
PMKID saldırısı.
**Argüman Açıklamaları:**
*   **--pmkid**: PMKID mode.

**Komut:**
\`\`\`bash
sudo wifite --ignore 00:11:22:33:44:55
\`\`\`
**Açıklama:**
MAC adresi yoksayma.
**Argüman Açıklamaları:**
*   **--ignore**: Ignore BSSID.

**Komut:**
\`\`\`bash
sudo wifite --power 60
\`\`\`
**Açıklama:**
Güç filtresi.
**Argüman Açıklamaları:**
*   **--power**: Min power.

**Komut:**
\`\`\`bash
sudo wifite --channels 1,6,11
\`\`\`
**Açıklama:**
Kanal seçimi.
**Argüman Açıklamaları:**
*   **--channels**: Channels list.

### Proxy / Network (Network Scanning)

**Komut:**
\`\`\`bash
sudo wifite --timeout 600
\`\`\`
**Açıklama:**
Genel zaman aşımı.
**Argüman Açıklamaları:**
*   **--timeout**: Timeout.

**Komut:**
\`\`\`bash
sudo wifite --pmkid-time 120
\`\`\`
**Açıklama:**
PMKID özel zaman aşımı.
**Argüman Açıklamaları:**
*   **--pmkid-time**: PMKID timeout.

**Komut:**
\`\`\`bash
sudo wifite --dict wordlist.txt
\`\`\`
**Açıklama:**
Sözlük dosyası.
**Argüman Açıklamaları:**
*   **--dict**: Dictionary file.

**Komut:**
\`\`\`bash
sudo wifite --verbose
\`\`\`
**Açıklama:**
Detaylı çıktı.
**Argüman Açıklamaları:**
*   **--verbose**: Verbose output.

**Komut:**
\`\`\`bash
sudo wifite --debug
\`\`\`
**Açıklama:**
Hata ayıklama.
**Argüman Açıklamaları:**
*   **--debug**: Debug mode.

### Payload & Request Manipulation (Attack Modes)

**Komut:**
\`\`\`bash
sudo wifite --wps --wpa
\`\`\`
**Açıklama:**
Hem WPS hem WPA hedefler.
**Argüman Açıklamaları:**
*   **--wps**: WPS.
*   **--wpa**: WPA.

**Komut:**
\`\`\`bash
sudo wifite --no-pmkid
\`\`\`
**Açıklama:**
PMKID saldırısını devre dışı bırakır (bazı versiyonlarda).
**Argüman Açıklamaları:**
*   **--no-pmkid**: Disable PMKID.

**Komut:**
\`\`\`bash
sudo wifite --no-wps
\`\`\`
**Açıklama:**
WPS saldırısını devre dışı bırakır.
**Argüman Açıklamaları:**
*   **--no-wps**: Disable WPS.

### Scanning / Enumeration

**Komut:**
\`\`\`bash
sudo wifite --nodeauths
\`\`\`
**Açıklama:**
Deauth (bağlantı koparma) saldırısı yapmadan tarar (pasif).
**Argüman Açıklamaları:**
*   **--nodeauths**: No deauth.

**Komut:**
\`\`\`bash
sudo wifite --daemon
\`\`\`
**Açıklama:**
Arka planda çalışır (bazı forklar destekler).
**Argüman Açıklamaları:**
*   **--daemon**: Daemon mode.

### Output

**Komut:**
\`\`\`bash
sudo wifite --csv
\`\`\`
**Açıklama:**
CSV çıktısı üretir.
**Argüman Açıklamaları:**
*   **--csv**: CSV output.

**Komut:**
\`\`\`bash
sudo wifite -o ./captures
\`\`\`
**Açıklama:**
Çıktı dizini.
**Argüman Açıklamaları:**
*   **-o**: Output dir.

## 6. Gerçek Pentest Senaryoları

### Hidden SSID Ortaya Çıkarma
\`\`\`bash
sudo wifite -i wlan0mon --wpa --power 50
\`\`\`
**Açıklama:**
Gizli ağları (Hidden SSID) tespit etmek için istemci trafiğini izler ve WPA ağlarını hedefler.

### WPA2 Handshake Capture + Dictionary Attack
\`\`\`bash
sudo wifite --wpa --dict /usr/share/wordlists/rockyou.txt --kill
\`\`\`
**Açıklama:**
WPA2 ağlarından handshake yakalayıp belirtilen sözlükle kırmaya çalışır.

### PMKID Toplama ve Offline Crack Hazırlığı
\`\`\`bash
sudo wifite --pmkid --pmkid-time 120 --no-wps
\`\`\`
**Açıklama:**
İstemci olmadan PMKID hash'ini toplar, WPS'i kapatarak sadece buna odaklanır.

### Yalnızca Zayıf Sinyalli AP’leri Hedefleme
\`\`\`bash
sudo wifite --power 10 --verbose
\`\`\`
**Açıklama:**
Uzak mesafedeki (düşük sinyalli) erişim noktalarını da tarama kapsamına alır.

### Kurumsal Ağda Rogue AP Tespiti
\`\`\`bash
sudo wifite --csv --check
\`\`\`
**Açıklama:**
Çevredeki tüm ağları CSV'ye dökerek yetkisiz (Rogue) erişim noktalarını analiz eder.

### Evil Twin Hazırlığı (Capture Phase)
\`\`\`bash
sudo wifite --wpa --nodeauths -o ./handshakes
\`\`\`
**Açıklama:**
Evil Twin saldırısı öncesi hedef ağın handshake bilgisini pasif olarak toplar.

### WPS Pixie Dust Zafiyeti Denemesi
\`\`\`bash
sudo wifite --wps --wps-only
\`\`\`
**Açıklama:**
Sadece WPS açık modemlerde Pixie Dust (offline WPS attack) dener.

### Kanal Sabitleyerek Hedef AP Davranış Analizi
\`\`\`bash
sudo wifite -c 11 --verbose
\`\`\`
**Açıklama:**
Sadece 11. kanalı dinleyerek o kanaldaki trafiği ve hedefleri izler.

### Timeout Manipülasyonu ile Rate-Limit Bypass Analizi
\`\`\`bash
sudo wifite --wps --timeout 600
\`\`\`
**Açıklama:**
WPS saldırısında rate-limit'e takılmamak için uzun zaman aşımı kullanır (veya delay ekler).

### Ignore List ile Belirli MAC Filtreleme
\`\`\`bash
sudo wifite --ignore 00:11:22:33:44:55 --ignore 66:77:88:99:AA:BB
\`\`\`
**Açıklama:**
Kapsam dışı olan komşu ağları tarama listesinden çıkarır.

### Sinyal Gücü Yüksek AP Brute-Force Davranışı
\`\`\`bash
sudo wifite --power 80 --wps
\`\`\`
**Açıklama:**
Sadece çok yakın ve güçlü sinyal veren modemlere WPS saldırısı yapar.

### Çoklu Interface ile Scanning Stabilizasyonu
\`\`\`bash
sudo wifite -i wlan1mon
\`\`\`
**Açıklama:**
Daha güçlü antene sahip harici adaptörü seçerek kararlı tarama yapar.

### 2.4 GHz vs 5 GHz Karşılaştırmalı Scanning
\`\`\`bash
sudo wifite --5ghz
\`\`\`
**Açıklama:**
(Destekleyen kartlarda) 5GHz bandındaki ağları tarar.

### Low-Visibility AP Enumeration
\`\`\`bash
sudo wifite --power 1 --verbose
\`\`\`
**Açıklama:**
Görünürlüğü çok düşük olan tüm sinyalleri listeler.

### PMKID + Handshake Hibrit Toplama
\`\`\`bash
sudo wifite --wpa --pmkid
\`\`\`
**Açıklama:**
Hem handshake yakalamayı hem de PMKID almayı dener, hangisi önce gelirse.

### Fake Deauth ile Bağlantı Koparma Davranış Testi
\`\`\`bash
sudo wifite --wpa --timeout 30
\`\`\`
**Açıklama:**
Kısa süreli deauth paketleri göndererek istemcilerin tekrar bağlanma (reconnect) hızını ölçer.

## 8. Best Practices (Uzman Seviye)

*   **Monitor Mode**: Başlamadan önce \`airmon-ng start wlan0\` ile kartı manuel monitor moda alın.
*   **Handshake Doğrulama**: Yakalanan .cap dosyasını \`hcxpcapngtool\` veya \`pyrit\` ile doğrulayın.
*   **WPS Pixie Dust**: Varsayılan olarak açıktır, kapatmayın; en hızlı yöntemdir.
*   **PMKID Timeout**: PMKID bazen geç düşer, \`--pmkid-time\` değerini 120+ saniye yapın.
*   **Hidden SSID**: Gizli ağları bulmak için trafiğin yoğun olduğu saatleri bekleyin.
*   **Ignore List**: Kendi ağınızı veya test dışı ağları mutlaka \`--ignore\` ile hariç tutun.
*   **Sinyal Gücü**: \`--power 50\` gibi bir filtre ile zaman kaybetmeyi önleyin.
*   **CSV Output**: Raporlama için \`--csv\` parametresini her zaman kullanın.
*   **Lock-out**: WPS saldırılarında modem kilitlenirse (lock-out) saldırıyı durdurun.
*   **5 GHz**: Kartınız destekliyorsa 5 GHz ağlarını taramayı unutmayın, kurumsal ağlar oradadır.

## 9. Sık Yapılan Hatalar

*   **No Monitor Mode**: Kartı managed modda bırakıp tarama yapmaya çalışmak.
*   **Low PMKID Timeout**: PMKID süresini kısa tutup hash'i kaçırmak.
*   **Passive Hidden SSID**: Gizli ağa hiç deauth atmadan isminin görünmesini beklemek.
*   **Ignoring Lock-out**: WPS kilitlendiği halde saldırıya devam edip zaman harcamak.
*   **All Channels**: Tüm kanalları tarayarak (hoping) hedefi kaçırmak (hedef kanalı sabitleyin).
*   **Wrong Wordlist**: WPA kırmak için çok küçük veya alakasız wordlist kullanmak.
*   **Weak Signal**: %10 sinyal gücü olan ağa saldırıp paket kaybı yaşamak.
*   **No CSV**: Ekranda akan veriyi kaydetmeyip sonradan analiz edememek.
*   **No Ignore**: Yasal olmayan ağlara yanlışlıkla saldırı başlatmak.
*   **Unverified Handshake**: Bozuk (partial) handshake ile saatlerce crack denemesi yapmak.
`;

const contentEN = `# Wifite - Automated Wireless Auditor

## 1. Tool Definition
**Wifite** performs automated attacks, handshake capture, WPS cracking, PMKID collection, evil twin preparation, and general wireless auditing on wireless networks. It is Python-based and automates tools like Aircrack-ng, Reaver, and Pyrit.

## 2. Installation
*   **Kali Linux**: \`sudo apt install wifite\`
*   **Source**: \`git clone https://github.com/derv82/wifite2.git && cd wifite2 && sudo python3 setup.py install\`

## 3. Basic Usage

### Automatic Scan and Attack
Scans surrounding networks after interface selection and waits for target selection.
\`\`\`bash
sudo wifite
\`\`\`

### Start with Specific Interface
Starts by directly specifying the interface in monitor mode.
\`\`\`bash
sudo wifite -i wlan0mon
\`\`\`
**Argument Explanations:**
*   **-i**: Wireless interface.

### Target WPA Networks Only
Skips WEP and open networks, focusing only on WPA/WPA2 encrypted networks.
\`\`\`bash
sudo wifite --wpa
\`\`\`
**Argument Explanations:**
*   **--wpa**: Scan WPA networks only.

### Target WPS Enabled Networks Only
Targets modems with WPS (Wi-Fi Protected Setup) enabled (Pixie Dust, etc.).
\`\`\`bash
sudo wifite --wps
\`\`\`
**Argument Explanations:**
*   **--wps**: Scan WPS networks only.

### PMKID Attack (Clientless)
Attempts to capture PMKID hash without needing a client.
\`\`\`bash
sudo wifite --pmkid
\`\`\`
**Argument Explanations:**
*   **--pmkid**: Enable PMKID capture mode.

### Kill Services
Stops conflicting network managers (NetworkManager, wpa_supplicant).
\`\`\`bash
sudo wifite --kill
\`\`\`
**Argument Explanations:**
*   **--kill**: Kill conflicting processes.

### Ignore Specific MAC Addresses
Excludes your own network or out-of-scope networks from the scan list.
\`\`\`bash
sudo wifite --ignore 00:11:22:33:44:55
\`\`\`
**Argument Explanations:**
*   **--ignore**: Skip specified MAC address.

### Signal Power Filter
Does not list distant networks below a certain signal power (dBm).
\`\`\`bash
sudo wifite --power 70
\`\`\`
**Argument Explanations:**
*   **--power**: Minimum signal power (> 70).

## 4. Advanced Usage

### Specify Dictionary
Uses a custom wordlist to crack captured handshakes.
\`\`\`bash
sudo wifite --dict /usr/share/wordlists/rockyou.txt
\`\`\`
**Argument Explanations:**
*   **--dict**: Wordlist path.

### Channel Fixing
Increases speed by scanning only on specified channels.
\`\`\`bash
sudo wifite --channels 1,6,11
\`\`\`
**Argument Explanations:**
*   **--channels**: Channels to scan.

### Attack Timeout
Sets the maximum attack duration for each target.
\`\`\`bash
sudo wifite --timeout 300
\`\`\`
**Argument Explanations:**
*   **--timeout**: Duration in seconds.

### PMKID Wait Time
Sets the duration to wait for PMKID capture.
\`\`\`bash
sudo wifite --pmkid-time 60
\`\`\`
**Argument Explanations:**
*   **--pmkid-time**: PMKID wait time.

### Dependency Check
Checks if required tools (aircrack-ng, reaver, tshark, etc.) are installed.
\`\`\`bash
sudo wifite --check
\`\`\`

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments

**Command:**
\`\`\`bash
sudo wifite -i wlan0mon
\`\`\`
**Description:**
Interface selection.
**Argument Explanations:**
*   **-i**: Interface.

**Command:**
\`\`\`bash
sudo wifite --check
\`\`\`
**Description:**
Dependency check.
**Argument Explanations:**
*   **--check**: Check dependencies.

**Command:**
\`\`\`bash
sudo wifite --kill
\`\`\`
**Description:**
Stops network services.
**Argument Explanations:**
*   **--kill**: Kill processes.

**Command:**
\`\`\`bash
sudo wifite --wpa
\`\`\`
**Description:**
WPA filtering.
**Argument Explanations:**
*   **--wpa**: WPA only.

**Command:**
\`\`\`bash
sudo wifite --wps
\`\`\`
**Description:**
WPS filtering.
**Argument Explanations:**
*   **--wps**: WPS only.

**Command:**
\`\`\`bash
sudo wifite --pmkid
\`\`\`
**Description:**
PMKID attack.
**Argument Explanations:**
*   **--pmkid**: PMKID mode.

**Command:**
\`\`\`bash
sudo wifite --ignore 00:11:22:33:44:55
\`\`\`
**Description:**
Ignore MAC address.
**Argument Explanations:**
*   **--ignore**: Ignore BSSID.

**Command:**
\`\`\`bash
sudo wifite --power 60
\`\`\`
**Description:**
Power filter.
**Argument Explanations:**
*   **--power**: Min power.

**Command:**
\`\`\`bash
sudo wifite --channels 1,6,11
\`\`\`
**Description:**
Channel selection.
**Argument Explanations:**
*   **--channels**: Channels list.

### Proxy / Network (Network Scanning)

**Command:**
\`\`\`bash
sudo wifite --timeout 600
\`\`\`
**Description:**
General timeout.
**Argument Explanations:**
*   **--timeout**: Timeout.

**Command:**
\`\`\`bash
sudo wifite --pmkid-time 120
\`\`\`
**Description:**
PMKID specific timeout.
**Argument Explanations:**
*   **--pmkid-time**: PMKID timeout.

**Command:**
\`\`\`bash
sudo wifite --dict wordlist.txt
\`\`\`
**Description:**
Dictionary file.
**Argument Explanations:**
*   **--dict**: Dictionary file.

**Command:**
\`\`\`bash
sudo wifite --verbose
\`\`\`
**Description:**
Verbose output.
**Argument Explanations:**
*   **--verbose**: Verbose output.

**Command:**
\`\`\`bash
sudo wifite --debug
\`\`\`
**Description:**
Debugging.
**Argument Explanations:**
*   **--debug**: Debug mode.

### Payload & Request Manipulation (Attack Modes)

**Command:**
\`\`\`bash
sudo wifite --wps --wpa
\`\`\`
**Description:**
Targets both WPS and WPA.
**Argument Explanations:**
*   **--wps**: WPS.
*   **--wpa**: WPA.

**Command:**
\`\`\`bash
sudo wifite --no-pmkid
\`\`\`
**Description:**
Disables PMKID attack (in some versions).
**Argument Explanations:**
*   **--no-pmkid**: Disable PMKID.

**Command:**
\`\`\`bash
sudo wifite --no-wps
\`\`\`
**Description:**
Disables WPS attack.
**Argument Explanations:**
*   **--no-wps**: Disable WPS.

### Scanning / Enumeration

**Command:**
\`\`\`bash
sudo wifite --nodeauths
\`\`\`
**Description:**
Scans without deauth attacks (passive).
**Argument Explanations:**
*   **--nodeauths**: No deauth.

**Command:**
\`\`\`bash
sudo wifite --daemon
\`\`\`
**Description:**
Runs in background (some forks support this).
**Argument Explanations:**
*   **--daemon**: Daemon mode.

### Output

**Command:**
\`\`\`bash
sudo wifite --csv
\`\`\`
**Description:**
Generates CSV output.
**Argument Explanations:**
*   **--csv**: CSV output.

**Command:**
\`\`\`bash
sudo wifite -o ./captures
\`\`\`
**Description:**
Output directory.
**Argument Explanations:**
*   **-o**: Output dir.

## 6. Real Pentest Scenarios

### Revealing Hidden SSID
\`\`\`bash
sudo wifite -i wlan0mon --wpa --power 50
\`\`\`
**Description:**
Monitors client traffic to detect Hidden SSIDs and targets WPA networks.

### WPA2 Handshake Capture + Dictionary Attack
\`\`\`bash
sudo wifite --wpa --dict /usr/share/wordlists/rockyou.txt --kill
\`\`\`
**Description:**
Captures handshake from WPA2 networks and attempts to crack it with the specified dictionary.

### PMKID Collection and Offline Crack Preparation
\`\`\`bash
sudo wifite --pmkid --pmkid-time 120 --no-wps
\`\`\`
**Description:**
Collects PMKID hash without clients, disabling WPS to focus only on this.

### Targeting Only Weak Signal APs
\`\`\`bash
sudo wifite --power 10 --verbose
\`\`\`
**Description:**
Includes distant (low signal) access points in the scan scope.

### Rogue AP Detection in Corporate Network
\`\`\`bash
sudo wifite --csv --check
\`\`\`
**Description:**
Dumps all surrounding networks to CSV to analyze unauthorized (Rogue) access points.

### Evil Twin Preparation (Capture Phase)
\`\`\`bash
sudo wifite --wpa --nodeauths -o ./handshakes
\`\`\`
**Description:**
Passively collects handshake info of the target network before Evil Twin attack.

### WPS Pixie Dust Vulnerability Attempt
\`\`\`bash
sudo wifite --wps --wps-only
\`\`\`
**Description:**
Tries Pixie Dust (offline WPS attack) only on WPS enabled modems.

### Target AP Behavior Analysis by Fixing Channel
\`\`\`bash
sudo wifite -c 11 --verbose
\`\`\`
**Description:**
Monitors traffic and targets only on channel 11.

### Rate-Limit Bypass Analysis with Timeout Manipulation
\`\`\`bash
sudo wifite --wps --timeout 600
\`\`\`
**Description:**
Uses long timeout (or adds delay) to avoid rate-limit in WPS attack.

### Filtering Specific MAC with Ignore List
\`\`\`bash
sudo wifite --ignore 00:11:22:33:44:55 --ignore 66:77:88:99:AA:BB
\`\`\`
**Description:**
Removes out-of-scope neighbor networks from the scan list.

### High Signal Power AP Brute-Force Behavior
\`\`\`bash
sudo wifite --power 80 --wps
\`\`\`
**Description:**
Performs WPS attack only on very close and strong signal modems.

### Scanning Stabilization with Multiple Interfaces
\`\`\`bash
sudo wifite -i wlan1mon
\`\`\`
**Description:**
Selects external adapter with stronger antenna for stable scanning.

### 2.4 GHz vs 5 GHz Comparative Scanning
\`\`\`bash
sudo wifite --5ghz
\`\`\`
**Description:**
Scans networks in the 5GHz band (on supported cards).

### Low-Visibility AP Enumeration
\`\`\`bash
sudo wifite --power 1 --verbose
\`\`\`
**Description:**
Lists all signals with very low visibility.

### PMKID + Handshake Hybrid Collection
\`\`\`bash
sudo wifite --wpa --pmkid
\`\`\`
**Description:**
Attempts to capture both handshake and PMKID, whichever comes first.

### Disconnection Behavior Test with Fake Deauth
\`\`\`bash
sudo wifite --wpa --timeout 30
\`\`\`
**Description:**
Measures client reconnection speed by sending short-term deauth packets.

## 8. Best Practices (Expert Level)

*   **Monitor Mode**: Manually set card to monitor mode with \`airmon-ng start wlan0\` before starting.
*   **Handshake Verification**: Verify captured .cap file with \`hcxpcapngtool\` or \`pyrit\`.
*   **WPS Pixie Dust**: It is on by default, do not turn it off; it is the fastest method.
*   **PMKID Timeout**: PMKID sometimes drops late, set \`--pmkid-time\` to 120+ seconds.
*   **Hidden SSID**: Wait for peak traffic hours to find hidden networks.
*   **Ignore List**: Always exclude your own or out-of-scope networks with \`--ignore\`.
*   **Signal Power**: Prevent wasting time with a filter like \`--power 50\`.
*   **CSV Output**: Always use \`--csv\` parameter for reporting.
*   **Lock-out**: Stop the attack if the modem locks out during WPS attacks.
*   **5 GHz**: Don't forget to scan 5 GHz networks if your card supports it, corporate networks are there.

## 9. Common Mistakes

*   **No Monitor Mode**: Trying to scan leaving the card in managed mode.
*   **Low PMKID Timeout**: Keeping PMKID duration short and missing the hash.
*   **Passive Hidden SSID**: Waiting for hidden network name to appear without sending any deauth.
*   **Ignoring Lock-out**: Continuing attack even when WPS is locked, wasting time.
*   **All Channels**: Scanning all channels (hopping) and missing the target (fix the target channel).
*   **Wrong Wordlist**: Using a very small or irrelevant wordlist for WPA cracking.
*   **Weak Signal**: Attacking a network with 10% signal and experiencing packet loss.
*   **No CSV**: Not saving streaming data to file and failing to analyze later.
*   **No Ignore**: Accidentally attacking illegal networks.
*   **Unverified Handshake**: Trying to crack for hours with a corrupted (partial) handshake.
`;

async function addWifite() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Wifite cheatsheet...');

        let category = await Category.findOne({ 'name.en': 'Wireless Attacks' });
        if (!category) {
            console.log('Category "Wireless Attacks" not found, creating...');
            category = await Category.create({
                name: { tr: 'Kablosuz Ağ Saldırıları', en: 'Wireless Attacks' },
                description: { tr: 'Wi-Fi ve kablosuz ağ güvenlik test araçları', en: 'Wi-Fi and wireless network security testing tools' },
                slug: 'wireless-attacks',
                icon: 'Wifi'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Wifite Cheat Sheet',
                en: 'Wifite Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['wifite', 'wireless', 'wifi', 'wpa', 'wps', 'pmkid', 'handshake', 'cracking']
        };

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Wifite Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Wifite cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addWifite();
