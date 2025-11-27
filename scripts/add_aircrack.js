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

const contentTR = `# Aircrack-ng Suite

## 3. Temel Kullanım

**Monitor Mode Aktifleştirme:**
Kablosuz ağ kartını dinleme moduna (monitor mode) alarak havada uçuşan tüm paketleri yakalamayı sağlar.
\`\`\`bash
airmon-ng start wlan0
\`\`\`

**Aireplay-ng ile Paket Injection:**
Kartın paket enjekte edip edemediğini test eder. Saldırıların başarısı için injection şarttır.
\`\`\`bash
aireplay-ng --test wlan0mon
\`\`\`

**Airodump-ng ile Tarama:**
2.4 GHz veya 5 GHz bandındaki tüm erişim noktalarını (AP) ve bağlı istemcileri (client) listeler.
\`\`\`bash
airodump-ng wlan0mon
\`\`\`

**WPA/WPA2 Handshake Yakalama:**
Bir istemci AP'ye bağlanırken gerçekleşen 4'lü el sıkışmayı (4-way handshake) yakalar. Parola kırmak için gereklidir.

**WEP IV Toplama:**
WEP şifresini kırmak için gereken Initialization Vector (IV) paketlerini toplar.

**Temel Kanal ve BSSID Seçimi:**
Hedef odaklı tarama yapmak için belirli bir kanala ve AP'nin MAC adresine (BSSID) kilitlenilir.

**Pcap Çıktı Alma:**
Yakalanan paketleri analiz veya kırma işlemi için dosyaya kaydeder (\`-w dosyaadi\`).

**Temel Aircrack-ng WPA2 Kırma:**
Yakalanan handshake dosyasını bir wordlist (sözlük) kullanarak kırmayı dener.

## 4. İleri Seviye Kullanım

### Monitor Mode Gelişmiş Teknikleri
*   **Driver Selection**: Kartın chipsetine (ath9k, rtl88xx, mt76) uygun driver'ı kullanmak injection performansını doğrudan etkiler.
*   **Injection Optimization**: Bazı kartlar belirli kanallarda daha iyi injection yapar.
*   **Regulatory Domain**: \`iw reg set BO\` gibi komutlarla kartın çıkış gücü (TX power) limitleri artırılabilir.

### Airodump-ng Gelişmiş Kullanım
*   **Kanal Sabitleme**: \`-c 6\` ile kartın kanal değiştirmesini (hopping) engelleyerek paket kaybını önleyin.
*   **Only-WPA**: \`--encrypt wpa\` ile sadece WPA ağlarını filtreleyin.
*   **Hidden SSID Enumeration**: Gizli ağlara (Hidden SSID) bağlanan bir client yakalandığında airodump-ng ismi otomatik çözer.
*   **Konumlama**: Sinyal gücü (PWR) -100 (uzak) ile -10 (çok yakın) arasında değişir. Fiziksel yer tespiti için kullanılır.

### Aireplay-ng Gelişmiş Kullanım
*   **Deauth Saldırısı**: İstemciyi ağdan düşürerek yeniden bağlanmaya (re-associate) zorlar ve handshake yakalanmasını sağlar.
*   **Fake Authentication**: WEP saldırılarında veya AP'ye paket göndermeden önce "ben bu ağa bağlıyım" demek için kullanılır.
*   **ARP Replay**: WEP ağlarında trafiği yapay olarak artırarak IV toplama hızını 100 katına çıkarır.
*   **Fragmentation/ChopChop**: Paket içeriğini bilmeden keystream elde etmeye yarayan gelişmiş WEP saldırılarıdır.

### Handshake & PMKID Yakalama
*   **PMKID Yöntemi**: İstemciye (client) ihtiyaç duymadan, doğrudan AP'den alınan ilk EAPOL karesindeki RSN IE alanından hash elde etmektir.
*   **Weak EAPOL**: Bazen yakalanan handshake eksik veya bozuk olabilir, aircrack-ng bunu analiz eder.

### Aircrack-ng WPA/WPA2 Kırma
*   **Rule-based Saldırılar**: Wordlist'teki kelimelere kurallar (sonuna 123 ekle, leetspeak yap) uygulayarak olasılıkları artırır.
*   **PMK Caching**: Daha önce hesaplanan PMK'leri veritabanında tutarak aynı SSID için kırma işlemini hızlandırır.
*   **GPU Kullanımı**: Aircrack-ng CPU kullanır. Hız için \`hashcat\` tercih edilmelidir.

### WEP Gelişmiş Saldırılar
*   **PTW Saldırısı**: ARP request paketlerini kullanarak çok daha az IV ile (yaklaşık 40.000) WEP şifresini dakikalar içinde kırar.
*   **Korek Attacks**: İstatistiksel kriptanaliz yöntemleri.

### Performans Optimizasyonu
*   **Packet Filtering**: Sadece gerekli paketleri (Beacon, Data, EAPOL) kaydederek disk I/O ve CPU yükünü azaltın.
*   **Multi-interface**: Birden fazla kart ile farklı kanalları aynı anda tarayın.

### Tam Entegre Workflow
1.  **Airodump-ng**: Hedefi belirle ve kaydı başlat.
2.  **Aireplay-ng**: Deauth ile handshake yakala.
3.  **Aircrack-ng**: Yakalanan dosyayı (veya PMKID'yi) kır.
4.  **Hashcat**: Eğer wordlist büyükse .cap dosyasını .hccapx'e çevirip GPU ile kır.

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

**Komut:**
\`\`\`bash
airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w capture wlan0mon
\`\`\`
**Açıklama:**
Sadece 6. kanaldaki ve belirtilen MAC adresine sahip AP'yi dinler, paketleri "capture" adıyla kaydeder.

**Argüman Açıklamaları:**
*   **-c 6**: Kanal 6'yı dinle.
*   **--bssid**: Hedef Access Point MAC adresi.
*   **-w capture**: Dosya adı öneki (capture-01.cap vb. oluşturur).
*   **wlan0mon**: Monitor modundaki arayüz.

**Monitor Mode / Capture Argümanları:**
*   **airmon-ng start wlan0**: wlan0 arayüzünü monitor moda alır (genelde wlan0mon olur).
*   **airmon-ng check kill**: NetworkManager ve wpa_supplicant gibi çakışan süreçleri öldürür.
*   **-c**: Kanal seçimi (tek kanal veya aralık 1-13).
*   **-b / --bssid**: Sadece bu BSSID'ye ait paketleri topla.
*   **--ivs**: Sadece IV'leri kaydeder (WEP için alan tasarrufu).
*   **--write-interval**: Dosyayı diske yazma sıklığı (saniye).
*   **--manufacturer**: AP'nin üreticisini (OUI) gösterir.

**Aireplay-ng Argümanları:**
*   **--deauth 10**: 10 adet deauthentication paketi gönderir (0 = sonsuz).
*   **--fakeauth 0**: Sahte kimlik doğrulama (0 = tek sefer).
*   **--arpreplay**: ARP replay saldırısını başlatır (WEP).
*   **--fragment**: Fragmentation saldırısını dener.
*   **--chopchop**: Chopchop saldırısını dener.
*   **--test**: Injection kalitesini test eder.
*   **-x**: Saniyede gönderilecek paket sayısı (hız ayarı).
*   **-a**: Hedef AP MAC adresi.
*   **-h**: Hedef Client MAC adresi (veya kendi MAC adresiniz).

**Aircrack-ng WPA/WPA2 Argümanları:**
*   **-w wordlist.txt**: Kullanılacak parola listesi.
*   **-b**: Hedef BSSID (capture dosyasında birden fazla ağ varsa).
*   **-l key.txt**: Kırılan şifreyi dosyaya yazar.
*   **-K**: WPA PMKID kırma modunu (wordlist ile) kullanır.
*   **--bssid**: Hedef AP filtresi.
*   **--verify**: Handshake'in sağlam olup olmadığını kontrol eder.

**WEP Cracking Argümanları:**
*   **-z**: PTW saldırısını (daha hızlı) kullanır.
*   **-K**: Korek saldırısını kullanır (eski yöntem).
*   **-f**: Fudge factor (brute force yoğunluğu).
*   **-n**: Key uzunluğu (64/128/256 bit).
*   **-m**: Kırma denemesi için gereken minimum IV sayısı.

## 6. Gerçek Pentest Senaryoları

**Hidden SSID Tespiti:**
\`\`\`bash
airodump-ng -c 11 --bssid 00:11:22:33:44:55 wlan0mon
\`\`\`
Gizli ağa bir istemci bağlandığında veya \`aireplay-ng --deauth\` ile düşürülüp tekrar bağlandığında SSID görünür olur.

**WPA2 Handshake Yakalayarak Parola Kırma:**
\`\`\`bash
aireplay-ng --deauth 5 -a 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF wlan0mon
\`\`\`
Belirli bir istemciyi düşürerek handshake yakalanır, sonra aircrack-ng ile kırılır.

**PMKID Yöntemi ile Parola Kırma:**
\`\`\`bash
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
\`\`\`
(Not: Aircrack-ng paketi dışındaki araçlar gerekebilir, ancak aircrack-ng PMKID kırmayı destekler).

**5 GHz-only Ağlarda Discovery Bypass:**
\`\`\`bash
airodump-ng --band a wlan0mon
\`\`\`
Sadece 5 GHz bandını tarayarak (band a) 2.4 GHz'de görünmeyen kurumsal ağları bulur.

**Rogue AP / Evil Twin Saldırı Analizi:**
\`\`\`bash
airodump-ng --essid "Sirket_Wifi" wlan0mon
\`\`\`
Aynı isme sahip ancak farklı BSSID, farklı kanal veya farklı şifreleme türü kullanan sahte AP'leri tespit eder.

**WEP Zafiyeti Olan Eski IoT Cihazların Testi:**
\`\`\`bash
aireplay-ng --arpreplay -b 00:11:22:33:44:55 -h AA:BB:CC:DD:EE:FF wlan0mon
\`\`\`
Hızlıca IV toplayarak eski cihazların şifresini kırar.

**Airtime Flooding Tespiti:**
\`\`\`bash
airodump-ng wlan0mon
\`\`\`
"Frames" sayacı aşırı hızlı artan bir istasyon varsa, ağı DoS saldırısı ile kilitliyor olabilir.

**MAC Filtering Bypass:**
\`\`\`bash
macchanger -m AA:BB:CC:DD:EE:FF wlan0mon
\`\`\`
Ağa bağlı yetkili bir istemcinin MAC adresini taklit ederek filtreyi aşar.

## 8. Best Practices (Uzman Seviye)

*   **Monitor Mode Kanal Sabitleme:** Handshake yakalarken asla kanal değiştirmeyin (\`-c\`), yoksa paketin yarısını kaçırırsınız.
*   **İdeal Injection Değerleri:** \`--deauth\` gönderirken aşırıya kaçmayın, istemci tamamen bloklanırsa handshake gönderemez. 5-10 paket yeterlidir.
*   **Anten ve Gain:** Uzaktaki hedefler için yüksek dBi anten kullanın, ancak çok yakındaysanız sinyal gürültüsü oluşabilir, TX gücünü düşürün.
*   **WEP IV Threshold:** PTW saldırısı için en az 20.000, standart saldırı için 50.000+ IV hedefleyin.
*   **Handshake Kalitesi:** Aircrack-ng'nin "No valid handshake" hatası almaması için 4 paketin (M1-M4) tamamını yakalamaya çalışın.
*   **PMKID:** İstemcisi olmayan AP'ler için en iyi yöntemdir.
*   **Aireplay Rate:** \`-x\` ile paket hızını sınırlayın, aksi takdirde AP saldırıyı algılayıp sizi görmezden gelebilir (ignore).

## 9. Sık Yapılan Hatalar

*   **Monitor Mode Açmadan Capture Yapmak:** Paketleri göremezsiniz veya injection yapamazsınız.
*   **Yanlış Kanal Üzerinde Deauth Denemek:** AP 6. kanalda ise siz 1. kanalda deauth atamazsınız.
*   **Weak Handshake ile Kırma Denemek:** Eksik handshake ile saatlerce wordlist denemek zaman kaybıdır.
*   **WEP İçin Yetersiz IV:** 500 IV ile WEP kırılmaz.
*   **BSSID ve Kanal Eşleşmesini Gözden Kaçırmak:** Aynı SSID farklı kanallarda yayın yapabilir, doğru BSSID'yi hedefleyin.
*   **Multi-adapter Doğru Yapılandırmamak:** Injection yapan kart ile dinleyen kartın aynı kanalda olması gerekir.
*   **Wordlist Boyutu:** 50GB'lık wordlist'i CPU ile denemek aylar sürer, küçük ve hedef odaklı wordlist kullanın.
*   **AP'den Uzak Konum:** Sinyal -85 dBm'den kötüyse paket kaybı çok olur, handshake bozuk gelir.
*   **PMKID Olmayan AP:** Her AP (özellikle eski olanlar) PMKID göndermez.
`;

const contentEN = `# Aircrack-ng Suite

## 3. Basic Usage

**Activating Monitor Mode:**
Enables capturing all airborne packets by putting the wireless card into monitor mode.
\`\`\`bash
airmon-ng start wlan0
\`\`\`

**Packet Injection with Aireplay-ng:**
Tests if the card can inject packets. Injection is crucial for successful attacks.
\`\`\`bash
aireplay-ng --test wlan0mon
\`\`\`

**Scanning with Airodump-ng:**
Lists all Access Points (AP) and connected clients in 2.4 GHz or 5 GHz bands.
\`\`\`bash
airodump-ng wlan0mon
\`\`\`

**Capturing WPA/WPA2 Handshake:**
Captures the 4-way handshake occurring when a client connects to an AP. Required for password cracking.

**Collecting WEP IVs:**
Collects Initialization Vector (IV) packets needed to crack WEP encryption.

**Basic Channel and BSSID Selection:**
Locks onto a specific channel and AP MAC address (BSSID) for targeted scanning.

**Pcap Output:**
Saves captured packets to a file for analysis or cracking (\`-w filename\`).

**Basic Aircrack-ng WPA2 Cracking:**
Attempts to crack the captured handshake file using a wordlist.

## 4. Advanced Usage

### Advanced Monitor Mode Techniques
*   **Driver Selection**: Using the correct driver for the chipset (ath9k, rtl88xx, mt76) directly affects injection performance.
*   **Injection Optimization**: Some cards inject better on specific channels.
*   **Regulatory Domain**: Commands like \`iw reg set BO\` can increase TX power limits.

### Advanced Airodump-ng Usage
*   **Channel Locking**: Prevent packet loss by stopping channel hopping with \`-c 6\`.
*   **Only-WPA**: Filter only WPA networks with \`--encrypt wpa\`.
*   **Hidden SSID Enumeration**: Airodump-ng automatically resolves the name when a client connects to a Hidden SSID.
*   **Positioning**: Signal strength (PWR) ranges from -100 (far) to -10 (very close). Used for physical location tracking.

### Advanced Aireplay-ng Usage
*   **Deauth Attack**: Forces a client to disconnect and re-associate, allowing handshake capture.
*   **Fake Authentication**: Used in WEP attacks or to associate with an AP without sending data.
*   **ARP Replay**: Artificially increases traffic in WEP networks to speed up IV collection by 100x.
*   **Fragmentation/ChopChop**: Advanced WEP attacks to obtain keystream without knowing packet content.

### Handshake & PMKID Capture
*   **PMKID Method**: Obtaining the hash directly from the RSN IE field in the first EAPOL frame from the AP, without needing a client.
*   **Weak EAPOL**: Aircrack-ng analyzes if the captured handshake is incomplete or corrupted.

### Aircrack-ng WPA/WPA2 Cracking
*   **Rule-based Attacks**: Applies rules (append 123, leetspeak) to words in the wordlist to increase probability.
*   **PMK Caching**: Caches calculated PMKs to speed up cracking for the same SSID.
*   **GPU Usage**: Aircrack-ng uses CPU. For speed, \`hashcat\` should be preferred.

### Advanced WEP Attacks
*   **PTW Attack**: Cracks WEP keys in minutes using ARP request packets with very few IVs (approx 40,000).
*   **Korek Attacks**: Statistical cryptanalysis methods.

### Performance Optimization
*   **Packet Filtering**: Save only necessary packets (Beacon, Data, EAPOL) to reduce disk I/O and CPU load.
*   **Multi-interface**: Scan different channels simultaneously with multiple cards.

### Fully Integrated Workflow
1.  **Airodump-ng**: Identify target and start capture.
2.  **Aireplay-ng**: Capture handshake via Deauth.
3.  **Aircrack-ng**: Crack the captured file (or PMKID).
4.  **Hashcat**: Convert .cap to .hccapx and crack with GPU if wordlist is large.

## 5. Annotated Commands (EXTENDED LIST)

**Command:**
\`\`\`bash
airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w capture wlan0mon
\`\`\`
**Description:**
Listens only on channel 6 and for the AP with the specified MAC, saving packets with prefix "capture".

**Argument Explanations:**
*   **-c 6**: Listen on channel 6.
*   **--bssid**: Target Access Point MAC address.
*   **-w capture**: Filename prefix (creates capture-01.cap etc.).
*   **wlan0mon**: Interface in monitor mode.

**Monitor Mode / Capture Arguments:**
*   **airmon-ng start wlan0**: Puts wlan0 into monitor mode (usually becomes wlan0mon).
*   **airmon-ng check kill**: Kills conflicting processes like NetworkManager and wpa_supplicant.
*   **-c**: Channel selection (single channel or range 1-13).
*   **-b / --bssid**: Collect packets only for this BSSID.
*   **--ivs**: Saves only IVs (space saving for WEP).
*   **--write-interval**: File write frequency (seconds).
*   **--manufacturer**: Shows AP manufacturer (OUI).

**Aireplay-ng Arguments:**
*   **--deauth 10**: Sends 10 deauthentication packets (0 = infinite).
*   **--fakeauth 0**: Fake authentication (0 = once).
*   **--arpreplay**: Starts ARP replay attack (WEP).
*   **--fragment**: Tries fragmentation attack.
*   **--chopchop**: Tries chopchop attack.
*   **--test**: Tests injection quality.
*   **-x**: Packets per second (speed control).
*   **-a**: Target AP MAC address.
*   **-h**: Target Client MAC address (or your own MAC).

**Aircrack-ng WPA/WPA2 Arguments:**
*   **-w wordlist.txt**: Password list to use.
*   **-b**: Target BSSID (if multiple networks in capture).
*   **-l key.txt**: Writes cracked key to file.
*   **-K**: Uses WPA PMKID cracking mode (with wordlist).
*   **--bssid**: Target AP filter.
*   **--verify**: Checks if handshake is valid.

**WEP Cracking Arguments:**
*   **-z**: Uses PTW attack (faster).
*   **-K**: Uses Korek attack (older method).
*   **-f**: Fudge factor (brute force intensity).
*   **-n**: Key length (64/128/256 bit).
*   **-m**: Minimum IV count required to try cracking.

## 6. Real Pentest Scenarios

**Hidden SSID Detection:**
\`\`\`bash
airodump-ng -c 11 --bssid 00:11:22:33:44:55 wlan0mon
\`\`\`
SSID becomes visible when a client connects to the hidden network or re-connects after \`aireplay-ng --deauth\`.

**Cracking Password by Capturing WPA2 Handshake:**
\`\`\`bash
aireplay-ng --deauth 5 -a 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF wlan0mon
\`\`\`
Captures handshake by disconnecting a specific client, then cracks with aircrack-ng.

**Cracking Password via PMKID Method:**
\`\`\`bash
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
\`\`\`
(Note: May require tools outside aircrack-ng package, but aircrack-ng supports PMKID cracking).

**Discovery Bypass on 5 GHz-only Networks:**
\`\`\`bash
airodump-ng --band a wlan0mon
\`\`\`
Scans only the 5 GHz band (band a) to find corporate networks invisible on 2.4 GHz.

**Rogue AP / Evil Twin Attack Analysis:**
\`\`\`bash
airodump-ng --essid "Company_Wifi" wlan0mon
\`\`\`
Detects fake APs with the same name but different BSSID, channel, or encryption.

**Testing Old IoT Devices with WEP Vulnerability:**
\`\`\`bash
aireplay-ng --arpreplay -b 00:11:22:33:44:55 -h AA:BB:CC:DD:EE:FF wlan0mon
\`\`\`
Quickly collects IVs to crack passwords of old devices.

**Airtime Flooding Detection:**
\`\`\`bash
airodump-ng wlan0mon
\`\`\`
If "Frames" count for a station increases excessively fast, it might be jamming the network with DoS.

**MAC Filtering Bypass:**
\`\`\`bash
macchanger -m AA:BB:CC:DD:EE:FF wlan0mon
\`\`\`
Bypasses filter by mimicking the MAC address of an authorized client.

## 8. Best Practices (Expert Level)

*   **Monitor Mode Channel Locking:** Never change channels (\`-c\`) while capturing handshake, or you'll miss half the packets.
*   **Ideal Injection Values:** Don't overdo \`--deauth\`; if the client is fully blocked, it can't send a handshake. 5-10 packets are enough.
*   **Antenna and Gain:** Use high dBi antennas for distant targets, but lower TX power if very close to avoid signal noise.
*   **WEP IV Threshold:** Aim for at least 20,000 IVs for PTW, 50,000+ for standard attacks.
*   **Handshake Quality:** Try to capture all 4 packets (M1-M4) to avoid "No valid handshake" errors in Aircrack-ng.
*   **PMKID:** Best method for APs with no clients.
*   **Aireplay Rate:** Limit packet rate with \`-x\`, otherwise the AP might detect the attack and ignore you.

## 9. Common Mistakes

*   **Capturing Without Monitor Mode:** You won't see packets or be able to inject.
*   **Deauth on Wrong Channel:** You can't deauth on channel 1 if the AP is on channel 6.
*   **Trying to Crack with Weak Handshake:** Wasting time with wordlists on incomplete handshakes.
*   **Insufficient IVs for WEP:** WEP won't crack with 500 IVs.
*   **Missing BSSID and Channel Match:** Same SSID can broadcast on different channels; target the correct BSSID.
*   **Misconfigured Multi-adapter:** Injection card and listening card must be on the same channel.
*   **Wordlist Size:** Trying a 50GB wordlist on CPU takes months; use small, targeted wordlists.
*   **Far from AP:** If signal is worse than -85 dBm, packet loss is high, handshake arrives corrupted.
*   **Non-PMKID AP:** Not every AP (especially older ones) sends PMKID.
`;

async function addAircrack() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Aircrack-ng cheatsheet...');

        // 1. Find or create the category
        let category = await Category.findOne({ 'name.en': 'Wireless Attacks' });
        if (!category) {
            console.log('Category "Wireless Attacks" not found, creating...');
            category = await Category.create({
                name: { tr: 'Kablosuz Saldırılar', en: 'Wireless Attacks' },
                description: { tr: 'Wi-Fi ve kablosuz ağ güvenliği araçları', en: 'Wi-Fi and wireless network security tools' },
                slug: 'wireless-attacks',
                icon: 'Wifi'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Aircrack-ng Cheat Sheet',
                en: 'Aircrack-ng Cheat Sheet'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['aircrack-ng', 'wifi', 'wireless', 'wpa', 'wep', 'handshake', 'cracking']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Aircrack-ng Cheat Sheet' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Aircrack-ng cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addAircrack();
