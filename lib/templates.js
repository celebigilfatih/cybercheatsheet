export const TEMPLATE_OPTIONS = [
  { value: 'comprehensive', label: 'Kapsamlı Şablon (Genel)' },
  { value: 'web-pentest', label: 'Web Pentest' },
  { value: 'linux-network', label: 'Linux / Network' },
  { value: 'kubernetes', label: 'Kubernetes' },
  { value: 'git-gitops', label: 'Git / GitOps' }
  ,{ value: 'nmap', label: 'Nmap (Genişletilmiş)' }
]

const comprehensive = `# [Konunuz/Aracınız] Kapsamlı Cheatsheet

[toc]

## Temel komutlar ve sözdizimi

Açıklama: Bu bölüm, en temel kullanımı ve sözdizimini net şekilde özetler.

### Hızlı Başlangıç
- Amaç: En sık kullanılan komutların minimum örnekle gösterilmesi.
- Örnek:
\`\`\`bash
arac --help
arac init --name proje
arac run --verbose
\`\`\`

### Sözdizimi Özeti Tablosu
| Komut | Açıklama | Örnek |
|------|----------|-------|
| \`arac init\` | Yeni proje başlatır | \`arac init --name proje\` |
| \`arac build\` | Derleme yapar | \`arac build --prod\` |
| \`arac run\` | Çalıştırır | \`arac run --port 8080\` |

### Yapılandırma Dosyaları
- \`config.yaml\`: Temel ayarlar
- Örnek:
\`\`\`yaml
port: 8080
logLevel: info
features:
  - gfm
  - mermaid
\`\`\`

## Sık kullanılan örnekler ve kullanım durumları

Açıklama: Gerçek kullanım senaryoları ve sık başvurulan kombinasyonlar.

### Örnek 1: Standart Çalıştırma
Adımlar:
1. Kurulumu doğrulayın: \`arac --version\`
2. Varsayılan yapılandırmayla çalıştırın: \`arac run\`
3. Sonuçları kontrol edin: \`http://localhost:8080\`

### Örnek 2: Üretim Modu
\`\`\`bash
arac build --prod
arac run --port 8080 --env production
\`\`\`

### Örnek 3: Entegrasyon Akışı (Diyagram)
\`\`\`mermaid
flowchart LR
  A[Kaynak] --> B[Önişleme]
  B --> C{Doğrulama}
  C -->|Geçti| D[Derleme]
  C -->|Hata| E[Log İncele]
  D --> F[Dağıtım]
\`\`\`

## İleri düzey teknikler ve ipuçları

Açıklama: Performans, güvenlik ve otomasyon odaklı ileri konular.

### Performans İpuçları
- Önbellekleme: \`--cache\` bayrağını etkinleştirin
- Paralel işlemler: \`--parallel\` ile job sayısını artırın

### Güvenlik Sertleştirme
- Min. yetki: Konfigürasyonda sadece gerekli izinleri tanımlayın
- Girdi doğrulama: Parametre kontrollerini zorunlu yapın

### Otomasyon ve CI/CD
- Örnek \`.ci.yml\`:
\`\`\`yaml
steps:
  - run: npm ci
  - run: npm test
  - run: npm run build
  - run: npm run deploy
\`\`\`

## Sorun giderme rehberi ve hata çözümleri

Açıklama: Yaygın hatalar, semptomlar ve çözüm adımları.

### Sık Hatalar Tablosu
| Hata/Belirti | Olası Neden | Çözüm |
|--------------|-------------|-------|
| Port kullanımda | Sunucu zaten çalışıyor | Süreci durdurun veya port değiştirin |
| Yetki hatası | Yanlış izinler | IAM/kullanıcı izinlerini gözden geçirin |
| Bağımlılık çakışması | Paket sürüm uyumsuzluğu | \`npm ls\` ile inceleyin, gerekirse \`npm dedupe\` |

### Adım Adım Teşhis
1. Logları kontrol edin: \`arac logs\`
2. Konfigürasyonu doğrulayın: \`arac config validate\`
3. Gerekirse güvenli modda çalıştırın: \`arac run --safe-mode\`

### Sorun Akışı (Diyagram)
\`\`\`mermaid
graph TD
  X[Belirti] --> Y{Kritik mi?}
  Y -->|Evet| Z[Rollback]
  Y -->|Hayır| W[Log Analizi]
  W --> K[Kalıcı Çözüm]
\`\`\`

## Bakım ve Güncelleme

### Trendleri Yansıtma
- GFM ve mermaid ile zengin içerik
- Otomatik TOC ile hızlı gezinme
- Versiyonlama ve “değişiklik günlüğü” ekleme

### Düzenli Güncelleme Mekanizması
- Aylık gözden geçirme: “Yeni sürüm notları” ekleyin
- Otomatik link doğrulama: Kırık linkleri raporlayın
- Depolama: PDF/MD çıktıları arşivleyin

### Versiyon Kontrol Sistemi
- SemVer: \`v1.2.0\` formatı
- Git dal modeli:
  - \`main\`: kararlı
  - \`feature/<konu>\`: yeni içerik
  - \`docs/<guncelleme>\`: dokümantasyon değişiklikleri
- Sürüm notları: \`CHANGELOG.md\` bölümü ekleyin

## Kullanıcı Dostu Format

- İçindekiler için \`[toc]\` kullanın
- Bölümleri aynı başlıklarla adlandırarak renk kodlamayı etkinleştirin
- Anahtar Kelime İndeksi:
  - Örnek:
    - \`#anahtar-kelimeler\`: [komut], [performans], [güvenlik], [otomasyon], [hata]
`

const webPentest = `# Web Pentest Cheatsheet

[toc]

## Temel komutlar ve sözdizimi

### Hızlı Başlangıç
\`\`\`bash
nmap -sC -sV -oN scan.txt target
nikto -h http://target
gobuster dir -u http://target -w wordlist.txt -x php,txt
\`\`\`

### Login Brute Force (wfuzz)
\`\`\`bash
wfuzz -u http://target/login -d "user=FUZZ&pass=FUZZ" -w users.txt -w pass.txt --hc 302
\`\`\`

### SQL Injection (sqlmap)
\`\`\`bash
sqlmap -u "http://target/item?id=1" --batch --risk=2 --level=2 --dump
\`\`\`

## Sık kullanılan örnekler ve kullanım durumları

### WordPress Keşif (wpscan)
\`\`\`bash
wpscan --url https://target --enumerate u,plugins
\`\`\`

### Akış Diyagramı
\`\`\`mermaid
flowchart LR
  Recon[Keşif] --> Enum[Enum]
  Enum --> Vuln[Zafiyet Analizi]
  Vuln --> Exploit[Sömürü]
\`\`\`

## İleri düzey teknikler ve ipuçları
- Proxy zinciri (Burp <-> ffuf)
- Rate limit bypass teknikleri
- WAF fingerprint + bypass stratejileri

## Sorun giderme rehberi ve hata çözümleri
- Yanıt 403: WAF tetikleniyor olabilir; user-agent ve yolları çeşitlendirin
- Login brute force engelleniyor: delay ve randomization ekleyin
`

const linuxNetwork = `# Linux / Network Cheatsheet

[toc]

## Temel komutlar ve sözdizimi
\`\`\`bash
ip a
ss -tulpn
iptables -L -n
tcpdump -i eth0 -nn port 80
\`\`\`

## Sık kullanılan örnekler ve kullanım durumları
\`\`\`bash
curl -I http://localhost:8080
dig +short example.com
nc -vz host 22
\`\`\`

### Ağ Akışı Diyagramı
\`\`\`mermaid
sequenceDiagram
  Client->>Server: HTTP GET /
  Server-->>Client: 200 OK
\`\`\`

## İleri düzey teknikler ve ipuçları
- iptables NAT ve port yönlendirme
- systemd-networkd ile ağ profilleri

## Sorun giderme rehberi ve hata çözümleri
- Port kullanımda: \`lsof -i :PORT\` ve süreç sonlandırma
`

const kubernetes = `# Kubernetes Cheatsheet

[toc]

## Temel komutlar ve sözdizimi
\`\`\`bash
kubectl get pods -A
kubectl describe pod <name>
kubectl logs -f <pod>
\`\`\`

## Sık kullanılan örnekler ve kullanım durumları
\`\`\`bash
kubectl apply -f deploy.yaml
kubectl rollout status deploy/<name>
\`\`\`

### Cluster Diyagramı
\`\`\`mermaid
graph TD
  API[API Server] --> Ctrl[Controller Manager]
  API --> Sched[Scheduler]
  API --> ETCD[(etcd)]
  API --> Kubelet[Kubelet]
\`\`\`

## İleri düzey teknikler ve ipuçları
- Context yönetimi ve kubeconfig çoklu dosya
- RBAC en iyi uygulamalar

## Sorun giderme rehberi ve hata çözümleri
- CrashLoopBackOff: \`kubectl describe\` ve \`kubectl logs\` ile inceleyin
`

const gitGitops = `# Git / GitOps Cheatsheet

[toc]

## Temel komutlar ve sözdizimi
\`\`\`bash
git init
git add -A && git commit -m "init"
git push origin main
\`\`\`

## Sık kullanılan örnekler ve kullanım durumları
\`\`\`bash
git switch -c feature/awesome
git tag v1.2.0
\`\`\`

### Pipeline Diyagramı
\`\`\`mermaid
flowchart LR
  Dev[Developer] --> Repo[Git Repo]
  Repo --> CI[CI]
  CI --> CD[CD]
  CD --> Prod[Production]
\`\`\`

## İleri düzey teknikler ve ipuçları
- SemVer ve conventional commits
- Protected branches ve required reviews

## Sorun giderme rehberi ve hata çözümleri
- Merge conflict: \`git rebase\` ile temiz akış
`

// Nmap (Genişletilmiş) — Uygulamalı eğitim ve örnekler
const nmap = `
[toc]

## Temel komutlar ve sözdizimi

Nmap, ağ keşfi ve güvenlik denetimleri için kullanılan güçlü bir araçtır. Aşağıdaki temel komutlar ile TCP, UDP, servis keşfi, OS tespiti ve çıktı yönetimi yapılır.

\`\`\`bash
# Hızlı tarama: En yaygın 1000 TCP portu
nmap 192.168.1.10

# En popüler portlar (ilk 100): hızlı keşif
nmap --top-ports 100 192.168.1.10

# TCP SYN (stealth) taraması
nmap -sS 192.168.1.10

# TCP connect taraması (firewall ve IDS daha fazla iz bırakabilir)
nmap -sT 192.168.1.10

# UDP servis taraması (yavaş olabilir, -T ve --max-retries ile ayarlayın)
nmap -sU 192.168.1.10

# Belirli port aralığı
nmap -p 1-65535 192.168.1.10
nmap -p 22,80,443 192.168.1.10

# Servis versiyon tespiti ve script taraması
nmap -sV -sC 192.168.1.10

# Agresif tarama: OS tespiti, traceroute, scriptler ve versiyon tespiti
nmap -A 192.168.1.10

# Ping taraması (host keşfi) — servislere dokunmadan
nmap -sn 192.168.1.0/24

# Ping atlaması: güvenlik duvarını bypass etmeye çalışırken kullanılır
nmap -Pn 192.168.1.10

# IPv6 taraması
nmap -6 fe80::1ff:fe23:4567:890a

# Çıktıları kaydetme (üç format birden)
nmap -oA scans/lan-scan 192.168.1.0/24

# Detay seviyeleri
nmap -v 192.168.1.10      # daha fazla bilgi
nmap -vv 192.168.1.10     # çok ayrıntılı
\`\`\`

Host keşfi (ping türleri) ve port probu seçenekleri:

\`\`\`bash
# ICMP Echo (PE), Timestamp (PP), Netmask (PM)
nmap -PE -PP -PM 192.168.1.0/24

# TCP SYN ping (PS) ve ACK ping (PA) belirli portlar ile
nmap -PS80,443 -PA80,443 192.168.1.0/24

# UDP ping (PU)
nmap -PU53,67 192.168.1.0/24

# ARP ping (PR) — yerel ağlarda en etkili
nmap -PR 192.168.1.0/24
\`\`\`

## Sık kullanılan örnekler ve kullanım durumları

Aşağıdaki örnekler günlük pentest ve envanter çalışmalarında sık kullanılır.

\`\`\`bash
# CIDR aralığı tarama
nmap -sS -Pn -p 22,80,443 10.10.10.0/24

# Liste dosyasından tarama
nmap -iL targets.txt -sV -oA scans/targets

# Belirli IP’leri hariç tutma
nmap 10.0.0.0/24 --exclude 10.0.0.1,10.0.0.2
nmap -iL targets.txt --excludefile exclude.txt

# Servis başlıkları ve TLS/SSL şifre takımları
nmap -sV --script http-title,ssl-enum-ciphers -p 80,443 192.168.1.0/24

# SMB ve Windows hedeflerinde temel keşif
nmap -sV --script smb-os-discovery,smb-enum-shares -p 445 192.168.1.0/24

# SSH anahtar ve banner bilgisi
nmap -sV --script ssh-hostkey,banner -p 22 192.168.1.0/24

# FTP anonim erişim kontrolü
nmap -sV --script ftp-anon -p 21 192.168.1.0/24

# DNS brute force ve transfer denemesi
nmap --script dns-brute,dns-zone-transfer -p 53 example.com

# SNMP info
nmap -sU -p 161 --script snmp-info 192.168.1.0/24

# NTP bilgi sızıntısı
nmap -sU -p 123 --script ntp-info 192.168.1.0/24

# RDP ve VNC kontrolü
nmap -sV -p 3389,5900 --script vnc-info 192.168.1.0/24

# Redis ve Memcached
nmap -sV -p 6379 --script redis-info 192.168.1.0/24
nmap -sV -p 11211 --script memcached-info 192.168.1.0/24

# MQTT ve AMQP kontrolü
nmap -sV -p 1883,5672 --script mqtt-subscribe 192.168.1.0/24

# Web servislerde dizin keşfi (lightweight)
nmap --script http-enum -p 80,443 192.168.1.0/24

# Çıktıların XML, GNMAP ve normal formatta kaydı
nmap -oA scans/web-scan -sV -p 80,443 192.168.1.0/24
\`\`\`

Mermaid diyagramı: örnek tarama akışı.

\`\`\`mermaid
flowchart LR
  A[Hedef Listesi] --> B{Host Keşfi}
  B -->|Canlı| C[Port Tarama]
  B -->|Kapalı/Filtreli| D[Logla ve geç]
  C --> E[Servis/Versiyon Tespiti]
  E --> F[NSE Scriptleri]
  F --> G[Çıktı Kaydı -oA]
\`\`\`

## İleri düzey teknikler ve ipuçları

Performans, gizlilik ve atlatma teknikleri.

\`\`\`bash
# Zamanlama ve hız kontrolü
nmap -T4 --min-rate 200 --max-retries 2 192.168.1.0/24
nmap --scan-delay 10ms --max-retries 1 192.168.1.10

# Paket boyutu ve fragment
nmap -f --mtu 24 192.168.1.10

# Decoy (sahte kaynaklar) ve kaynak portu
nmap -D RND:10 -g 53 -sS 192.168.1.10

# MAC spoof ve özel arayüz seçimi
nmap --spoof-mac Cisco -e eth0 192.168.1.10

# Rastgele host sıralaması ve yeniden denemeler
nmap --randomize-hosts --max-retries 1 -T5 192.168.1.0/24

# Script kategorileri: safe, default, vuln, intrusive
nmap --script "default,safe" -sV 192.168.1.10
nmap --script vuln 192.168.1.10

# Script argümanları ile örnek (http-form-brute)
nmap --script http-form-brute --script-args 'http-form-brute.path=/login' -p 80 192.168.1.10

# OS tespiti için koşullar: en az bir açık ve bir kapalı port olmalı
nmap -O 192.168.1.10

# IPv6 keşfi ve port taraması
nmap -6 -sV -p 22,80,443 2001:db8::10

# Traceroute ve hop analizi
nmap --traceroute -A 192.168.1.10

# Çıktının XSLT dönüştürülmesi (eski yöntem; harici xslt ile)
nmap -oX scans/out.xml 192.168.1.10
# xsltproc scans/out.xml -o scans/out.html
\`\`\`

Mermaid sıralı diyagram: NSE script yürütme akışı.

\`\`\`mermaid
sequenceDiagram
  participant N as Nmap
  participant H as Host
  N->>H: SYN/UDP Probe
  H-->>N: SYN-ACK/ICMP/No Response
  N->>H: Version Probe
  N->>H: NSE Script (default/safe)
  N-->>N: Sonuçları topla ve -oA kaydet
\`\`\`

## Sorun giderme rehberi ve hata çözümleri

Sık karşılaşılan durumlar ve çözümler.

\`\`\`bash
# Kapalı vs. filtreli farkı
# Kapalı (closed): RST döner; Filtreli (filtered): firewall/ACL engeller, cevap yok

# -Pn ile ping atlaması (canlı hostu hizmette test eder)
nmap -Pn 192.168.1.10

# OS tespiti başarısızsa: port kombinasyonunu genişletin
nmap -O -p 1-1024,3389,5900,8080 192.168.1.10

# UDP taraması yavaşsa: hız ayarları
nmap -sU --min-rate 100 --max-retries 1 --top-ports 50 192.168.1.10

# NIC ve gateway sorunları: arayüzü ve geçidi belirtin
nmap -e eth0 --source-port 53 192.168.1.10

# Hatalı sonuçlar: IDS/IPS etkisi; -f, -D, zamanlama ile dengeleyin
nmap -f -D RND:5 -T3 192.168.1.10

# Çıktı analizi: GNMAP ile grep
grep 'Ports:' scans/lan-scan.gnmap | awk -F":" '{print $1,$2}'

# Hedef erişilemezse: ARP/ICMP ping türlerini artırın
nmap -PR -PE -PP -PS80,443 192.168.1.0/24
\`\`\`

### İpuçları
- OS tespiti için en az bir açık ve bir kapalı port gerektiğini unutmayın.
- UDP taramada hız ve yeniden deneme sayıları kritik; filtreli görünümler normaldir.
- Çıktıları her zaman \`-oA\` ile kaydedin; XML/grepable formatlar raporlamayı kolaylaştırır.
- Script kullanırken \`default,safe\` ile başlayın; \`vuln\` ve \`intrusive\` kategorileri dikkatle kullanın.

### Kısa Özet
- Keşif: \`nmap -sn\`, \`-PR\`, \`-PE/PS/PA/PU\`
- Servis: \`-sV\`, \`-sC\`, \`-A\`
- Performans: \`-T\`, \`--min-rate\`, \`--max-retries\`, \`--scan-delay\`
- Evasion: \`-f\`, \`-D\`, \`--spoof-mac\`, \`-g\`
- Çıktı: \`-oA\` (xml/gnmap/normal)

## Ek Nmap Örnekleri

### Hızlı keşif varyasyonları
- \`nmap -sn 10.10.0.0/16 --exclude 10.10.10.1,10.10.20.1\`
- \`nmap -sn --min-rate 3000 --max-retries 1 --defeat-icmp-ratelimit 192.168.1.0/24\`
- \`nmap -sn --traceroute -PE -PS80,443 172.16.0.0/16\`

### Port kapsamını hassas ayarla
- \`nmap -p- --min-rate 2000 --max-retries 1 --top-ports 200 10.0.0.5\`
- \`nmap -p1-65535 --exclude-ports 5900,6000-6060 -T4 10.0.0.5\`
- \`nmap --top-ports 50 --open 10.0.0.0/24\`

### TCP tarama teknikleri
- \`nmap -sS -p80,443,22 -T4 --min-rate 1500 --defeat-rst-ratelimit 10.0.0.5\`
- \`nmap -sA -p80,443 --reason 10.0.0.5\` (stateful firewall tespiti)
- \`nmap -sN -p80,443 10.0.0.5\` (NULL scan, filtre/kapalı ayrımı)

### UDP odaklı örnekler
- \`nmap -sU -p53,123,161 --min-rate 500 --max-retries 2 10.0.0.5\`
- \`nmap -sU --top-ports 200 --open 10.0.0.0/24\`
- \`nmap -sU -p161 --script snmp-info 10.0.0.5\`

### IPv6 taraması
- \`nmap -6 -sn fe80::/64\`
- \`nmap -6 -sS -p80,443 2001:db8::10\`
- \`nmap -6 --traceroute 2001:db8::/32\`

### Servis ve sürüm tespiti
- \`nmap -sV --version-intensity 9 -p80,443,22 10.0.0.5\`
- \`nmap -A -p80,443 10.0.0.5\` (OS + servis + script + traceroute)
- \`nmap -sC -p- 10.0.0.5\` (varsayılan script seti ile)

### HTTP ve TLS odaklı NSE
- \`nmap -p443 --script ssl-cert,ssl-enum-ciphers 10.0.0.5\`
- \`nmap -p80,443 --script http-title,http-enum 10.0.0.5\`
- \`nmap --script http-headers --script-args http.useragent='Mozilla/5.0 (Pentest)' -p80 10.0.0.5\`

### SMB ve Windows hedefleri
- \`nmap -p445 --script smb-os-discovery,smb-enum-shares 10.0.0.5\`
- \`nmap -p445 --script smb-vuln-ms17-010 10.0.0.0/24\`
- \`nmap -p135,139,445 --script msrpc-enum,smb2-capabilities 10.0.0.5\`

### DNS ve e-posta servisleri
- \`nmap -p53 --script dns-nsid,dns-cache-snoop 10.0.0.5\`
- \`nmap -p25,110,143 --script smtp-commands,imap-capabilities,pop3-capabilities 10.0.0.5\`

### Evasion ve iz bırakmama
- \`nmap -f -p80,443 --data-length 25 --mtu 24 10.0.0.5\` (fragment + padding + MTU)
- \`nmap -D 192.0.2.10,198.51.100.3,203.0.113.5 -p80 10.0.0.5\` (decoy)
- \`nmap --spoof-mac Apple -g 53 -p80 10.0.0.5\` (MAC spoof + source port)

### Zamanlama ve paralellik
- \`nmap -T3 --min-rate 800 --max-rate 2000 --scan-delay 10ms 10.0.0.0/24\`
- \`nmap --min-parallelism 10 --max-parallelism 100 -p- 10.0.0.5\`
- \`nmap --max-retries 2 --host-timeout 60s 10.0.0.0/24\`

### Script argümanlarıyla derinlemesine
- \`nmap --script http-passwd --script-args http-passwd.root=/protected 10.0.0.5\`
- \`nmap -p21 --script ftp-anon --script-args ftp-anon.maxlist=200 10.0.0.5\`
- \`nmap -p80 --script http-form-brute --script-args 'http-form-brute.path=/login' 10.0.0.5\`

### Çıktı, karşılaştırma ve rapor
- \`nmap -oA scans/full-10.0.0.5 -p- 10.0.0.5\`
- \`ndiff scans/full-10.0.0.5.xml scans/full-10.0.0.5-later.xml\`
- \`xsltproc /usr/share/nmap/nmap.xsl scans/full-10.0.0.5.xml -o full-10.0.0.5.html\`

### Gelişmiş keşif ve traceroute
- \`nmap --packet-trace --reason -p80,443 10.0.0.5\` (paket izleme + neden)
- \`nmap --resolve-all -sn 10.0.0.0/24\` (çoklu hostname çözümlemesi)
- \`nmap -sn --traceroute 10.0.0.5\`

### SCTP ve diğer protokoller
- \`nmap -sY -p3868 10.0.0.5\` (SCTP INIT scan, Diameter)
- \`nmap -sO 10.0.0.5\` (IP protokol taraması)

### Kaynak port, özel bayraklar
- \`nmap -sS -p80 --source-port 53 10.0.0.5\`
- \`nmap -sX -p80 10.0.0.5\` (Xmas scan)

### Kısa İpuçları
- \`-sA\` firewall durumu için idealdir; kapalı/açık ayrımına bakma.
- UDP’de \`--max-retries\` ve \`--min-rate\` ile hız/tekrar dengesini ayarla.
- \`-oA\` üçlü çıktıyla XML ve grepable formatı birlikte kaydet.
- NSE’de önce \`default,safe\`; sonra hedefe uygun \`vuln\`/\`intrusive\`ye geç.
`

export function getTemplate(name) {
  switch (name) {
    case 'comprehensive':
      return comprehensive
    case 'web-pentest':
      return webPentest
    case 'linux-network':
      return linuxNetwork
    case 'kubernetes':
      return kubernetes
    case 'git-gitops':
      return gitGitops
    case 'nmap':
      return nmap
    default:
      return comprehensive
  }
}