/* CLI Seeder for CyberSec Cheatsheet
 * Loads .env.local, connects MongoDB, upserts categories & cheatsheets.
 */
import fs from 'fs'
import path from 'path'
import mongoose from 'mongoose'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Load .env.local if present
const envPath = path.join(__dirname, '..', '.env.local')
if (fs.existsSync(envPath)) {
  const lines = fs.readFileSync(envPath, 'utf-8').split(/\r?\n/)
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const idx = trimmed.indexOf('=')
    if (idx === -1) continue
    const key = trimmed.slice(0, idx).trim()
    const val = trimmed.slice(idx + 1).trim()
    if (key && !(key in process.env)) process.env[key] = val
  }
}

const uri = process.env.MONGODB_URI
if (!uri) {
  console.error('Missing MONGODB_URI env variable. Set it in .env.local or environment.')
  process.exit(1)
}

const CategorySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true, trim: true },
    description: { type: String, default: '' }
  },
  { timestamps: true }
)

const CheatsheetSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: '' },
    tags: { type: [String], default: [] },
    links: { type: [String], default: [] },
    category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true }
  },
  { timestamps: true }
)

CheatsheetSchema.index({ title: 'text', description: 'text', tags: 'text' })

const Category = mongoose.models.Category || mongoose.model('Category', CategorySchema)
const Cheatsheet = mongoose.models.Cheatsheet || mongoose.model('Cheatsheet', CheatsheetSchema)

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
    description: `# Nmap Cheatsheet\n\nTemel tarama:\n\n\`\`\`\nnmap 192.168.1.10\nnmap 192.168.1.0/24\n\`\`\`\n\nPort aralığı ve top-ports:\n\n\`\`\`\nnmap -p 1-65535 192.168.1.10\nnmap --top-ports 1000 192.168.1.10\n\`\`\`\n\nServis/versiyon ve OS detection:\n\n\`\`\`\nnmap -sV 192.168.1.10\nnmap -O 192.168.1.10\n\`\`\`\n\nNSE örnekleri:\n\n\`\`\`\nnmap --script vuln 192.168.1.10\n\`\`\`\n`
  },
  { title: 'Masscan Cheatsheet', category: 'Network Scanning', tags: ['masscan','scan','ports'], links: ['https://github.com/robertdavidgraham/masscan'], description: `# Masscan Cheatsheet\n\n\`\`\`\nmasscan 192.168.1.0/24 -p80,443 --rate=10000\n\`\`\`\n` },
  { title: 'Gobuster Cheatsheet', category: 'Directory Bruteforce', tags: ['gobuster','dir','dns'], links: ['https://github.com/OJ/gobuster'], description: `# Gobuster\n\n\`\`\`\ngobuster dir -u http://target -w wordlist.txt -x php,txt,html -t 50\n\`\`\`\n` },
  { title: 'FFUF Cheatsheet', category: 'Web Enumeration', tags: ['ffuf','fuzz','web'], links: ['https://github.com/ffuf/ffuf'], description: `# FFUF\n\n\`\`\`\nffuf -u http://target/FUZZ -w /path/wordlist.txt -mc 200\n\`\`\`\n` },
  { title: 'Dirsearch Cheatsheet', category: 'Directory Bruteforce', tags: ['dirsearch','dir','web'], links: ['https://github.com/maurosoria/dirsearch'], description: `# Dirsearch\n\n\`\`\`\ndirsearch -u http://target -e php,txt,html -w wordlist.txt -t 50\n\`\`\`\n` },
  { title: 'Nikto Cheatsheet', category: 'Web Enumeration', tags: ['nikto','web','scan'], links: ['https://github.com/sullo/nikto'], description: `# Nikto\n\n\`\`\`\nnikto -h http://target\n\`\`\`\n` },
  { title: 'SQLMap Cheatsheet', category: 'SQL Injection', tags: ['sqlmap','sqli','db'], links: ['https://sqlmap.org/'], description: `# SQLMap\n\n\`\`\`\nsqlmap -u 'http://target/item.php?id=1' --batch\n\`\`\`\n` },
  { title: 'Hydra Cheatsheet', category: 'Password Cracking', tags: ['hydra','bruteforce','ssh'], links: ['https://github.com/vanhauser-thc/thc-hydra'], description: `# Hydra\n\n\`\`\`\nhydra -l root -P passwords.txt ssh://192.168.1.10\n\`\`\`\n` },
  { title: 'Netcat Cheatsheet', category: 'Network Utilities', tags: ['nc','netcat','reverse-shell'], links: ['http://nc110.sourceforge.net/'], description: `# Netcat\n\n\`\`\`\nnc -lvnp 4444\n\`\`\`\n` },
  { title: 'Tcpdump Cheatsheet', category: 'Network Utilities', tags: ['tcpdump','pcap','filter'], links: ['https://www.tcpdump.org/manpages/tcpdump.1.html'], description: `# Tcpdump\n\n\`\`\`\ntcpdump -i eth0 'port 80'\n\`\`\`\n` },
  { title: 'Amass Cheatsheet', category: 'Subdomain Discovery', tags: ['amass','dns','enum'], links: ['https://github.com/owasp-amass/amass'], description: `# Amass\n\n\`\`\`\namass enum -d example.com\n\`\`\`\n` },
  { title: 'John the Ripper Cheatsheet', category: 'Password Cracking', tags: ['john','hash','cracking'], links: ['https://www.openwall.com/john/'], description: `# John\n\n\`\`\`\njohn hashes.txt --format=raw-md5\n\`\`\`\n` },
  { title: 'Hashcat Cheatsheet', category: 'Password Cracking', tags: ['hashcat','gpu','cracking'], links: ['https://hashcat.net/wiki/'], description: `# Hashcat\n\n\`\`\`\nhashcat -m 0 -a 0 hashes.txt /path/rockyou.txt\n\`\`\`\n` },
  { title: 'Metasploit Cheatsheet', category: 'Exploitation', tags: ['metasploit','msf','exploit'], links: ['https://docs.metasploit.com/'], description: `# Metasploit\n\n\`\`\`\nmsfconsole\n\`\`\`\n` },
  { title: 'WPScan Cheatsheet', category: 'Web Enumeration', tags: ['wpscan','wordpress','enum','vuln'], links: ['https://wpscan.com/', 'https://github.com/wpscanteam/wpscan'], description: `# WPScan\n\n\`\`\`\nwpscan --url https://target\n\`\`\`\n` },
  { title: 'Wfuzz Cheatsheet', category: 'Web Enumeration', tags: ['wfuzz','fuzz','web'], links: ['https://github.com/xmendez/wfuzz'], description: `# Wfuzz\n\n\`\`\`\nwfuzz -u http://target/FUZZ -w /path/wordlist.txt --hc 404\n\`\`\`\n` },
  { title: 'Sublist3r Cheatsheet', category: 'Subdomain Discovery', tags: ['sublist3r','subdomains'], links: ['https://github.com/aboul3la/Sublist3r'], description: `# Sublist3r\n\n\`\`\`\nsublist3r -d example.com -o subs.txt\n\`\`\`\n` },
  { title: 'TShark Cheatsheet', category: 'Network Utilities', tags: ['tshark','wireshark','cli'], links: ['https://www.wireshark.org/docs/man-pages/tshark.html'], description: `# TShark\n\n\`\`\`\ntshark -i eth0\n\`\`\`\n` },
  { title: 'Aircrack-ng Cheatsheet', category: 'Wireless', tags: ['aircrack-ng','wifi','wpa','monitor'], links: ['https://www.aircrack-ng.org/documentation.html'], description: `# Aircrack-ng\n\n\`\`\`\nairmon-ng start wlan0\nairodump-ng wlan0mon\n\`\`\`\n` },
  { title: 'Ncrack Cheatsheet', category: 'Password Cracking', tags: ['ncrack','bruteforce','network'], links: ['https://nmap.org/ncrack/'], description: `# Ncrack\n\n\`\`\`\nncrack -v -u admin -P passwords.txt ssh://192.168.1.10\n\`\`\`\n` },
  { title: 'Burp Suite Cheatsheet', category: 'Web Enumeration', tags: ['burp','proxy','intruder','repeater'], links: ['https://portswigger.net/burp/documentation'], description: `# Burp Suite\n\nProxy 127.0.0.1:8080\nIntercept ON/OFF\n` },
  { title: 'OWASP ZAP Cheatsheet', category: 'Web Enumeration', tags: ['zap','proxy','active-scan'], links: ['https://www.zaproxy.org/docs/'], description: `# ZAP\n\nQuick Start > Automated Scan\n` },
  { title: 'theHarvester Cheatsheet', category: 'Web Enumeration', tags: ['theharvester','osint','emails','hosts'], links: ['https://github.com/laramies/theHarvester'], description: `# theHarvester\n\n\`\`\`\ntheHarvester -d example.com -b google\n\`\`\`\n` },
  { title: 'dnsenum Cheatsheet', category: 'Subdomain Discovery', tags: ['dnsenum','dns','enum'], links: ['https://github.com/fwaeytens/dnsenum'], description: `# dnsenum\n\n\`\`\`\ndnsenum example.com\n\`\`\`\n` },
  { title: 'recon-ng Cheatsheet', category: 'Web Enumeration', tags: ['recon-ng','framework','osint'], links: ['https://github.com/lanmaster53/recon-ng'], description: `# recon-ng\n\nworkspaces add target\n` },
  { title: 'WhatWeb Cheatsheet', category: 'Web Enumeration', tags: ['whatweb','fingerprint'], links: ['https://github.com/urbanadventurer/WhatWeb'], description: `# WhatWeb\n\n\`\`\`\nwhatweb http://target -a 3\n\`\`\`\n` },
  { title: 'WAFW00F Cheatsheet', category: 'Web Enumeration', tags: ['wafw00f','waf','fingerprint'], links: ['https://github.com/EnableSecurity/wafw00f'], description: `# WAFW00F\n\n\`\`\`\nwafw00f http://target\n\`\`\`\n` },
  { title: 'amap Cheatsheet', category: 'Network Scanning', tags: ['amap','service-detection'], links: ['https://github.com/vanhauser-thc/amap'], description: `# amap\n\n\`\`\`\namap -b 192.168.1.10 1-1024\n\`\`\`\n` },
]

;(async function main() {
  try {
    // Optional JSON override
    try {
      const jsonPath = path.join(__dirname, '..', 'data', 'kali-tools.json')
      if (fs.existsSync(jsonPath)) {
        const data = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'))
        if (Array.isArray(data.categories) && data.categories.length) {
          categories = data.categories
        }
        if (Array.isArray(data.sheets) && data.sheets.length) {
          sheets = data.sheets
        }
        console.log(`Loaded JSON dataset: categories=${categories.length}, sheets=${sheets.length}`)
      }
    } catch (e) {
      console.warn('Failed to load JSON dataset, continuing with built-in seeds:', e.message)
    }

    console.log('Connecting to MongoDB...')
    await mongoose.connect(uri)
    console.log('Connected.')

    const catMap = {}
    for (const cat of categories) {
      let c = await Category.findOne({ name: cat.name })
      if (!c) c = await Category.create(cat)
      else {
        c.description = cat.description
        await c.save()
      }
      catMap[cat.name] = c._id
    }

    let created = 0
    for (const s of sheets) {
      const cid = catMap[s.category]
      if (!cid) continue
      const existing = await Cheatsheet.findOne({ title: s.title })
      if (existing) {
        existing.description = s.description
        existing.tags = s.tags
        existing.links = s.links
        existing.category = cid
        await existing.save()
      } else {
        await Cheatsheet.create({
          title: s.title,
          description: s.description,
          tags: s.tags,
          links: s.links,
          category: cid
        })
        created++
      }
    }

    console.log(`Seed completed: categories=${Object.keys(catMap).length}, created=${created}`)
    await mongoose.disconnect()
    process.exit(0)
  } catch (err) {
    console.error('Seed failed:', err)
    try { await mongoose.disconnect() } catch (_) {}
    process.exit(1)
  }
})()