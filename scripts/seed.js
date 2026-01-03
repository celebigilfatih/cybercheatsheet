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
    name: {
      tr: { type: String, required: true, trim: true },
      en: { type: String, required: true, trim: true }
    },
    description: {
      tr: { type: String, default: '' },
      en: { type: String, default: '' }
    }
  },
  { timestamps: true }
)

const CheatsheetSchema = new mongoose.Schema(
  {
    title: {
      tr: { type: String, required: true, trim: true },
      en: { type: String, required: true, trim: true }
    },
    description: {
      tr: { type: String, default: '' },
      en: { type: String, default: '' }
    },
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

Servis/versiyon ve OS detection:

\`\`\`
nmap -sV 192.168.1.10
nmap -O 192.168.1.10
\`\`\`

NSE örnekleri:

\`\`\`
nmap --script vuln 192.168.1.10
\`\`\`
`
  },
  { title: 'Masscan Cheatsheet', category: 'Network Scanning', tags: ['masscan','scan','ports'], links: ['https://github.com/robertdavidgraham/masscan'], description: `# Masscan Cheatsheet

\`\`\`
masscan 192.168.1.0/24 -p80,443 --rate=10000
\`\`\`
` },
  { title: 'Gobuster Cheatsheet', category: 'Directory Bruteforce', tags: ['gobuster','dir','dns'], links: ['https://github.com/OJ/gobuster'], description: `# Gobuster

\`\`\`
gobuster dir -u http://target -w wordlist.txt -x php,txt,html -t 50
\`\`\`
` },
  { title: 'FFUF Cheatsheet', category: 'Web Enumeration', tags: ['ffuf','fuzz','web'], links: ['https://github.com/ffuf/ffuf'], description: `# FFUF

\`\`\`
ffuf -u http://target/FUZZ -w /path/wordlist.txt -mc 200
\`\`\`
` },
  { title: 'Dirsearch Cheatsheet', category: 'Directory Bruteforce', tags: ['dirsearch','dir','web'], links: ['https://github.com/maurosoria/dirsearch'], description: `# Dirsearch

\`\`\`
dirsearch -u http://target -e php,txt,html -w wordlist.txt -t 50
\`\`\`
` },
  { title: 'Nikto Cheatsheet', category: 'Web Enumeration', tags: ['nikto','web','scan'], links: ['https://github.com/sullo/nikto'], description: `# Nikto

\`\`\`
nikto -h http://target
\`\`\`
` },
  { title: 'SQLMap Cheatsheet', category: 'SQL Injection', tags: ['sqlmap','sqli','db'], links: ['https://sqlmap.org/'], description: `# SQLMap

\`\`\`
sqlmap -u 'http://target/item.php?id=1' --batch
\`\`\`
` },
  { title: 'Hydra Cheatsheet', category: 'Password Cracking', tags: ['hydra','bruteforce','ssh'], links: ['https://github.com/vanhauser-thc/thc-hydra'], description: `# Hydra

\`\`\`
hydra -l root -P passwords.txt ssh://192.168.1.10
\`\`\`
` },
  { title: 'Netcat Cheatsheet', category: 'Network Utilities', tags: ['nc','netcat','reverse-shell'], links: ['http://nc110.sourceforge.net/'], description: `# Netcat

\`\`\`
nc -lvnp 4444
\`\`\`
` },
  { title: 'Tcpdump Cheatsheet', category: 'Network Utilities', tags: ['tcpdump','pcap','filter'], links: ['https://www.tcpdump.org/manpages/tcpdump.1.html'], description: `# Tcpdump

\`\`\`
tcpdump -i eth0 'port 80'
\`\`\`
` },
  { title: 'Amass Cheatsheet', category: 'Subdomain Discovery', tags: ['amass','dns','enum'], links: ['https://github.com/owasp-amass/amass'], description: `# Amass

\`\`\`
amass enum -d example.com
\`\`\`
` },
  { title: 'John the Ripper Cheatsheet', category: 'Password Cracking', tags: ['john','hash','cracking'], links: ['https://www.openwall.com/john/'], description: `# John

\`\`\`
john hashes.txt --format=raw-md5
\`\`\`
` },
  { title: 'Hashcat Cheatsheet', category: 'Password Cracking', tags: ['hashcat','gpu','cracking'], links: ['https://hashcat.net/wiki/'], description: `# Hashcat

\`\`\`
hashcat -m 0 -a 0 hashes.txt /path/rockyou.txt
\`\`\`
` },
  { title: 'Metasploit Cheatsheet', category: 'Exploitation', tags: ['metasploit','msf','exploit'], links: ['https://docs.metasploit.com/'], description: `# Metasploit

\`\`\`
msfconsole
\`\`\`
` },
  { title: 'WPScan Cheatsheet', category: 'Web Enumeration', tags: ['wpscan','wordpress','enum','vuln'], links: ['https://wpscan.com/', 'https://github.com/wpscanteam/wpscan'], description: `# WPScan

\`\`\`
wpscan --url https://target
\`\`\`
` },
  { title: 'Wfuzz Cheatsheet', category: 'Web Enumeration', tags: ['wfuzz','fuzz','web'], links: ['https://github.com/xmendez/wfuzz'], description: `# Wfuzz

\`\`\`
wfuzz -u http://target/FUZZ -w /path/wordlist.txt --hc 404
\`\`\`
` },
  { title: 'Sublist3r Cheatsheet', category: 'Subdomain Discovery', tags: ['sublist3r','subdomains'], links: ['https://github.com/aboul3la/Sublist3r'], description: `# Sublist3r

\`\`\`
sublist3r -d example.com -o subs.txt
\`\`\`
` },
  { title: 'TShark Cheatsheet', category: 'Network Utilities', tags: ['tshark','wireshark','cli'], links: ['https://www.wireshark.org/docs/man-pages/tshark.html'], description: `# TShark

\`\`\`
tshark -i eth0
\`\`\`
` },
  { title: 'Aircrack-ng Cheatsheet', category: 'Wireless', tags: ['aircrack-ng','wifi','wpa','monitor'], links: ['https://www.aircrack-ng.org/documentation.html'], description: `# Aircrack-ng

\`\`\`
airmon-ng start wlan0
airodump-ng wlan0mon
\`\`\`
` },
  { title: 'Ncrack Cheatsheet', category: 'Password Cracking', tags: ['ncrack','bruteforce','network'], links: ['https://nmap.org/ncrack/'], description: `# Ncrack

\`\`\`
ncrack -v -u admin -P passwords.txt ssh://192.168.1.10
\`\`\`
` },
  { title: 'Burp Suite Cheatsheet', category: 'Web Enumeration', tags: ['burp','proxy','intruder','repeater'], links: ['https://portswigger.net/burp/documentation'], description: `# Burp Suite

Proxy 127.0.0.1:8080
Intercept ON/OFF
` },
  { title: 'OWASP ZAP Cheatsheet', category: 'Web Enumeration', tags: ['zap','proxy','active-scan'], links: ['https://www.zaproxy.org/docs/'], description: `# ZAP\n\nQuick Start > Automated Scan\n` },
  { title: 'theHarvester Cheatsheet', category: 'Web Enumeration', tags: ['theharvester','osint','emails','hosts'], links: ['https://github.com/laramies/theHarvester'], description: `# theHarvester

\`\`\`
theHarvester -d example.com -b google
\`\`\`
` },
  { title: 'dnsenum Cheatsheet', category: 'Subdomain Discovery', tags: ['dnsenum','dns','enum'], links: ['https://github.com/fwaeytens/dnsenum'], description: `# dnsenum

\`\`\`
dnsenum example.com
\`\`\`
` },
  { title: 'recon-ng Cheatsheet', category: 'Web Enumeration', tags: ['recon-ng','framework','osint'], links: ['https://github.com/lanmaster53/recon-ng'], description: `# recon-ng\n\nworkspaces add target\n` },
  { title: 'WhatWeb Cheatsheet', category: 'Web Enumeration', tags: ['whatweb','fingerprint'], links: ['https://github.com/urbanadventurer/WhatWeb'], description: `# WhatWeb

\`\`\`
whatweb http://target -a 3
\`\`\`
` },
  { title: 'WAFW00F Cheatsheet', category: 'Web Enumeration', tags: ['wafw00f','waf','fingerprint'], links: ['https://github.com/EnableSecurity/wafw00f'], description: `# WAFW00F

\`\`\`
wafw00f http://target
\`\`\`
` },
  { title: 'amap Cheatsheet', category: 'Network Scanning', tags: ['amap','service-detection'], links: ['https://github.com/vanhauser-thc/amap'], description: `# amap

\`\`\`
amap -b 192.168.1.10 1-1024
\`\`\`
` },
]

;(async function main() {
  try {
    // Load from mdb/categories.json and mdb/cheatsheets.json
    try {
      const categoriesPath = path.join(__dirname, '..', 'mdb', 'categories.json')
      if (fs.existsSync(categoriesPath)) {
        const data = JSON.parse(fs.readFileSync(categoriesPath, 'utf-8'))
        if (Array.isArray(data)) {
          categories = data.map(cat => ({
            ...cat,
            createdAt: cat.createdAt && cat.createdAt.$date ? new Date(cat.createdAt.$date) : new Date(),
            updatedAt: cat.updatedAt && cat.updatedAt.$date ? new Date(cat.updatedAt.$date) : new Date()
          }))
        }
        console.log(`Loaded categories.json: ${categories.length} categories`)
      }
    } catch (e) {
      console.warn('Failed to load categories.json:', e.message)
    }

    try {
      const cheatsheetsPath = path.join(__dirname, '..', 'mdb', 'cheatsheets.json')
      if (fs.existsSync(cheatsheetsPath)) {
        const data = JSON.parse(fs.readFileSync(cheatsheetsPath, 'utf-8'))
        if (Array.isArray(data)) {
          sheets = data.map(sheet => ({
            ...sheet,
            createdAt: sheet.createdAt && sheet.createdAt.$date ? new Date(sheet.createdAt.$date) : new Date(),
            updatedAt: sheet.updatedAt && sheet.updatedAt.$date ? new Date(sheet.updatedAt.$date) : new Date()
          }))
        }
        console.log(`Loaded cheatsheets.json: ${sheets.length} cheatsheets`)
      }
    } catch (e) {
      console.warn('Failed to load cheatsheets.json:', e.message)
    }

    console.log('Connecting to MongoDB...')
    await mongoose.connect(uri)
    console.log('Connected.')

    const catMap = {}
    for (const cat of categories) {
      // Support both old {name: string} and new {name: {tr, en}} formats
      const nameQuery = typeof cat.name === 'string' ? cat.name : cat.name?.tr
      let c = await Category.findOne({ $or: [{ name: nameQuery }, { 'name.tr': nameQuery }] })
      if (!c) {
        // Convert old format to new bilingual format if needed
        const catData = typeof cat.name === 'string'
          ? { name: { tr: cat.name, en: cat.name }, description: { tr: cat.description || '', en: cat.description || '' } }
          : cat
        
        // If category has _id with $oid format, use it
        if (cat._id && cat._id.$oid) {
          catData._id = new mongoose.Types.ObjectId(cat._id.$oid)
        }
        
        try {
          c = await Category.create(catData)
          console.log(`Created category: ${nameQuery} (${c._id})`)
        } catch (err) {
          console.error(`Failed to create category ${nameQuery}:`, err.message)
          continue
        }
      }
      
      // Map both by name and by original ObjectId (if present)
      catMap[nameQuery] = c._id
      if (cat._id && cat._id.$oid) {
        catMap[cat._id.$oid] = c._id
      }
    }

    let created = 0
    for (const s of sheets) {
      // Get category ID - support both string (category name) and object ({$oid: ...}) formats
      let cid
      if (typeof s.category === 'string') {
        cid = catMap[s.category]
      } else if (s.category && s.category.$oid) {
        cid = catMap[s.category.$oid]
      }
      
      if (!cid) {
        console.warn(`Skipping cheatsheet "${s.title}" - category not found:`, s.category)
        continue
      }
      
      // Support both old {title: string} and new {title: {tr, en}} formats
      const titleQuery = typeof s.title === 'string' ? s.title : s.title?.tr
      const existing = await Cheatsheet.findOne({ $or: [{ title: titleQuery }, { 'title.tr': titleQuery }] })
      
      if (existing) {
        // Update existing - preserve bilingual format
        if (typeof s.title === 'object' && s.title.tr) {
          existing.title = s.title
        }
        if (typeof s.description === 'object' && s.description.tr) {
          existing.description = s.description
        } else if (typeof s.description === 'string') {
          existing.description = { tr: s.description, en: s.description }
        }
        existing.tags = s.tags
        existing.links = s.links
        existing.category = cid
        await existing.save()
      } else {
        // Create new - convert to bilingual format if needed
        const sheetData = {
          title: typeof s.title === 'string' ? { tr: s.title, en: s.title } : s.title,
          description: typeof s.description === 'string' ? { tr: s.description, en: s.description } : s.description,
          tags: s.tags,
          links: s.links,
          category: cid
        }
        await Cheatsheet.create(sheetData)
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