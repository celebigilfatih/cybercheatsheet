import dbConnect from '../lib/dbConnect.js';
import Cheatsheet from '../models/Cheatsheet.js';
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

const englishContent = `# Amass - In-depth DNS Enumeration

## Basic Usage

**Simple Enumeration:**
\`\`\`bash
amass enum -d example.com
\`\`\`
*Basic subdomain discovery.*

**Passive Mode:**
\`\`\`bash
amass enum -passive -d example.com
\`\`\`
*No direct interaction with target.*

**Active Mode:**
\`\`\`bash
amass enum -active -d example.com
\`\`\`
*Attempts zone transfers and certificate grabbing.*

**IP Address Discovery:**
\`\`\`bash
amass enum -ip -d example.com
\`\`\`

## Advanced Enumeration

**Bruteforce:**
\`\`\`bash
amass enum -brute -d example.com
\`\`\`

**Custom Wordlist:**
\`\`\`bash
amass enum -brute -w wordlist.txt -d example.com
\`\`\`

**Recursive Bruteforce:**
\`\`\`bash
amass enum -brute -min-for-recursive 2 -d example.com
\`\`\`

**Permutations:**
\`\`\`bash
amass enum -active -p 80,443,8080 -d example.com
\`\`\`

## Intelligence (Intel)

**Discover Target Domains (Reverse Whois):**
\`\`\`bash
amass intel -whois -d example.com
\`\`\`

**Discover by ASN:**
\`\`\`bash
amass intel -asn 12345
\`\`\`

**Discover by CIDR:**
\`\`\`bash
amass intel -cidr 192.168.1.0/24
\`\`\`

**Organization Search:**
\`\`\`bash
amass intel -org "Example Corp"
\`\`\`

## Configuration

**Config File:**
\`\`\`bash
amass enum -d example.com -config config.ini
\`\`\`

**Output Directory:**
\`\`\`bash
amass enum -d example.com -dir ./output
\`\`\`

**Log File:**
\`\`\`bash
amass enum -d example.com -log amass.log
\`\`\`

## Data Sources

**Passive Sources:**
* Shodan
* SecurityTrails
* ThreatCrowd
* HackerTarget
* Netcraft
* DNSDumpster
* Wayback Machine

**Active Sources:**
* DNS resolution
* Reverse DNS
* Port scanning
* Certificate analysis

## Tips

**List Data Sources:**
\`\`\`bash
amass enum -list
\`\`\`

**Check Config:**
\`\`\`bash
amass enum -d target.com -config config.ini -list
\`\`\`

**Database Operations:**
\`\`\`bash
amass db -dir output -list
amass db -dir output -show -d target.com
amass db -dir output -names
amass db -dir output -summary
\`\`\`

**Export Formats:**
\`\`\`bash
amass db -dir output -show -d target.com -o export.txt
amass viz -d3 -dir output -o graph.html
amass viz -dot -dir output | dot -Tpng > graph.png
\`\`\`

**Version:**
\`\`\`bash
amass -version
\`\`\`

**Help:**
\`\`\`bash
amass enum -h
amass intel -h
amass viz -h
amass db -h
\`\`\`
`;

async function updateAmass() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating Amass English content...');

        const result = await Cheatsheet.updateOne(
            { 'title.tr': /amass/i },
            { $set: { 'description.en': englishContent } }
        );

        console.log(`Update result:`, result);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateAmass();
