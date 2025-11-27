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

const englishContent = `# Sublist3r - Subdomain Enumeration Tool

## Basic Usage

**Simple subdomain scan:**
\`\`\`bash
sublist3r -d example.com
\`\`\`
*Uses default engines (Google, Yahoo, Bing, etc.).*

**Save results to file:**
\`\`\`bash
sublist3r -d example.com -o subdomains.txt
\`\`\`

**Verbose mode:**
\`\`\`bash
sublist3r -d example.com -v
\`\`\`
*Shows real-time results.*

## Advanced Scan

**Bruteforce mode:**
\`\`\`bash
sublist3r -d example.com -b
\`\`\`
*Uses built-in wordlist.*

**Specific ports:**
\`\`\`bash
sublist3r -d example.com -p 80,443
\`\`\`
*Checks if found subdomains are alive on these ports.*

**Thread count (default 30):**
\`\`\`bash
sublist3r -d example.com -t 50
\`\`\`

## Search Engines

**List available engines:**
\`\`\`bash
sublist3r -l
\`\`\`

**Enable specific engines:**
\`\`\`bash
sublist3r -d example.com -e google,yahoo,virustotal
\`\`\`

## Common Scenarios

**1. Full Recon:**
\`\`\`bash
sublist3r -d example.com -b -t 100 -v -o full_scan.txt
\`\`\`

**2. Passive Only (No Bruteforce):**
\`\`\`bash
sublist3r -d example.com -v -o passive.txt
\`\`\`

**3. Port Scan on Found Domains:**
\`\`\`bash
sublist3r -d example.com -p 80,443,8080,8443
\`\`\`

## Best Practices

**1. Use Bruteforce:**
Passive sources miss many subdomains. Always use \`-b\` for thoroughness.

**2. Threading:**
Increase threads (\`-t\`) for faster bruteforcing, but be careful not to crash your DNS resolver.

**3. Output:**
Always save output (\`-o\`) for later use with other tools (like httpx or nmap).

**4. API Keys:**
Configure API keys (VirusTotal, Shodan, etc.) in \`config.py\` for better results.

**5. Verification:**
Sublist3r might return dead domains. Verify them with \`httpx\` or \`dnsx\`.

## Tips

**Combination suggestions:**
\`\`\`bash
# Max coverage
sublist3r -d target.com -b -v -t 25 -o complete.txt

# Fast recon
sublist3r -d target.com -t 40 -s -o quick.txt

# Stealth mode
sublist3r -d target.com -t 3 -e virustotal,dnsdumpster -o stealth.txt
\`\`\`

**Result Verification:**
\`\`\`bash
# Verify Sublist3r results
cat results.txt | dnsx -silent -resp | tee verified.txt
\`\`\`

**Integration with other tools:**
\`\`\`bash
# Subfinder + Sublist3r
subfinder -d target.com -o sub1.txt
sublist3r -d target.com -o sub2.txt
cat sub1.txt sub2.txt | sort -u > merged.txt
\`\`\`

**API Token Usage:**
- VirusTotal API key: \`~/.config/sublist3r/config.json\`
- Shodan API integration
- Censys integration

**Common Wordlist Locations:**
\`\`\`
/usr/share/seclists/Discovery/DNS/
/opt/SecLists/Discovery/DNS/
~/wordlists/dns/
\`\`\`
`;

async function updateSublist3r() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating Sublist3r English content...');

        const result = await Cheatsheet.updateOne(
            { 'title.tr': /sublist3r/i },
            { $set: { 'description.en': englishContent } }
        );

        console.log(`Update result:`, result);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateSublist3r();
