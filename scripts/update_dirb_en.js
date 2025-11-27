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

const englishContent = `# Dirb - Web Content Scanner

## Basic Usage

**Simple scan (default wordlist):**
\`\`\`bash
dirb http://target.com
\`\`\`
*Scans using common.txt.*

**Specific wordlist:**
\`\`\`bash
dirb http://target.com /usr/share/wordlists/dirb/big.txt
\`\`\`

**Scan with extension list:**
\`\`\`bash
dirb http://target.com -X .php,.html,.txt
\`\`\`
*Only checks for specific extensions.*

**Recursive scan (default on):**
\`\`\`bash
dirb http://target.com -r
\`\`\`
*Scans subdirectories found.*

## Advanced Scan

**Case insensitive:**
\`\`\`bash
dirb http://target.com -i
\`\`\`

**Custom User-Agent:**
\`\`\`bash
dirb http://target.com -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
\`\`\`
*Useful for bypassing basic WAFs.*

**Ignore specific HTTP code:**
\`\`\`bash
dirb http://target.com -N 403
\`\`\`

**Print specific HTTP code:**
\`\`\`bash
dirb http://target.com -w
\`\`\`
*Don't stop on warnings.*

## Authentication

**Basic Auth:**
\`\`\`bash
dirb http://target.com -u username:password
\`\`\`

**Client Certificate:**
\`\`\`bash
dirb http://target.com -c client.pem
\`\`\`

**Cookie:**
\`\`\`bash
dirb http://target.com -H "Cookie: session=123"
\`\`\`

## Performance and Speed

**Delay (milliseconds):**
\`\`\`bash
dirb http://target.com -z 100
\`\`\`
*Adds 100ms delay between requests.*

**Parallel scanning:**
*Dirb is single-threaded. For multi-threading, use Gobuster or FFUF.*

## Output Formats

**Save output to file:**
\`\`\`bash
dirb http://target.com -o output.txt
\`\`\`

## Common Scenarios

**1. Finding Admin Panels:**
\`\`\`bash
dirb http://target.com /usr/share/wordlists/dirb/common.txt -X .php
\`\`\`

**2. Backup File Search:**
\`\`\`bash
dirb http://target.com -X .bak,.old,.zip,.tar.gz
\`\`\`

**3. API Endpoint Discovery:**
\`\`\`bash
dirb http://api.target.com /usr/share/wordlists/dirb/big.txt
\`\`\`

## Best Practices

**1. Start Small:**
Start with \`common.txt\`. If you find nothing, switch to \`big.txt\`.

**2. Use Extensions:**
Always use \`-X\` or \`-x\` flags tailored to the target technology (e.g., \`.php\` for LAMP, \`.aspx\` for IIS).

**3. Watch Rate Limits:**
If you get too many 403s or connection errors, use \`-z\` to slow down.

**4. Check Recursive:**
Recursive scanning can take forever. Use \`-r\` carefully on large sites.

**5. False Positives:**
Verify findings manually or with another tool like curl.

**6. WAF Bypass:**
Change User-Agent (\`-a\`) and add delays (\`-z\`).

**7. Don't change User-Agent:**
\`\`\`bash
# WRONG
dirb http://target.com

# RIGHT (WAF bypass)
dirb http://target.com -a "Mozilla/5.0..."
\`\`\`
*Default UA might be blocked.*

**8. Not saving output:**
\`\`\`bash
# WRONG
dirb http://target.com /huge-wordlist.txt

# RIGHT
dirb http://target.com /huge-wordlist.txt -o scan_$(date +%Y%m%d_%H%M).txt
\`\`\`
*If terminal closes, results are lost.*

## Wordlist Locations

\`\`\`
/usr/share/dirb/wordlists/common.txt          # 4600 entries
/usr/share/dirb/wordlists/big.txt             # 20k entries
/usr/share/dirb/wordlists/small.txt           # 980 entries
/usr/share/dirb/wordlists/extensions_common.txt
/usr/share/seclists/Discovery/Web-Content/    # SecLists
\`\`\`

## Tips

- SSL Error: Dirb does not verify SSL certs (advantage).
- Wildcard detection: Checks for patterns in first 10 requests.
- Case-sensitive: Use \`-i\` flag.
- Speed vs Stealth: Balance with \`-z\`.
- False-positive: Check manually via Proxy.
- Multi-stage: common.txt -> recursive scan on findings.
`;

async function updateDirb() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating Dirb English content...');

        const result = await Cheatsheet.updateOne(
            { 'title.tr': /dirb/i },
            { $set: { 'description.en': englishContent } }
        );

        console.log(`Update result:`, result);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateDirb();
