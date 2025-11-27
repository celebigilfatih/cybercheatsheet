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

const englishContent = `# WPScan - WordPress Security Scanner

## Basic Usage

**Simple scan:**
\`\`\`bash
wpscan --url https://target.com
\`\`\`

**Update database:**
\`\`\`bash
wpscan --update
\`\`\`
*Updates the vulnerability database.*

**Using API Token:**
\`\`\`bash
wpscan --url https://target.com --api-token YOUR_TOKEN
\`\`\`
*Required for vulnerability data.*

## Enumeration

**Enumerate Users:**
\`\`\`bash
wpscan --url https://target.com --enumerate u
\`\`\`

**Enumerate Plugins:**
\`\`\`bash
wpscan --url https://target.com --enumerate p
\`\`\`
* \`p\`: Popular plugins
* \`vp\`: Vulnerable plugins
* \`ap\`: All plugins

**Enumerate Themes:**
\`\`\`bash
wpscan --url https://target.com --enumerate t
\`\`\`
* \`t\`: Popular themes
* \`vt\`: Vulnerable themes
* \`at\`: All themes

**Combined Enumeration:**
\`\`\`bash
wpscan --url https://target.com --enumerate u,vp,vt
\`\`\`

## Bruteforce

**Password Attack:**
\`\`\`bash
wpscan --url https://target.com --passwords passwords.txt --usernames admin
\`\`\`

**User List + Password List:**
\`\`\`bash
wpscan --url https://target.com --passwords passwords.txt --usernames users.txt
\`\`\`

**Multithreading:**
\`\`\`bash
wpscan --url https://target.com -P passwords.txt -U users.txt --max-threads 50
\`\`\`

## Advanced Options

**Proxy:**
\`\`\`bash
wpscan --url https://target.com --proxy http://127.0.0.1:8080
\`\`\`

**User-Agent:**
\`\`\`bash
wpscan --url https://target.com --user-agent "Mozilla/5.0..."
\`\`\`

**Random User-Agent:**
\`\`\`bash
wpscan --url https://target.com --random-user-agent
\`\`\`

**Detection Mode:**
\`\`\`bash
wpscan --url https://target.com --stealthy
\`\`\`
*Alias for --random-user-agent --detection-mode passive --plugins-version-detection passive*

**Bypass WAF:**
\`\`\`bash
wpscan --url https://target.com --random-user-agent --throttle 500
\`\`\`

## Output Formats

**cli-no-color:**
\`\`\`bash
--format cli-no-color -o results.txt
\`\`\`
*Plain text (for logs)*

**json:**
\`\`\`bash
--format json -o results.json
\`\`\`
*JSON format (programmatic parsing)*

## Tips

**Quick Vulnerability Check:**
\`\`\`bash
wpscan --url https://target.com --api-token TOKEN --enumerate vp,vt --format json | jq '.plugins[] | select(.vulnerabilities != [])'
\`\`\`

**User + Bruteforce Combo:**
\`\`\`bash
wpscan --url https://target.com --enumerate u -U $(wpscan --url https://target.com --enumerate u --format json | jq -r '.users | keys[]') -P passwords.txt
\`\`\`

**Batch Scanning:**
\`\`\`bash
while read url; do
  wpscan --url $url --api-token TOKEN --enumerate vp --format json -o \${url//\\//_}.json
done < urls.txt
\`\`\`

**Custom wp-content path:**
\`\`\`bash
wpscan --url https://target.com --wp-content-dir custom-content
\`\`\`

**Plugin Version Extraction:**
\`\`\`bash
wpscan --url https://target.com --enumerate p --format json | jq -r '.plugins[] | "\\(.slug): \\(.version.number)"'
\`\`\`
`;

async function updateWPScan() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating WPScan English content...');

        const result = await Cheatsheet.updateOne(
            { 'title.tr': /wpscan/i },
            { $set: { 'description.en': englishContent } }
        );

        console.log(`Update result:`, result);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateWPScan();
