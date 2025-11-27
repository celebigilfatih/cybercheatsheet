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

const englishContent = `# Gobuster - Directory/File, DNS and VHost Busting Tool

## 1. What is Gobuster?

Gobuster is a tool written in Go programming language used to brute-force:
*   URIs (directories and files) in web sites.
*   DNS subdomains (with wildcard support).
*   Virtual Host names on target web servers.
*   Open Amazon S3 buckets.

It is preferred for its speed and efficiency compared to other tools like DirBuster or Dirb.

## 2. Installation

**Kali Linux / Debian:**
\`\`\`bash
apt install gobuster
\`\`\`

**Using Go (Golang):**
\`\`\`bash
go install github.com/OJ/gobuster/v3@latest
\`\`\`

**Version Check:**
\`\`\`bash
gobuster version
\`\`\`

## 3. Basic Usage

**Directory Brute-force:**
\`\`\`bash
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
\`\`\`
*   \`dir\`: Directory mode.
*   \`-u\`: Target URL.
*   \`-w\`: Wordlist.

**DNS Subdomain Brute-force:**
\`\`\`bash
gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
\`\`\`
*   \`dns\`: DNS mode.
*   \`-d\`: Target domain.

**VHost Brute-force:**
\`\`\`bash
gobuster vhost -u https://target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
\`\`\`
*   \`vhost\`: Virtual Host mode.

## 4. Directory Mode Options

**Extensions:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt -x php,html,txt
\`\`\`
*   \`-x\`: Extensions to search for.

**Status Codes:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt -s 200,301,302
\`\`\`
*   \`-s\`: Whitelist status codes.
*   \`-b\`: Blacklist status codes (e.g., \`-b 404\`).

**Threads:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt -t 50
\`\`\`
*   \`-t\`: Number of concurrent threads (default: 10).

**Timeout:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt --timeout 10s
\`\`\`

**Follow Redirects:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt -r
\`\`\`

**Disable SSL Verification:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt -k
\`\`\`

## 5. Advanced Usage

**Proxy:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt -p http://127.0.0.1:8080
\`\`\`

**User Agent:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt -a "MyUserAgent"
\`\`\`

**HTTP Headers:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt -H "Authorization: Bearer TOKEN"
\`\`\`

**Username/Password (Basic Auth):**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt -U username -P password
\`\`\`

**Output to File:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt -o results.txt
\`\`\`

## 6. Tips

**Quick Scan:**
\`\`\`bash
gobuster dir -u https://target.com -w common.txt -t 64 -x php,txt
\`\`\`

**Exclude Length:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt --exclude-length 1234
\`\`\`
*Useful for filtering out custom error pages.*

**Wildcard Detection:**
Gobuster automatically handles wildcard responses, but you can tune it with \`--wildcard\`.

**Pattern Matching:**
\`\`\`bash
gobuster dir -u https://target.com -w wordlist.txt --pattern "backup-{GOBUSTER}.zip"
\`\`\`
*Replaces {GOBUSTER} with the word from wordlist.*
`;

async function updateGobuster() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating Gobuster English content...');

        const result = await Cheatsheet.updateOne(
            { 'title.tr': /gobuster/i },
            { $set: { 'description.en': englishContent } }
        );

        console.log(`Update result:`, result);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateGobuster();
