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

const englishContent = `# FFUF - Fast Web Fuzzer

## Basic Usage

**Directory Fuzzing:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt
\`\`\`

**Extension Fuzzing:**
\`\`\`bash
ffuf -u https://target.com/indexFUZZ -w extensions.txt
\`\`\`

**File Fuzzing:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt
\`\`\`

**Silent Mode (Only Results):**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -s
\`\`\`

## HTTP Options

**Custom Header:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -H "Cookie: session=123"
\`\`\`

**POST Data:**
\`\`\`bash
ffuf -u https://target.com/api -w wordlist.txt -X POST -d "param=FUZZ"
\`\`\`

**Follow Redirects:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -r
\`\`\`

**Proxy:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -x http://127.0.0.1:8080
\`\`\`

## Matchers (Show)

**Match Status Code:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301
\`\`\`

**Match Line Count:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -ml 100
\`\`\`

**Match Word Count:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -mw 50
\`\`\`

**Match Size:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -ms 1024
\`\`\`

**Match Regex:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -mr "admin"
\`\`\`

## Filters (Hide)

**Filter Status Code:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -fc 404
\`\`\`

**Filter Line Count:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -fl 0
\`\`\`

**Filter Word Count:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -fw 10
\`\`\`

**Filter Size:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 0
\`\`\`

**Filter Regex:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -fr "error"
\`\`\`

## Advanced Usage

**Recursion:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2
\`\`\`

**Auto Calibration:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -ac
\`\`\`
*Automatically determines filters based on baseline requests.*

**Output Format:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -o results.json -of json
\`\`\`
*Formats: json, ejson, html, md, csv, ecsv*

**Multiple Wordlists:**
\`\`\`bash
ffuf -u https://target.com/FUZZ/FUZ2Z -w w1.txt:FUZZ -w w2.txt:FUZ2Z
\`\`\`

## Attack Modes

**Clusterbomb (all combinations):**
\`\`\`bash
# 2 wordlists, every combination
ffuf -u https://target.com/FUZZ/FUZ2Z -w w1.txt:FUZZ -w w2.txt:FUZ2Z -mode clusterbomb
\`\`\`

**Pitchfork (parallel):**
\`\`\`bash
# 2 wordlists, line by line
ffuf -u https://target.com/user/FUZZ/file/FUZ2Z -w users.txt:FUZZ -w files.txt:FUZ2Z -mode pitchfork
\`\`\`

## Filter & Matcher Combinations

**Multiple filters:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -fc 404,403 -fs 42,1234 -fw 100
\`\`\`

**Multiple matchers:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301 -ms 1000-5000 -mr "success"
\`\`\`

## Tips

**Quick scan:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w common.txt -mc 200 -c
\`\`\`

**Deep scan:**
\`\`\`bash
ffuf -u https://target.com/FUZZ -w big.txt -recursion -recursion-depth 3 -ac -o deep.json -of json
\`\`\`

**API testing:**
\`\`\`bash
ffuf -u https://api.target.com/v1/FUZZ -w api-endpoints.txt -mc 200,201,401 -c -v
\`\`\`

**Bypass 403:**
\`\`\`bash
ffuf -u https://target.com/adminFUZZ -w bypass.txt -mc 200 -fc 403
\`\`\`
`;

async function updateFFUF() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating FFUF English content...');

        const result = await Cheatsheet.updateOne(
            { 'title.tr': /ffuf/i },
            { $set: { 'description.en': englishContent } }
        );

        console.log(`Update result:`, result);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateFFUF();
