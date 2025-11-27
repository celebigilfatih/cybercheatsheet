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

const englishContent = `# Wfuzz - Web Application Fuzzer

## Basic Usage

**Simple directory fuzzing:**
\`\`\`bash
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 http://target.com/FUZZ
\`\`\`
* \`-c\`: Color output
* \`-z\`: Payload (file, wordlist path)
* \`--hc\`: Hide code (404)
* \`FUZZ\`: Injection point

**Fuzzing files with extensions:**
\`\`\`bash
wfuzz -c -z file,wordlist.txt http://target.com/FUZZ.php
\`\`\`

## Payload Types

**File:**
\`\`\`bash
-z file,wordlist.txt
\`\`\`

**Range (Numeric):**
\`\`\`bash
-z range,0-10
\`\`\`

**List:**
\`\`\`bash
-z list,admin-root-user
\`\`\`

## Multiple Fuzzing Points

**FUZZ and FUZ2Z:**
\`\`\`bash
wfuzz -c -z file,users.txt -z file,pass.txt --hc 404 http://target.com/login.php?user=FUZZ&pass=FUZ2Z
\`\`\`

**Multiple payloads mapping:**
\`\`\`bash
wfuzz -c -z file,users.txt -z file,pass.txt -m zip http://target.com/FUZZ/FUZ2Z
\`\`\`

## HTTP Options

**Custom Header:**
\`\`\`bash
wfuzz -H "Cookie: session=123" http://target.com/FUZZ
\`\`\`

**POST Data:**
\`\`\`bash
wfuzz -d "id=FUZZ&debug=true" http://target.com/api
\`\`\`

**Follow Redirects:**
\`\`\`bash
wfuzz -L --follow http://target.com/FUZZ
\`\`\`

**Proxy:**
\`\`\`bash
wfuzz -p 127.0.0.1:8080 http://target.com/FUZZ
\`\`\`

## Filters (Hide/Show)

**Hide Code (--hc):**
\`\`\`bash
--hc 404
--hc 404,403
\`\`\`

**Show Code (--sc):**
\`\`\`bash
--sc 200
--sc 200,301
\`\`\`

**Hide Lines (--hl) / Show Lines (--sl):**
\`\`\`bash
--hl 50
--sl 100
\`\`\`

**Hide Words (--hw) / Show Words (--sw):**
\`\`\`bash
--hw 120
--sw 500
\`\`\`

**Hide Chars (--hh) / Show Chars (--sh):**
\`\`\`bash
--hh 1024
--sh 2048
\`\`\`

## Advanced Filtering (--filter)

**Status Codes:**
\`\`\`bash
--filter "c=200"
--filter "c!=404"
--filter "c>=200 and c<300"
\`\`\`

**Lines:**
\`\`\`bash
--filter "l>50"
--filter "l<100"
\`\`\`

**Words:**
\`\`\`bash
--filter "w=75"
\`\`\`

**Chars (response size):**
\`\`\`bash
--filter "h>1000"
--filter "h!=5555"
\`\`\`

**Time:**
\`\`\`bash
--filter "t>5000"  # Response time > 5 sec
\`\`\`

**Combination:**
\`\`\`bash
--filter "c=200 and l>100 and h<10000"
\`\`\`

## Tips

**Wordlist Locations (Kali):**
\`\`\`
/usr/share/seclists/Discovery/Web-Content/
/usr/share/wordlists/dirb/
/usr/share/wordlists/dirbuster/
\`\`\`

**Output Formats:**
\`\`\`bash
-o json    # JSON output
-o html    # HTML report
-o csv     # CSV format
-o raw     # Raw output
\`\`\`

**Quick Snippets:**
\`\`\`bash
# API key brute-force
wfuzz -z file,keys.txt -H "X-API-Key: FUZZ" --sc 200 http://api.target.com/endpoint

# User enumeration
wfuzz -z file,users.txt -d "username=FUZZ" --hc 200 --sc 404 http://target.com/check-user

# Backup file hunting
wfuzz -z file,filenames.txt -z list,.bak-.old-.swp-.save http://target.com/FUZZ.FUZ2Z
\`\`\`
`;

async function updateWfuzz() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating Wfuzz English content...');

        const result = await Cheatsheet.updateOne(
            { 'title.tr': /wfuzz/i },
            { $set: { 'description.en': englishContent } }
        );

        console.log(`Update result:`, result);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateWfuzz();
