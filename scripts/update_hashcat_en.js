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

const englishContent = `# Hashcat - Advanced Password Recovery

## Basic Usage

**Dictionary Attack:**
\`\`\`bash
hashcat -m 0 -a 0 hash.txt wordlist.txt
\`\`\`
* \`-m 0\`: MD5
* \`-a 0\`: Dictionary mode

**Bruteforce (Mask Attack):**
\`\`\`bash
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a
\`\`\`
* \`?a\`: All characters
* Length: 6 characters

**Rule-based Attack:**
\`\`\`bash
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/best64.rule
\`\`\`

**Combination Attack:**
\`\`\`bash
hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt
\`\`\`

## Attack Modes (-a)

| Mode | Description |
|------|-------------|
| 0 | Straight (Dictionary) |
| 1 | Combination |
| 3 | Brute-force (Mask) |
| 6 | Hybrid Wordlist + Mask |
| 7 | Hybrid Mask + Wordlist |

## Common Hash Modes (-m)

| ID | Hash Type |
|----|-----------|
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 1700 | SHA512 |
| 1000 | NTLM |
| 3000 | LM |
| 1800 | sha512crypt $6$ (Unix) |
| 3200 | bcrypt $2*$, Blowfish |
| 2500 | WPA-EAPOL-PBKDF2 |
| 16800 | WPA-PMKID-PBKDF2 |
| 22000 | WPA-PBKDF2-PMKID+EAPOL |

## Mask Characters

| Char | Description |
|------|-------------|
| ?l | Lowercase (a-z) |
| ?u | Uppercase (A-Z) |
| ?d | Digits (0-9) |
| ?h | Hex lowercase (0-9, a-f) |
| ?H | Hex uppercase (0-9, A-F) |
| ?s | Special characters |
| ?a | All (?l?u?d?s) |
| ?b | Binary (0-255) |

**Custom Charsets:**
\`\`\`bash
-1 ?l?d
hashcat -a 3 hash.txt ?1?1?1?1
\`\`\`
*Mask of 4 characters, lowercase or digit.*

## Session Management

**Restore Session:**
\`\`\`bash
hashcat --session mySession --restore
\`\`\`

**Status Check:**
\`\`\`bash
[s] status
[p] pause
[r] resume
[q] quit
\`\`\`

## Performance Tuning

**Workload Profile (-w):**
* \`1\`: Low (Desktop)
* \`2\`: Default
* \`3\`: High (Dedicated)
* \`4\`: Nightmare

**Optimize Kernel:**
\`\`\`bash
-O
\`\`\`
*Limit password length to 32 chars for speed.*

## Hash Speeds (Reference)

**Fast (>1000 MH/s):**
\`\`\`
0 = MD5
1000 = NTLM
\`\`\`

**Slow (<10 MH/s):**
\`\`\`
1800 = sha512crypt
3200 = bcrypt
\`\`\`

**Very Slow (<100 H/s):**
\`\`\`
10900 = PBKDF2-HMAC-SHA256
22000 = WPA-PBKDF2-PMKID+EAPOL
\`\`\`

## Rule Syntax Reference

**Common rules:**
\`\`\`
:       # Do nothing
l       # Lowercase all
u       # Uppercase all
c       # Capitalize
C       # Lowercase first, uppercase rest
t       # Toggle case
r       # Reverse
d       # Duplicate (password -> passwordpassword)
$x      # Append character x
^x      # Prepend character x
[       # Remove first char
]       # Remove last char
\`\`\`

## Tips

**Benchmark all modes:**
\`\`\`bash
hashcat -b
\`\`\`

**Specific mode benchmark:**
\`\`\`bash
hashcat -b -m 1000
\`\`\`

**Show example hash:**
\`\`\`bash
hashcat --example-hashes | grep -A 2 "Hash mode #1000"
\`\`\`

**GPU info:**
\`\`\`bash
hashcat -I
\`\`\`

**Debug mode:**
\`\`\`bash
hashcat -m 0 -a 0 hash.txt wordlist.txt --debug-mode 1 --debug-file debug.txt
\`\`\`

**Wordlist + rule test:**
\`\`\`bash
hashcat -a 0 --stdout wordlist.txt -r best64.rule | head -100
\`\`\`

**Mask test:**
\`\`\`bash
hashcat -a 3 --stdout ?l?l?l?d?d | head -20
\`\`\`
`;

async function updateHashcat() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating Hashcat English content...');

        const result = await Cheatsheet.updateOne(
            { 'title.tr': /hashcat/i },
            { $set: { 'description.en': englishContent } }
        );

        console.log(`Update result:`, result);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateHashcat();
