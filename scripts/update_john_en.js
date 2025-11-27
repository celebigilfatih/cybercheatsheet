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

const englishContent = `# John the Ripper - Password Cracker

## Basic Usage

**Crack a password file:**
\`\`\`bash
john hashes.txt
\`\`\`
*Auto-detects hash type.*

**Show cracked passwords:**
\`\`\`bash
john --show hashes.txt
\`\`\`

**Specify format:**
\`\`\`bash
john --format=raw-md5 hashes.txt
\`\`\`

**Using a wordlist:**
\`\`\`bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
\`\`\`

## Advanced Attacks

**Single Crack Mode (Munging):**
\`\`\`bash
john --single hashes.txt
\`\`\`
*Uses username/GECOS as base words.*

**Incremental Mode (Bruteforce):**
\`\`\`bash
john --incremental hashes.txt
\`\`\`

**Rule-based Attack:**
\`\`\`bash
john --wordlist=wordlist.txt --rules=Jumbo hashes.txt
\`\`\`

**Mask Mode:**
\`\`\`bash
john --mask=?a?a?a?a?a?a hashes.txt
\`\`\`
*Bruteforce 6 characters.*

## Common Formats

| Format Name | Description |
|-------------|-------------|
| raw-md5 | MD5 |
| raw-sha1 | SHA1 |
| raw-sha256 | SHA256 |
| nt | NTLM |
| lm | LM |
| crypt | Unix Crypt (DES) |
| sha512crypt | Unix SHA512 |
| bcrypt | Bcrypt |
| wpapsk | WPA/WPA2 PSK |

## Session Management

**Restore Session:**
\`\`\`bash
john --restore
\`\`\`

**Specific Session:**
\`\`\`bash
john --session=mySession hashes.txt
john --restore=mySession
\`\`\`

**Status:**
*Press any key while running to see status.*

## Utility Commands

**Convert file formats:**
\`\`\`bash
# Zip
zip2john protected.zip > hash.txt

# SSH Key
ssh2john id_rsa > hash.txt

# PDF
pdf2john protected.pdf > hash.txt

# Rar
rar2john protected.rar > hash.txt
\`\`\`

**Test Speed:**
\`\`\`bash
john --test
\`\`\`

**List Formats:**
\`\`\`bash
john --list=formats
\`\`\`

## Configuration (john.conf)

**Location:**
\`\`\`
/etc/john/john.conf
~/.john/john.conf
\`\`\`

**Custom Rules:**
Define rules in \`[List.Rules:Wordlist]\` section.

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
f       # Reflect (password -> passworddrowssap)
$x      # Append character x
^x      # Prepend character x
[       # Remove first char
]       # Remove last char
Dn      # Delete char at position n
xNM     # Extract substring from N, length M
iNx     # Insert char x at position N
oNx     # Overwrite char at position N with x
sxy     # Replace x with y
\`\`\`

## Tips

**Test rules:**
\`\`\`bash
echo "password" | john --rules=best64 --stdout
\`\`\`

**Wordlist stats:**
\`\`\`bash
john --wordlist=rockyou.txt --rules=best64 --stdout | wc -l
\`\`\`

**Format benchmark:**
\`\`\`bash
john --test --format=raw-md5
john --test=10 --format=bcrypt-opencl
\`\`\`

**Available formats:**
\`\`\`bash
john --list=formats | grep -i ntlm
\`\`\`

**Available rules:**
\`\`\`bash
john --list=rules
\`\`\`

**OpenCL devices:**
\`\`\`bash
john --list=opencl-devices
\`\`\`

**Session list:**
\`\`\`bash
ls -la ~/.john/*.rec
\`\`\`

**Potfile location:**
\`\`\`bash
~/.john/john.pot
\`\`\`
`;

async function updateJohn() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating John English content...');

        const result = await Cheatsheet.updateOne(
            { 'title.tr': /john/i },
            { $set: { 'description.en': englishContent } }
        );

        console.log(`Update result:`, result);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateJohn();
