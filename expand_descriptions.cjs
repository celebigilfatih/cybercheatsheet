const fs = require('fs');

const cheatsheets = JSON.parse(fs.readFileSync('./mdb/cheatsheets.json', 'utf8'));

console.log('=== SHORT DESCRIPTIONS TO EXPAND ===\n');

const shortDescriptions = cheatsheets
  .map((sheet, idx) => ({
    index: idx,
    title: sheet.title,
    length: sheet.description.length,
    description: sheet.description
  }))
  .filter(s => s.length < 500)
  .sort((a, b) => a.length - b.length);

console.log(`Found ${shortDescriptions.length} cheatsheets with descriptions < 500 chars\n`);

shortDescriptions.forEach((item, i) => {
  console.log(`${i+1}. ${item.title} (${item.length} chars)`);
  console.log(`   Current: "${item.description.substring(0, 80)}..."`);
  console.log();
});

// Recommendations for expansion
console.log('\n=== EXPANSION RECOMMENDATIONS ===\n');

const expansions = {
  'Nmap Cheatsheet': {
    addition: `

## Basic Scans

**Simple TCP connection scan:**
\`\`\`
nmap -sT 192.168.1.0/24
\`\`\`

**SYN stealth scan:**
\`\`\`
nmap -sS 192.168.1.0/24
\`\`\`

**UDP scan:**
\`\`\`
nmap -sU 192.168.1.0/24
\`\`\`

## Service Detection & OS Fingerprinting

**Service version detection:**
\`\`\`
nmap -sV 192.168.1.1
\`\`\`

**OS detection:**
\`\`\`
nmap -O 192.168.1.1
\`\`\`

**Aggressive scan (combines -sV, -O, -A):**
\`\`\`
nmap -A 192.168.1.1
\`\`\`

## Advanced Options

**Ping sweep (find live hosts):**
\`\`\`
nmap -sn 192.168.1.0/24
\`\`\`

**Scan specific ports:**
\`\`\`
nmap -p 22,80,443 192.168.1.1
\`\`\`

**Scan all ports:**
\`\`\`
nmap -p- 192.168.1.1
\`\`\`

**Timing templates (paranoid, sneaky, polite, normal, aggressive, insane):**
\`\`\`
nmap -T4 192.168.1.1
\`\`\`

## Output Formats

**Save to file:**
\`\`\`
nmap -oN scan.txt 192.168.1.1
nmap -oX scan.xml 192.168.1.1
nmap -oG scan.gnmap 192.168.1.1
\`\`\`

## Firewall/IDS Evasion

**Fragment packets:**
\`\`\`
nmap -f 192.168.1.1
\`\`\`

**Decoy scan:**
\`\`\`
nmap -D RND:10 192.168.1.1
\`\`\`

**Idle scan:**
\`\`\`
nmap -sI zombie.com 192.168.1.1
\`\`\``
  },
  'Masscan Cheatsheet': {
    addition: `

## Basic Usage

**Scan all ports on a target:**
\`\`\`
masscan 192.168.1.0/24 -p0-65535
\`\`\`

**Fast full port scan:**
\`\`\`
masscan 10.0.0.0/8 -p0-65535 --rate 100000
\`\`\`

**Scan specific ports:**
\`\`\`
masscan 192.168.1.0/24 -p 80,443,8080
\`\`\`

## Advanced Options

**Rate limiting (packets/second):**
\`\`\`
masscan 192.168.1.0/24 -p0-65535 --rate 10000
\`\`\`

**Probe types:**
\`\`\`
masscan 192.168.1.0/24 -p0-65535 --probe tcp
\`\`\`

## Output

**Save results:**
\`\`\`
masscan 192.168.1.0/24 -p0-65535 -oL results.txt
\`\`\`

**JSON output:**
\`\`\`
masscan 192.168.1.0/24 -p0-65535 -oJ results.json
\`\`\`

## Key Differences from Nmap

- Masscan is 10x+ faster for full port scans
- Designed for scanning large ranges
- Uses custom TCP/IP stack
- Better for wide-range reconnaissance
- Less detailed service info (use nmap for details)`
  },
  'Sqlmap Cheatsheet': {
    addition: `

## Basic SQL Injection Testing

**Simple parameter test:**
\`\`\`
sqlmap -u "http://target.com/page.php?id=1"
\`\`\`

**With custom user-agent:**
\`\`\`
sqlmap -u "http://target.com/page.php?id=1" -a "Mozilla/5.0..."
\`\`\`

## Advanced Options

**Specify injection point:**
\`\`\`
sqlmap -u "http://target.com/page.php?id=1*" --technique=TIME
\`\`\`

**Try all techniques:**
\`\`\`
sqlmap -u "http://target.com/page.php?id=1" --technique=BEUSTQ
\`\`\`

## Database Enumeration

**List databases:**
\`\`\`
sqlmap -u "http://target.com/page.php?id=1" --dbs
\`\`\`

**List tables:**
\`\`\`
sqlmap -u "http://target.com/page.php?id=1" -D database_name --tables
\`\`\`

**Dump data:**
\`\`\`
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --dump
\`\`\`

## Batch Mode

**Non-interactive (automatic answers):**
\`\`\`
sqlmap -u "http://target.com/page.php?id=1" --batch --banner
\`\`\`

## POST Data

**Test POST parameters:**
\`\`\`
sqlmap -u "http://target.com/login.php" --data="user=admin&pass=admin"
\`\`\`

## Output

**Save session for resume:**
\`\`\`
sqlmap -u "http://target.com/page.php?id=1" -s session.sqlite
\`\`\`

**Verbose output:**
\`\`\`
sqlmap -u "http://target.com/page.php?id=1" -v 3
\`\`\``
  }
};

console.log('Sample expansions created for:');
Object.keys(expansions).forEach(title => {
  console.log(`✓ ${title}`);
});
