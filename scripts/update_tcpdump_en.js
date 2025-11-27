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

const englishContent = `# Tcpdump - Network Traffic Analyzer

## Basic Usage

**Capture packets on interface:**
\`\`\`bash
tcpdump -i eth0
\`\`\`

**Capture and save to file:**
\`\`\`bash
tcpdump -i eth0 -w capture.pcap
\`\`\`

**Read from file:**
\`\`\`bash
tcpdump -r capture.pcap
\`\`\`

**Verbose mode:**
\`\`\`bash
tcpdump -i eth0 -v
tcpdump -i eth0 -vv
\`\`\`

**Don't resolve hostnames (faster):**
\`\`\`bash
tcpdump -i eth0 -n
\`\`\`

**Don't resolve ports:**
\`\`\`bash
tcpdump -i eth0 -nn
\`\`\`

## Filtering

**By Host:**
\`\`\`bash
tcpdump host 192.168.1.1
\`\`\`

**By Source/Destination:**
\`\`\`bash
tcpdump src 192.168.1.1
tcpdump dst 192.168.1.1
\`\`\`

**By Network:**
\`\`\`bash
tcpdump net 192.168.1.0/24
\`\`\`

**By Port:**
\`\`\`bash
tcpdump port 80
tcpdump port 443
\`\`\`

**By Protocol:**
\`\`\`bash
tcpdump tcp
tcpdump udp
tcpdump icmp
\`\`\`

## Advanced Filtering

**Logical Operators:**
\`\`\`bash
tcpdump 'src 192.168.1.1 and port 80'
tcpdump 'tcp or udp'
tcpdump 'not arp'
\`\`\`

**Packet Size (Snaplen):**
\`\`\`bash
tcpdump -i eth0 -s 0
\`\`\`
*Capture full packet (default in newer versions).*

**Limit Packet Count:**
\`\`\`bash
tcpdump -i eth0 -c 100
\`\`\`
*Stop after 100 packets.*

**Display ASCII:**
\`\`\`bash
tcpdump -A
\`\`\`

**Display HEX and ASCII:**
\`\`\`bash
tcpdump -X
\`\`\`

## Common Scenarios

**HTTP Traffic:**
\`\`\`bash
tcpdump -i eth0 -A port 80
\`\`\`

**DNS Traffic:**
\`\`\`bash
tcpdump -i eth0 port 53
\`\`\`

**SSH Traffic:**
\`\`\`bash
tcpdump -i eth0 port 22
\`\`\`

**Detect SYN Scan:**
\`\`\`bash
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0'
\`\`\`

**Detect HTTP GET:**
\`\`\`bash
tcpdump -i eth0 -A | grep "GET /"
\`\`\`

## BPF (Berkeley Packet Filter) Syntax

**Primitives:**
\`\`\`
host        # Hostname or IP
net         # Network address
port        # Port number
portrange   # Port range
src         # Source
dst         # Destination
proto       # Protocol (tcp, udp, icmp, etc.)
\`\`\`

**Qualifiers:**
\`\`\`
tcp         # TCP protocol
udp         # UDP protocol
icmp        # ICMP protocol
ip          # IPv4
ip6         # IPv6
arp         # ARP
ether       # Ethernet
vlan        # VLAN tagged
\`\`\`

**Operators:**
\`\`\`
and (&&)    # Logical AND
or (||)     # Logical OR
not (!)     # Logical NOT
\`\`\`

**Examples:**
\`\`\`
tcp and port 80
not arp and not icmp
host 192.168.1.1 and (port 80 or port 443)
\`\`\`

## Tips

**Interface list:**
\`\`\`bash
tcpdump -D
\`\`\`

**BPF syntax check:**
\`\`\`bash
tcpdump -d 'tcp port 80'
\`\`\`

**Packet count:**
\`\`\`bash
tcpdump -r capture.pcap | wc -l
\`\`\`

**File info:**
\`\`\`bash
tcpdump -r capture.pcap -nn -c 1
\`\`\`

**Convert to text:**
\`\`\`bash
tcpdump -r capture.pcap -nn -tttt > capture.txt
\`\`\`

**Split by protocol:**
\`\`\`bash
tcpdump -r capture.pcap 'tcp' -w tcp.pcap
tcpdump -r capture.pcap 'udp' -w udp.pcap
\`\`\`
`;

async function updateTcpdump() {
    try {
        await dbConnect();
        console.log('Connected to DB. Updating Tcpdump English content...');

        const result = await Cheatsheet.updateOne(
            { 'title.tr': /tcpdump/i },
            { $set: { 'description.en': englishContent } }
        );

        console.log(`Update result:`, result);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

updateTcpdump();
