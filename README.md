# Kali Tools Suite — Windows GUI

![Kali Tools Suite](Tools.png)

A unified PyQt5 desktop application that wraps a curated collection of Kali-style security tools into a clean, phase-oriented workflow — all runnable from a single Windows GUI without touching the command line mid-test.

```
Reconnaissance  →  Scanning  →  Vulnerability Assessment  →  Exploitation  →  Reporting
```

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Quick Start](#2-quick-start)
3. [Full Installation (step by step)](#3-full-installation-step-by-step)
4. [External Tools — Binary Dependencies](#4-external-tools--binary-dependencies)
5. [Plugin Catalogue](#5-plugin-catalogue)
6. [Running the GUI](#6-running-the-gui)
7. [Full Pentest Wizard](#7-full-pentest-wizard)
8. [Using the PowerShell Setup Script](#8-using-the-powershell-setup-script)
9. [Troubleshooting](#9-troubleshooting)
10. [Contributing](#10-contributing)
11. [Disclaimer](#11-disclaimer)

---

## 1. Prerequisites

### 1.1 Operating System

- Windows 10 or Windows 11 (64-bit)
- PowerShell 5.1+ (ships with both — press Win+X → "Windows PowerShell")
- Internet access (first-time tool downloads)

### 1.2 Python 3.10+

**Download:** https://www.python.org/downloads/

During the installer:
- ✅ Check **"Add python.exe to PATH"** (critical — do this before clicking Install)
- Choose the default install location

Verify after install (new PowerShell window):

```powershell
python --version    # should print Python 3.10.x or higher
pip --version
```

### 1.3 Git for Windows

**Download:** https://git-scm.com/download/win

- Default options are fine
- Ensures `git` is on your PATH for cloning / pulling updates

Verify:

```powershell
git --version
```

---

## 2. Quick Start

For users who just want to get running fast:

```powershell
# 1 — Clone the repo
git clone https://github.com/zy538324/Kali-tools.git
cd Kali-tools

# 2 — Run the bootstrap script (elevated prompt)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup-kali-tools.ps1

# 3 — Create and activate a venv
python -m venv venv
.\venv\Scripts\Activate.ps1

# 4 — Install Python dependencies
pip install -r requirements.txt

# 5 — Launch
python main.py
```

> The setup script creates `C:\tools\`, downloads several binaries, and adds them to your user PATH. Open a **new** PowerShell window after running it.

---

## 3. Full Installation (step by step)

### Step 1 — Install Python

1. Go to https://www.python.org/downloads/ and download the latest 3.x installer
2. Run the installer — **tick "Add python.exe to PATH"** before proceeding
3. Open a new PowerShell window and run `python --version` to confirm

### Step 2 — Install Git

1. Go to https://git-scm.com/download/win and run the installer
2. Accept defaults throughout
3. Confirm with `git --version`

### Step 3 — Clone this repository

```powershell
cd C:\Users\<YourName>\Documents\GitHub
git clone https://github.com/zy538324/Kali-tools.git
cd Kali-tools
```

### Step 4 — Run the setup script

Right-click PowerShell → "Run as Administrator", then:

```powershell
cd C:\Users\<YourName>\Documents\GitHub\Kali-tools
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup-kali-tools.ps1
```

This script:
- Creates `C:\tools\` and subdirectories for each binary tool
- Downloads Nmap installer, sqlmap zip, and Gobuster binary
- Leaves `README.txt` hints in folders for tools requiring manual install
- Adds `C:\tools` and subfolders to your **user PATH**
- Prints a sanity check showing which tools are found

Then open a **new** PowerShell window to pick up the PATH changes.

### Step 5 — Install external tools manually (where needed)

See [Section 4](#4-external-tools--binary-dependencies) for each tool's download and install steps.

### Step 6 — Create a Python virtual environment

```powershell
cd C:\Users\<YourName>\Documents\GitHub\Kali-tools
python -m venv venv
.\venv\Scripts\Activate.ps1
```

You should see `(venv)` at the left of your prompt.

### Step 7 — Install Python packages

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

If `requirements.txt` is missing, install the baseline manually:

```powershell
pip install PyQt5 requests beautifulsoup4 python-nmap python-whois dnspython paramiko impacket shodan
```

### Step 8 — Launch

```powershell
python main.py
```

---

## 4. External Tools — Binary Dependencies

Many plugins are **pure Python** (no external binary needed). Some plugins call external binaries via subprocess or `python-nmap`. The table below maps each binary to the plugins that use it, so you know exactly what to install and what breaks without it.

### Dependency Overview

| Binary | Install Method | Download / Source | Used By (plugins) |
|---|---|---|---|
| **nmap** | Windows installer | https://nmap.org/download.html | `nmap_scan`, `nmap_scanner`, `nmap_vuln_scan`, `os_fingerprint`, `service_detect` |
| **sqlmap** | Python script (no build needed) | https://github.com/sqlmapproject/sqlmap | `sqlmap_exploit` |
| **gobuster** | Pre-built binary | https://github.com/OJ/gobuster/releases | `gobuster_scan`, `dirb_scan` |
| **nikto** | Perl script (needs Perl) | https://github.com/sullo/nikto | `nikto_scan` (Recon, Scanning, VA, Exploit phases) |
| **hashcat** | Pre-built binary | https://hashcat.net/hashcat/ | `hashcat_crack` |
| **john** (John the Ripper) | Pre-built binary | https://www.openwall.com/john/ | `john_crack` |
| **hydra** (THC-Hydra) | Build from source / WSL | https://github.com/vanhauser-thc/thc-hydra | `hydra_brute` |
| **medusa** | Build from source / WSL | https://github.com/jmk-foofus/medusa | `medusa_brute` |
| **metasploit** | Windows installer (Rapid7) | https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/ | `metasploit_run` |
| **nuclei** | Pre-built binary | https://github.com/projectdiscovery/nuclei/releases | `nuclei_scan` |
| **theharvester** | `pip install theHarvester` | https://github.com/laramies/theHarvester | `theharvester`, `theharvester_subdomains` |
| **sherlock** | `pip install sherlock-project` | https://github.com/sherlock-project/sherlock | `sherlock` |
| **sublist3r** | `pip install sublist3r` | https://github.com/aboul3la/Sublist3r | `sublist3r_scan` |
| **wafw00f** | `pip install wafw00f` | https://github.com/EnableSecurity/wafw00f | `wafw00f`, `wafw00f_scan` |
| **whatweb** | Ruby gem / WSL | https://github.com/urbanadventurer/WhatWeb | `whatweb`, `whatweb_scan` |
| **dnsenum** | Perl script / WSL | https://github.com/fwaeytens/dnsenum | `dnsenum` |
| **dnsrecon** | `pip install dnsrecon` | https://github.com/darkoperator/dnsrecon | `dnsrecon_advanced` |
| **spiderfoot** | `pip install spiderfoot` | https://github.com/smicallef/spiderfoot | `spiderfoot_scan` |
| **Perl** | Windows installer | https://strawberryperl.com/ | Required by nikto, dnsenum |
| **Wireshark / tshark** | Windows installer | https://www.wireshark.org/download.html | `traffic_capture` |
| **Burp Suite** (optional) | Installer | https://portswigger.net/burp/community-download | Can act as a proxy for SQLi / XSS tools |

### Tools installable with `pip` (inside your venv)

Run these once after activating your venv:

```powershell
pip install theHarvester sherlock-project sublist3r wafw00f dnsrecon spiderfoot
```

### Nmap — Step by Step

1. Download the `.exe` installer from https://nmap.org/download.html
2. Run it — default install to `C:\Program Files (x86)\Nmap\`
3. Nmap's installer adds itself to PATH automatically
4. Verify: `nmap --version`

The `setup-kali-tools.ps1` script downloads the Nmap installer to `C:\tools\nmap\nmap-setup-latest.exe` — you still need to run it manually.

### sqlmap — Step by Step

1. The setup script downloads `sqlmap-master.zip` to `C:\tools\sqlmap\`
2. Extract it: right-click → "Extract All" → to `C:\tools\sqlmap\`
3. You should now have `C:\tools\sqlmap\sqlmap-master\sqlmap.py`
4. Create a wrapper: save as `C:\tools\sqlmap\sqlmap.bat`:
   ```bat
   @echo off
   python C:\tools\sqlmap\sqlmap-master\sqlmap.py %*
   ```
5. `C:\tools\sqlmap\` is already on your PATH after the setup script — verify:
   ```powershell
   sqlmap --version
   ```

### Gobuster — Step by Step

1. The setup script downloads the Windows zip to `C:\tools\gobuster\`
2. Extract it — you get `gobuster.exe` in that folder
3. Verify: `gobuster --help`

### Nikto — Step by Step

1. Install Strawberry Perl from https://strawberryperl.com/
2. Clone nikto: `git clone https://github.com/sullo/nikto.git C:\tools\nikto`
3. Test: `perl C:\tools\nikto\program\nikto.pl -h`
4. Add a wrapper `C:\tools\nikto\nikto.bat`:
   ```bat
   @echo off
   perl C:\tools\nikto\program\nikto.pl %*
   ```
5. Add `C:\tools\nikto\` to PATH manually or re-run the setup script with the nikto folder uncommented.

### Metasploit — Step by Step

1. Download the Windows installer from https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/
2. Run as Administrator — installs to `C:\metasploit-framework\`
3. Metasploit adds itself to PATH during install
4. Verify: `msfconsole --version`

### Hydra / Medusa on Windows

Both are primarily Linux tools. On Windows, the recommended approach is:

- **WSL2** (Windows Subsystem for Linux): `wsl --install` in an admin PowerShell, then `sudo apt install hydra medusa` inside WSL
- **Pre-compiled binaries** (community builds): search GitHub for `thc-hydra windows release`

The plugins detect the binary via `shutil.which("hydra")` / `shutil.which("medusa")` — as long as the binary is on PATH they will work.

---

## 5. Plugin Catalogue

All tools are loaded as YAML plugin definitions from each phase's `plugins/` directory. New tools can be added by dropping a new `.yaml` file there — no code changes required.

### 🔍 Reconnaissance (`Reconnaissance/kali_host/plugins/`)

| Plugin | Description | External Binary? |
|---|---|---|
| `whois_lookup` | WHOIS data for domains and IPs | None (pure Python) |
| `dns_recon` | A/AAAA/MX/NS/TXT/SOA/CNAME records | None |
| `dnsrecon_advanced` | Extended DNS enumeration | `dnsrecon` |
| `dnsenum` | DNS enumeration with zone transfer | `dnsenum` (Perl) |
| `subdomain_enum` | DNS brute-force + CT log search | None |
| `sublist3r_scan` | Passive subdomain enumeration | `sublist3r` |
| `port_scanner` | TCP port scanner (pure Python) | None |
| `nmap_scan` | Nmap wrapper | `nmap` |
| `nmap_scanner` | Nmap with OS/service detection | `nmap` |
| `ping_sweep` | ICMP ping sweep across a range | None |
| `tech_stack` | HTTP header / HTML tech fingerprint | None |
| `whatweb` / `whatweb_scan` | WhatWeb web fingerprinting | `whatweb` |
| `ssl_cert_info` | SSL certificate details | None |
| `http_headers` | HTTP response header audit | None |
| `robots_sitemap` | robots.txt and sitemap.xml fetch | None |
| `shodan_recon` | Shodan host lookup (API key needed) | None (`pip install shodan`) |
| `ip_geo` | IP geolocation lookup | None |
| `cloud_detect` | Cloud provider detection | None |
| `wafw00f` / `wafw00f_scan` | WAF detection | `wafw00f` |
| `search_dorks` | Google dork search | None |
| `email_osint` | Email header / OSINT analysis | None |
| `email_pattern` | Email format pattern detection | None |
| `theharvester` / `theharvester_subdomains` | Email/domain harvesting | `theHarvester` |
| `sherlock` | Username social-media lookup | `sherlock` |
| `username_osint_plus` | Extended username OSINT | None |
| `spiderfoot_scan` | SpiderFoot OSINT scan | `spiderfoot` |
| `full_recon_profile` | Orchestrated multi-tool recon | Multiple |

### 📡 Scanning (`Scanning/scanning_host/plugins/`)

| Plugin | Description | External Binary? |
|---|---|---|
| `nmap_vuln_scan` | Nmap `--script vuln` scan | `nmap` |
| `nikto_scan` | Nikto web vulnerability scan | `nikto` (Perl) |
| `nuclei_scan` | Nuclei template scan | `nuclei` |
| `dirb_scan` | Web directory brute-force | `gobuster` |
| `gobuster_scan` | Gobuster directory/DNS/vhost scan | `gobuster` |
| `banner_grab` | TCP banner grabbing | None |
| `arp_scan` | ARP host discovery | None |
| `smb_enum` | SMB share/user enumeration | None |
| `snmp_enum` | SNMP community string enumeration | None |
| `ssh_probe` | SSH version and auth-method probe | None |
| `ftp_probe` | FTP banner and anon-login check | None |
| `rdp_probe` | RDP version / NLA detection | None |
| `ssl_vuln_scan` | SSL/TLS weakness check | None |
| `traceroute` | Network path trace | None |
| `udp_scan` | UDP port scan | None |
| `cve_lookup` | CVE NVD API lookup | None |
| `exploit_search` | ExploitDB / searchsploit lookup | None |
| `dependency_checker` | Python dependency audit | None |
| `full_scan_profile` | Orchestrated multi-tool scan | Multiple |

### 🧪 Vulnerability Assessment (`Vulnerability Assessment/va_host/plugins/`)

| Plugin | Description | External Binary? |
|---|---|---|
| `nikto_scan` | Nikto web scan | `nikto` |
| `ssl_check` / `tls_config_audit` | TLS version / cipher check | None |
| `sqli_scanner` | SQL injection quick check | None |
| `xss_scanner` | Reflected XSS check | None |
| `lfi_scanner` | Local file inclusion check | None |
| `cors_checker` | CORS misconfiguration check | None |
| `http_methods_checker` | Dangerous HTTP methods (PUT/DELETE) | None |
| `security_headers_audit` | Missing security headers check | None |
| `smb_vuln_check` | SMB vulnerability check | None |
| `smtp_probe` | SMTP open relay / user enum | None |
| `ssh_audit` | SSH weak algorithms check | None |
| `jwt_analyser` | JWT token weakness analysis | None |
| `session_token_analyser` | Session token entropy check | None |
| `cloud_exposure_checker` | Exposed cloud resources check | None |
| `exposed_files_checker` | .git / .env / backup file exposure | None |
| `default_creds_checker` | Default credentials quick test | None |
| `cve_lookup` | CVE lookup for detected services | None |
| `full_va_profile` | Orchestrated VA run | Multiple |

### 💀 Exploitation (`Exploitation/exploit_host/plugins/`)

| Plugin | Description | External Binary? |
|---|---|---|
| `default_creds` | 32 default credential pairs (HTTP/FTP/SSH/SNMP) | None |
| `sql_injection` | Error/Boolean/Time/UNION SQLi (pure Python) | None |
| `sqlmap_exploit` | sqlmap-backed SQL injection | `sqlmap` |
| `xss_scanner` | Reflected XSS with 15 payloads | None |
| `lfi_tester` | LFI path traversal tester | None |
| `vuln_scanner` | Generic web vulnerability scanner | None |
| `hydra_brute` | Hydra brute-force wrapper | `hydra` |
| `medusa_brute` | Medusa brute-force wrapper | `medusa` |
| `hashcat_crack` | Hashcat hash cracking | `hashcat` |
| `john_crack` | John the Ripper hash cracking | `john` |
| `gobuster_scan` | Gobuster directory brute-force | `gobuster` |
| `nikto_scan` | Nikto web scanner | `nikto` |
| `searchsploit_lookup` | ExploitDB lookup | `searchsploit` (Metasploit) |
| `metasploit_run` | Metasploit module runner | `msfconsole` |
| `smb_exploit` | SMB exploit wrapper | None |
| `rdp_exploit` | RDP exploit wrapper | None |
| `c2_beacon` | C2 beacon stub | None |
| `payload_generator` | msfvenom payload generator | `msfvenom` (Metasploit) |
| `exploit_chain` | Chained exploit runner | Multiple |
| `persistence` | Persistence mechanism setup | None |
| `privilege_escalation` | PrivEsc check runner | None |
| `file_exfiltration` | File exfiltration test | None |
| `traffic_capture` | Packet capture (tshark) | `tshark` (Wireshark) |
| `log_cleaner` | Log entry removal | None |
| `network_pivot` | Pivot / tunnel setup | None |
| `linpeas_scan` | LinPEAS privilege escalation | `linpeas.sh` |
| `proof_of_access` | Access proof screenshot/data | None |
| `report` | Per-tool HTML report generation | None |

---

## 6. Running the GUI

### Activate venv and launch

```powershell
cd C:\Users\<YourName>\Documents\GitHub\Kali-tools
.\venv\Scripts\Activate.ps1
python main.py
```

### Main window layout

```
┌─────────────────────────────────────────────────────────────┐
│  Kali Tools Suite                                           │
├───────────┬─────────────────────────────────────────────────┤
│           │                                                 │
│ ⬢ Full    │                                                 │
│   Pentest │           Phase Content Panel                   │
│           │   (tool tree / param form / live output)        │
│ 🔍 Recon  │                                                 │
│ 📡 Scan   │                                                 │
│ 🧪 VA     │                                                 │
│ 💀 Exploit│                                                 │
│ 📋 Report │                                                 │
│           │                                                 │
└───────────┴─────────────────────────────────────────────────┘
```

- Click a phase in the sidebar to switch to it
- Each phase shows its tool tree on the left, parameter form in the centre, and live output at the bottom
- Double-click a tool in the tree (or click Run) to execute it

---

## 7. Full Pentest Wizard

Click **⬢ Full Pentest** in the sidebar.

### 7.1 Global input fields

| Field | What to enter | Notes |
|---|---|---|
| **Target IP / Host** | `10.0.0.5` or `example.com` | **Required**. Used by all tools that don't have their own URL/domain |
| **Target URL** | `https://10.0.0.5` or `https://app.example.com` | For XSS, SQLi, tech stack. Auto-built as `http://<target>` if blank |
| **Domain** | `example.com` | For DNS / subdomain tools. Falls back to Target if blank |
| **Port Range** | `80,443,22` or `1-1024` | Defaults to top common ports |
| **Threads** | `10` | Concurrency for scanners |
| **Timeout (s)** | `10` | Per-request/scan timeout |
| **Username** | `admin` | Used by default-creds, hydra, medusa |
| **Password** | `password` | Used by auth tools |
| **Wordlist Path** | `C:\wordlists\common.txt` | Used by gobuster, dirb, brute-force tools |
| **API Key** | Shodan API key | Optional — only needed for Shodan recon |
| **Output Directory** | `C:\Users\You\Desktop\pentest_output` | Where reports / artifacts are saved |
| **Report Format** | HTML / PDF / TXT / JSON | Format for the auto-generated report |

### 7.2 Phase and tool selection

Below the global form, four cards (one per phase) each show:
- A **Select all** toggle for the whole phase
- A checkbox per tool — uncheck any you want to skip

Full pentest selected tools (defaults):
- **Recon:** WHOIS, DNS Recon, Subdomain Enum, Port Scanner, Tech Stack, SSL Cert
- **Scanning:** Nmap Full, Service Detection, OS Fingerprint, UDP Scan
- **VA:** Nikto, SSL/TLS Check, CVE Lookup, Vuln Summary
- **Exploit:** Default Creds, SQL Injection, XSS Scanner, Vuln Scanner

### 7.3 Running and output

1. Click **▶ Run Full Pentest**
2. Watch the live output pane — each tool prints its own start/result lines
3. Progress bar shows `<done>/<total>` tools
4. Each tool also prints the exact params it was called with (minus passwords) for easy debugging:
   ```
   [*] Running: SQL Injection (sql_injection)
       Params: {'url': 'http://10.252.10.240', 'method': 'GET', 'techniques': 'error,boolean,time,union', 'timeout': 10}
   ```
5. When complete, findings are sent to the Reporting panel, or saved to `Desktop\full_pentest_findings.json`

### 7.4 Cancelling

Click **■ Cancel** — the worker stops between tools as soon as possible. Any findings collected so far are still emitted.

---

## 8. Using the PowerShell Setup Script

File: `setup-kali-tools.ps1` (repo root)

### What it does

1. Creates `C:\tools\` and one subfolder per major binary tool
2. Downloads:
   - Nmap Windows installer → `C:\tools\nmap\nmap-setup-latest.exe` *(run it manually)*
   - sqlmap zip → `C:\tools\sqlmap\sqlmap-master.zip` *(extract manually)*
   - Gobuster Windows binary → `C:\tools\gobuster\gobuster-windows-amd64.zip` *(extract manually)*
3. Leaves `README.txt` in tool folders for those needing manual steps
4. Adds `C:\tools`, `C:\tools\nmap`, `C:\tools\sqlmap`, `C:\tools\gobuster` to your **user PATH**
5. Runs a sanity check (`python`, `git`, `nmap`, `sqlmap.py`, `gobuster`)

### Running it

```powershell
# Right-click PowerShell → Run as Administrator
cd C:\Users\<YourName>\Documents\GitHub\Kali-tools
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup-kali-tools.ps1
```

### Customising the install root

```powershell
.\setup-kali-tools.ps1 -ToolsRoot D:\SecurityTools
```

### After running

1. Open a **new** PowerShell window (PATH changes need a fresh session)
2. Extract downloaded archives manually (sqlmap, gobuster)
3. Run the Nmap installer manually
4. Verify: `nmap --version`, `gobuster --help`, `sqlmap --version`

---

## 9. Troubleshooting

### GUI crashes immediately / won't start

**Symptom:** `ModuleNotFoundError: No module named 'PyQt5'`

```powershell
.\venv\Scripts\Activate.ps1
pip install PyQt5
python main.py
```

**Symptom:** `python: command not found`

- Python is not on PATH. Reinstall Python, ticking "Add to PATH"
- Or add manually: Start → search "Environment Variables" → Edit PATH → add Python folder (e.g. `C:\Users\You\AppData\Local\Programs\Python\Python312\`)

**Symptom:** Blank window or the sidebar shows but no content loads

- Make sure you launch from the **repo root**, not a subfolder:
  ```powershell
  cd C:\Users\<YourName>\Documents\GitHub\Kali-tools
  python main.py
  ```

### A tool shows `[!] ... error: [Errno 2] No such file or directory`

The external binary is not installed or not on PATH.

1. Check which binary the tool needs in [Section 4](#4-external-tools--binary-dependencies)
2. Verify: `where nmap` / `where gobuster` / etc.
3. If nothing is printed, install the binary and check PATH:
   ```powershell
   # Check current PATH
   $env:PATH -split ';'
   
   # Temporarily add a path for testing
   $env:PATH += ";C:\tools\gobuster"
   gobuster --help
   ```

### Full Pentest: web tools scan the wrong target

- **Problem:** XSS / SQLi / tech stack hitting wrong URL
- **Fix:** Fill in the **Target URL** field explicitly, e.g. `https://10.252.10.240` or `http://app.example.com:8080`
- If you leave it blank, the wizard auto-builds `http://<Target IP/Host>` — useful for HTTP on port 80 but wrong for HTTPS or non-standard ports

### Full Pentest: `[ERROR] No host specified`

- One of the tools received an empty `target` or `url` param
- Ensure **Target IP / Host** is filled in before clicking Run
- Check the param line printed above each tool in the output pane for what was actually sent

### `InsecureRequestWarning` in output

```
InsecureRequestWarning: Unverified HTTPS request is being made...
```

This is a `urllib3` warning — not an error. Scans still run. It appears when a tool connects to an HTTPS target with a self-signed cert. You can suppress it by adding `urllib3.disable_warnings()` at the top of the relevant tool module, or ignore it.

### venv activation error: `cannot be loaded because running scripts is disabled`

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\venv\Scripts\Activate.ps1
```

### `git pull` not updating latest changes

```powershell
cd C:\Users\<YourName>\Documents\GitHub\Kali-tools
git fetch origin
git pull origin main
# Re-install any new Python deps
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Findings not appearing in Report panel

- The reporting page may not have fully loaded yet (lazy-loaded on first click)
- Click **📋 Report** in the sidebar at least once before running a full pentest
- If findings still don't appear, check the Desktop for `full_pentest_findings.json` and import it manually via the Report panel's import function

### Port scanner / Nmap shows no results

- Some Nmap features require **Administrator / elevated privileges** to send raw packets
- Run PowerShell as Administrator, then relaunch `python main.py`
- The pure-Python port scanner does not require elevation, but may be slower and less accurate than Nmap

---

## 10. Contributing

1. Fork the repo on GitHub
2. Create a feature branch: `git checkout -b feature/my-new-plugin`
3. Add your plugin YAML to the appropriate `plugins/` folder
4. If it needs a new Python tool module, add it under the relevant `*_host/tools/` directory
5. Test with `python main.py`
6. Submit a pull request with a short description

### Adding a new plugin

Each plugin is a YAML file with these required fields:

```yaml
tool_id: my_tool
name: My Tool
description: What it does
category: Web Exploitation
module_path: exploit_host.tools.my_tool
entry_function: run
params:
  - name: target
    label: "Target URL"
    param_type: string
    required: true
```

Drop the YAML into the correct `plugins/` folder and it will be discovered automatically on next launch.

---

## 11. Disclaimer

> **This tool suite is intended exclusively for authorised security testing and educational purposes.**
>
> You must have **explicit written permission** from the system owner before running any scans, enumeration, or exploitation modules against any target.
>
> Unauthorised use against systems you do not own or have permission to test is illegal in most jurisdictions (Computer Fraud and Abuse Act, Computer Misuse Act 1990, and equivalents worldwide).
>
> The authors and contributors accept no liability for misuse.
