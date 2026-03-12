<#
.SYNOPSIS
    Bootstrap script for Kali Tools Suite on Windows.

.DESCRIPTION
    Creates C:\tools\ (or a custom path), downloads key tool archives/installers,
    adds tool directories to the user PATH, and prints a sanity-check summary.

    Must be run from an ELEVATED PowerShell prompt (Run as Administrator).
    After running, open a NEW PowerShell window for PATH changes to take effect.

.PARAMETER ToolsRoot
    Root directory for all security tools. Default: C:\tools

.EXAMPLE
    .\setup-kali-tools.ps1
    .\setup-kali-tools.ps1 -ToolsRoot D:\SecurityTools

.NOTES
    After this script completes:
      1. Open a NEW PowerShell window
      2. Extract sqlmap-master.zip  -> C:\tools\sqlmap\
      3. Extract gobuster zip       -> C:\tools\gobuster\  (gobuster.exe should be in root)
      4. Run the Nmap installer     -> C:\tools\nmap\nmap-setup-latest.exe
      5. Follow C:\tools\<name>\README.txt for tools that need manual install
      6. Run: python main.py
#>

Param(
    [string]$ToolsRoot = "C:\tools"
)

# ============================================================
# Helpers
# ============================================================

function Write-Step {
    param([string]$Msg)
    Write-Host ""`n[*] $Msg" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Msg)
    Write-Host "    [+] $Msg" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Msg)
    Write-Host "    [!] $Msg" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Msg)
    Write-Host "    [-] $Msg" -ForegroundColor Red
}

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-OK "Created $Path"
    } else {
        Write-Host "    [=] Exists: $Path" -ForegroundColor DarkGray
    }
}

function Download-IfMissing {
    param(
        [string]$Url,
        [string]$Destination,
        [string]$Label
    )
    if (Test-Path -LiteralPath $Destination) {
        Write-Host "    [=] Already downloaded: $Label" -ForegroundColor DarkGray
        return $true
    }
    Write-Warn "Downloading $Label ..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -TimeoutSec 120
        Write-OK "Saved to $Destination"
        return $true
    } catch {
        Write-Fail "Failed to download $Label : $_"
        Write-Fail "  Manual URL: $Url"
        return $false
    }
}

function Add-ToUserPath {
    param([string[]]$Paths)
    $current = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $parts   = ($current -split ';') | Where-Object { $_ -ne '' } | ForEach-Object { $_.TrimEnd('\') }
    $changed = $false
    foreach ($p in $Paths) {
        $p = $p.TrimEnd('\')
        if ($p -and -not ($parts -contains $p)) {
            $parts  += $p
            $changed = $true
            Write-OK "Added to user PATH: $p"
        } else {
            Write-Host "    [=] Already in PATH: $p" -ForegroundColor DarkGray
        }
    }
    if ($changed) {
        [System.Environment]::SetEnvironmentVariable("Path", ($parts -join ';'), "User")
        # Also update the current session
        $env:PATH = ($parts -join ';')
    }
}

function Write-ManualReadme {
    param(
        [string]$Folder,
        [string]$ToolName,
        [string]$Url,
        [string]$Notes = ""
    )
    $readmePath = Join-Path $Folder "README.txt"
    if (-not (Test-Path -LiteralPath $readmePath)) {
        $content = @"
$ToolName — Manual Installation Required
==========================================

Download URL:
  $Url

Install steps:
  1. Download the installer / archive from the URL above.
  2. Extract or install to this folder: $Folder
  3. Ensure the main executable is in this folder (or a subfolder that is on PATH).
  4. Test from a new PowerShell window.

$Notes
"@
        $content | Out-File -FilePath $readmePath -Encoding UTF8
        Write-OK "Created README: $readmePath"
    }
}

# ============================================================
# 1. Banner
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  Kali Tools Suite — Windows Setup Script" -ForegroundColor Magenta
Write-Host "  Tools root: $ToolsRoot" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

# ============================================================
# 2. Check elevation
# ============================================================

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Warn "Not running as Administrator. Some steps (Nmap install, system PATH) may fail."
    Write-Warn "Re-run with: Start-Process powershell -Verb RunAs"
}

# ============================================================
# 3. Create directory structure
# ============================================================

Write-Step "Creating tool directories under $ToolsRoot"

$dirs = @{
    "nmap"        = Join-Path $ToolsRoot "nmap"
    "sqlmap"      = Join-Path $ToolsRoot "sqlmap"
    "gobuster"    = Join-Path $ToolsRoot "gobuster"
    "nikto"       = Join-Path $ToolsRoot "nikto"
    "hashcat"     = Join-Path $ToolsRoot "hashcat"
    "john"        = Join-Path $ToolsRoot "john"
    "hydra"       = Join-Path $ToolsRoot "hydra"
    "medusa"      = Join-Path $ToolsRoot "medusa"
    "metasploit"  = Join-Path $ToolsRoot "metasploit"
    "nuclei"      = Join-Path $ToolsRoot "nuclei"
    "theharvester"= Join-Path $ToolsRoot "theharvester"
    "wordlists"   = Join-Path $ToolsRoot "wordlists"
}

Ensure-Dir -Path $ToolsRoot
foreach ($kv in $dirs.GetEnumerator()) {
    Ensure-Dir -Path $kv.Value
}

# ============================================================
# 4. Download tools
# ============================================================

Write-Step "Downloading available Windows builds"

# --- Nmap ---
$nmapExe = Join-Path $dirs["nmap"] "nmap-setup-latest.exe"
Download-IfMissing `
    -Url         "https://nmap.org/dist/nmap-7.95-setup.exe" `
    -Destination $nmapExe `
    -Label       "Nmap 7.95 installer"
Write-Warn "Nmap: run $nmapExe manually to complete installation."

# --- sqlmap ---
$sqlmapZip = Join-Path $dirs["sqlmap"] "sqlmap-master.zip"
$sqlmapDir = Join-Path $dirs["sqlmap"] "sqlmap-master"
Download-IfMissing `
    -Url         "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip" `
    -Destination $sqlmapZip `
    -Label       "sqlmap (zip)"

if ((Test-Path $sqlmapZip) -and (-not (Test-Path $sqlmapDir))) {
    Write-Warn "Extracting sqlmap ..."
    try {
        Expand-Archive -Path $sqlmapZip -DestinationPath $dirs["sqlmap"] -Force
        Write-OK "Extracted to $sqlmapDir"
    } catch {
        Write-Fail "Auto-extract failed. Extract manually: $sqlmapZip -> $($dirs['sqlmap'])"
    }
}

# Create sqlmap.bat wrapper
$sqlmapBat = Join-Path $dirs["sqlmap"] "sqlmap.bat"
if (-not (Test-Path $sqlmapBat)) {
    $batContent = "@echo off`r`npython `"$sqlmapDir\sqlmap.py`" %*"
    $batContent | Out-File -FilePath $sqlmapBat -Encoding ASCII
    Write-OK "Created sqlmap.bat wrapper: $sqlmapBat"
}

# --- Gobuster ---
$gobusterZip = Join-Path $dirs["gobuster"] "gobuster-windows-amd64.zip"
Download-IfMissing `
    -Url         "https://github.com/OJ/gobuster/releases/latest/download/gobuster-windows-amd64.zip" `
    -Destination $gobusterZip `
    -Label       "Gobuster (Windows amd64)"

if ((Test-Path $gobusterZip) -and (-not (Test-Path (Join-Path $dirs["gobuster"] "gobuster.exe")))) {
    Write-Warn "Extracting gobuster ..."
    try {
        Expand-Archive -Path $gobusterZip -DestinationPath $dirs["gobuster"] -Force
        Write-OK "gobuster.exe extracted to $($dirs['gobuster'])"
    } catch {
        Write-Fail "Auto-extract failed. Extract manually: $gobusterZip -> $($dirs['gobuster'])"
    }
}

# --- Nuclei ---
$nucleiZip = Join-Path $dirs["nuclei"] "nuclei-windows-amd64.zip"
Download-IfMissing `
    -Url         "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_windows_amd64.zip" `
    -Destination $nucleiZip `
    -Label       "Nuclei (Windows amd64)"

if ((Test-Path $nucleiZip) -and (-not (Test-Path (Join-Path $dirs["nuclei"] "nuclei.exe")))) {
    try {
        Expand-Archive -Path $nucleiZip -DestinationPath $dirs["nuclei"] -Force
        Write-OK "nuclei.exe extracted to $($dirs['nuclei'])"
    } catch {
        Write-Fail "Auto-extract failed: $nucleiZip"
    }
}

# --- SecLists wordlist (common.txt) ---
$commonWordlist = Join-Path $dirs["wordlists"] "common.txt"
Download-IfMissing `
    -Url         "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" `
    -Destination $commonWordlist `
    -Label       "SecLists common.txt wordlist"

# --- Tools requiring manual install: write README hints ---
Write-Step "Writing install hints for tools that need manual steps"

Write-ManualReadme -Folder $dirs["nikto"] `
    -ToolName "Nikto" `
    -Url      "https://github.com/sullo/nikto" `
    -Notes    "Requires Perl (https://strawberryperl.com/).`n`nSteps:`n  1. Install Strawberry Perl`n  2. git clone https://github.com/sullo/nikto.git $($dirs['nikto'])`n  3. Create nikto.bat in this folder:`n       @echo off`n       perl $($dirs['nikto'])\program\nikto.pl %*"

Write-ManualReadme -Folder $dirs["hashcat"] `
    -ToolName "Hashcat" `
    -Url      "https://hashcat.net/hashcat/" `
    -Notes    "Download the Windows binaries zip. Extract hashcat.exe to this folder."

Write-ManualReadme -Folder $dirs["john"] `
    -ToolName "John the Ripper" `
    -Url      "https://www.openwall.com/john/" `
    -Notes    "Download the Windows build. Extract john.exe (from run\john.exe) to this folder."

Write-ManualReadme -Folder $dirs["hydra"] `
    -ToolName "THC-Hydra" `
    -Url      "https://github.com/vanhauser-thc/thc-hydra" `
    -Notes    "Hydra is primarily Linux. Recommended: install via WSL2 (wsl --install, then sudo apt install hydra).`nAlternatively search GitHub for Windows pre-built releases."

Write-ManualReadme -Folder $dirs["medusa"] `
    -ToolName "Medusa" `
    -Url      "https://github.com/jmk-foofus/medusa" `
    -Notes    "Medusa is primarily Linux. Recommended: install via WSL2 (sudo apt install medusa)."

Write-ManualReadme -Folder $dirs["metasploit"] `
    -ToolName "Metasploit Framework" `
    -Url      "https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/" `
    -Notes    "Download the Windows installer from Rapid7. Run as Administrator.`nInstalls msfconsole and msfvenom to C:\metasploit-framework\bin\ (auto-added to PATH by installer)."

# ============================================================
# 5. PATH update
# ============================================================

Write-Step "Updating user PATH"

$pathDirs = @(
    $ToolsRoot,
    $dirs["nmap"],
    $dirs["sqlmap"],
    $dirs["gobuster"],
    $dirs["nuclei"],
    $dirs["nikto"],
    $dirs["hashcat"],
    $dirs["john"],
    $dirs["wordlists"]
)

Add-ToUserPath -Paths $pathDirs

# ============================================================
# 6. pip install Python-only tools
# ============================================================

Write-Step "Installing Python-based tools via pip"

$pipPackages = @(
    "theHarvester",
    "sherlock-project",
    "sublist3r",
    "wafw00f",
    "dnsrecon",
    "spiderfoot"
)

$pythonOk = (Get-Command python -ErrorAction SilentlyContinue) -ne $null
if ($pythonOk) {
    foreach ($pkg in $pipPackages) {
        Write-Host "    pip install $pkg" -ForegroundColor DarkGray
        try {
            & python -m pip install --quiet --upgrade $pkg 2>&1 | Out-Null
            Write-OK "$pkg installed/updated"
        } catch {
            Write-Fail "Failed to pip install $pkg : $_"
        }
    }
} else {
    Write-Fail "Python not found on PATH — skipping pip installs."
    Write-Fail "Install Python from https://www.python.org/downloads/ (tick 'Add to PATH'), then re-run."
}

# ============================================================
# 7. Sanity check
# ============================================================

Write-Step "Sanity check — testing key commands"
Write-Warn "Note: some commands may not appear until you open a NEW PowerShell window."
Write-Host ""

$checks = @(
    @{ Cmd = "python";    Args = "--version";  Label = "Python" },
    @{ Cmd = "pip";       Args = "--version";  Label = "pip" },
    @{ Cmd = "git";       Args = "--version";  Label = "Git" },
    @{ Cmd = "nmap";      Args = "--version";  Label = "Nmap" },
    @{ Cmd = "sqlmap";    Args = "--version";  Label = "sqlmap (.bat)" },
    @{ Cmd = "gobuster";  Args = "--help";     Label = "Gobuster" },
    @{ Cmd = "nuclei";    Args = "-version";   Label = "Nuclei" },
    @{ Cmd = "theharvester"; Args = "-h";      Label = "theHarvester" },
    @{ Cmd = "wafw00f";   Args = "--version";  Label = "wafw00f" },
    @{ Cmd = "msfconsole";Args = "--version";  Label = "Metasploit" }
)

$found = 0
$missing = @()

foreach ($c in $checks) {
    $cmdObj = Get-Command $c.Cmd -ErrorAction SilentlyContinue
    if ($cmdObj) {
        $found++
        Write-OK "$($c.Label.PadRight(20)) found at $($cmdObj.Source)"
    } else {
        Write-Fail "$($c.Label.PadRight(20)) NOT FOUND"
        $missing += $c.Label
    }
}

# ============================================================
# 8. Summary
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  Setup complete: $found / $($checks.Count) tools found" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Warn "Still missing (manual steps required):"
    $missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "  See README.txt in each tool folder under $ToolsRoot for install steps." -ForegroundColor DarkGray
    Write-Host "  See the project README.md Section 4 for full download links." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Open a NEW PowerShell window (PATH changes need a fresh session)"
Write-Host "  2. Run the Nmap installer if not already done: $($dirs['nmap'])\nmap-setup-latest.exe"
Write-Host "  3. cd into your Kali-tools repo and activate your venv:"
Write-Host "       .\venv\Scripts\Activate.ps1"
Write-Host "       pip install -r requirements.txt"
Write-Host "  4. Launch: python main.py"
Write-Host ""
