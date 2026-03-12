"""
theHarvester - OSINT tool for gathering emails, subdomains, hosts, and IPs
Uses public sources like Google, Bing, DuckDuckGo, Shodan, etc.
"""
import subprocess
import json
import os
import re
import sys
import shutil
from typing import Dict, Any, Callable, List
from kali_host.core.api_keys import get_api_key_manager


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run theHarvester OSINT collection.
    
    Params:
        target: Domain to search (e.g., "example.com")
        sources: Data sources to use (comma-separated or 'all')
        limit: Limit search results (default: 500)
        dns_lookup: Perform DNS lookups on discovered hosts
        use_shodan: Use Shodan to query discovered hosts
        take_screenshots: Take screenshots of discovered websites
    """
    target = params.get("target", "")
    sources = params.get("sources", "all")
    limit = params.get("limit", 500)
    dns_lookup = params.get("dns_lookup", False)
    use_shodan = params.get("use_shodan", False)
    take_screenshots = params.get("take_screenshots", False)
    
    if not target:
        print("[ERROR] No target domain specified")
        return {"error": "No target domain specified"}
    
    results = {
        "target": target,
        "emails": [],
        "hosts": [],
        "ips": [],
        "asns": [],
        "urls": [],
        "interesting_urls": []
    }
    
    print(f"[*] theHarvester starting for: {target}")
    print(f"[*] Sources: {sources}")
    print(f"[*] Limit: {limit}")
    print("=" * 60)
    
    # Check for API keys if needed
    api_mgr = get_api_key_manager()
    if use_shodan:
        shodan_key = api_mgr.get_key("shodan")
        if shodan_key:
            os.environ["SHODAN_API_KEY"] = shodan_key
            print("[+] Using Shodan API key")
        else:
            print("[!] Warning: Shodan API key not configured")
            print("[*] Add key via Settings to enable Shodan queries")
    
    # Check if theHarvester is installed
    if not _check_theharvester_installed():
        print("[!] theHarvester not found. Installing...")
        if not _install_theharvester():
            print("[ERROR] Failed to install theHarvester")
            print("[*] Manual install: pip install theHarvester")
            return {"error": "theHarvester installation failed"}
    
    command_prefix = _resolve_theharvester_command()
    if not command_prefix:
        print("[ERROR] Could not find a runnable theHarvester command in this Python environment")
        print("[*] Try reinstalling in this venv: python -m pip install --upgrade theHarvester")
        return {"error": "theHarvester executable not found"}

    # Build theHarvester command
    cmd = [
        *command_prefix,
        "-d", target,
        "-b", sources,
        "-l", str(limit)
    ]
    
    if dns_lookup:
        cmd.append("-n")
    
    if use_shodan and api_mgr.has_key("shodan"):
        cmd.append("-s")
    
    if take_screenshots:
        cmd.append("-t")
    
    # Create temp directory for output
    output_dir = os.path.join(os.path.expanduser("~"), ".kali_tools_temp")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"theharvester_{target}")
    cmd.extend(["-f", output_file])
    
    print(f"[*] Running command: {' '.join(cmd)}")
    print()
    
    try:
        # Run theHarvester
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Stream output
        for line in iter(process.stdout.readline, ''):
            if is_cancelled and is_cancelled():
                process.terminate()
                print("\n[!] Scan cancelled")
                return results
            
            line = line.rstrip()
            if line:
                print(line)
                
                # Parse results in real-time
                _parse_output_line(line, results)
        
        process.wait()
        
        # Parse JSON output if available
        json_file = f"{output_file}.json"
        if os.path.exists(json_file):
            results = _parse_json_output(json_file, results)
        
        # Parse XML output as fallback
        xml_file = f"{output_file}.xml"
        if os.path.exists(xml_file) and not results.get("emails"):
            results = _parse_xml_output(xml_file, results)
        
    except FileNotFoundError:
        print("[ERROR] theHarvester command not found")
        print("[*] Install with: pip install theHarvester")
        return {"error": "theHarvester not installed"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}
    
    print("\n" + "=" * 60)
    print(f"[+] Emails found: {len(results.get('emails', []))}")
    print(f"[+] Hosts found: {len(results.get('hosts', []))}")
    print(f"[+] IPs found: {len(results.get('ips', []))}")
    print(f"[+] ASNs found: {len(results.get('asns', []))}")
    print(f"[+] URLs found: {len(results.get('urls', []))}")
    print("=" * 60)
    print("[*] theHarvester scan complete")
    
    return results


def _check_theharvester_installed() -> bool:
    """Check if theHarvester is installed."""
    return _resolve_theharvester_command() is not None


def _install_theharvester() -> bool:
    """Attempt to install theHarvester via pip."""
    try:
        print("[*] Installing theHarvester...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "theHarvester"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if _resolve_theharvester_command() is not None:
            print("[+] theHarvester installed successfully")
            return True

        print("[!] theHarvester package installed but command was not found")
        print("[*] This can happen if a non-official package was installed")
        return False
    except subprocess.CalledProcessError:
        return False


def _resolve_theharvester_command() -> List[str] | None:
    """Resolve a runnable theHarvester command from the active Python environment."""
    script_dir = os.path.dirname(sys.executable)
    if os.name == "nt":
        script_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
        candidates = [
            os.path.join(script_dir, "theHarvester.exe"),
            os.path.join(script_dir, "theHarvester.cmd"),
            os.path.join(script_dir, "theHarvester.bat"),
            os.path.join(script_dir, "theHarvester"),
        ]
    else:
        candidates = [os.path.join(script_dir, "theHarvester")]

    for candidate in candidates:
        if os.path.exists(candidate):
            return [candidate]

    resolved = shutil.which("theHarvester")
    if resolved:
        return [resolved]

    # Fallback when package is importable but script entrypoint is unavailable.
    for module_name in ["theHarvester", "theHarvester.theHarvester"]:
        try:
            subprocess.run(
                [sys.executable, "-m", module_name, "-h"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            return [sys.executable, "-m", module_name]
        except (subprocess.TimeoutExpired, OSError):
            continue

    return None


def _parse_output_line(line: str, results: Dict) -> None:
    """Parse theHarvester output line and extract data."""
    # Email pattern
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', line)
    if email_match:
        email = email_match.group(0)
        if email not in results["emails"]:
            results["emails"].append(email)
    
    # IP pattern
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
    if ip_match:
        ip = ip_match.group(0)
        if ip not in results["ips"] and not ip.startswith("127."):
            results["ips"].append(ip)
    
    # URL pattern
    url_match = re.search(r'https?://[^\s]+', line)
    if url_match:
        url = url_match.group(0)
        if url not in results["urls"]:
            results["urls"].append(url)


def _parse_json_output(json_file: str, results: Dict) -> Dict:
    """Parse theHarvester JSON output."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        results["emails"] = list(set(data.get("emails", [])))
        results["hosts"] = list(set(data.get("hosts", [])))
        results["ips"] = list(set(data.get("ips", [])))
        results["asns"] = list(set(data.get("asns", [])))
        results["urls"] = list(set(data.get("urls", [])))
        results["interesting_urls"] = list(set(data.get("interesting_urls", [])))
        
        print(f"\n[+] Parsed JSON output from {json_file}")
        
    except Exception as e:
        print(f"[!] Error parsing JSON: {e}")
    
    return results


def _parse_xml_output(xml_file: str, results: Dict) -> Dict:
    """Parse theHarvester XML output as fallback."""
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for email in root.findall(".//email"):
            if email.text and email.text not in results["emails"]:
                results["emails"].append(email.text)
        
        for host in root.findall(".//host"):
            if host.text and host.text not in results["hosts"]:
                results["hosts"].append(host.text)
        
        for ip in root.findall(".//ip"):
            if ip.text and ip.text not in results["ips"]:
                results["ips"].append(ip.text)
        
        print(f"\n[+] Parsed XML output from {xml_file}")
        
    except Exception as e:
        print(f"[!] Error parsing XML: {e}")
    
    return results
