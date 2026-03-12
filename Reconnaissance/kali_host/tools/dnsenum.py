"""
DNSenum - Advanced DNS enumeration tool
Performs zone transfers, subdomain brute-forcing, Google scraping, and more
"""
import subprocess
import os
import re
from typing import Dict, Any, Callable


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run DNSenum for comprehensive DNS enumeration.
    
    Params:
        target: Target domain to enumerate
        nameserver: DNS server to use for queries
        threads: Number of threads for subdomain brute-forcing
        subdomains: Number of subdomains to try (from wordlist)
        zone_transfer: Attempt zone transfer
        google_scrape: Use Google for subdomain discovery
        whois: Perform WHOIS queries
        reverse_lookup: Perform reverse lookups on discovered IPs
    """
    target = params.get("target", "")
    nameserver = params.get("nameserver", "")
    threads = params.get("threads", 5)
    subdomains = params.get("subdomains", 1000)
    zone_transfer = params.get("zone_transfer", True)
    google_scrape = params.get("google_scrape", True)
    whois = params.get("whois", False)
    reverse_lookup = params.get("reverse_lookup", True)
    
    if not target:
        print("[ERROR] No target domain specified")
        return {"error": "No target domain specified"}
    
    results = {
        "target": target,
        "name_servers": [],
        "mx_records": [],
        "subdomains": [],
        "ip_addresses": [],
        "zone_transfer_success": False
    }
    
    print(f"[*] DNSenum starting for: {target}")
    print(f"[*] Threads: {threads}")
    print(f"[*] Subdomain attempts: {subdomains}")
    print("=" * 60)
    
    # Check if dnsenum is installed
    if not _check_dnsenum_installed():
        print("[ERROR] DNSenum not found")
        print("[*] Install via package manager: apt install dnsenum (Linux)")
        print("[*] Or from: https://github.com/fwaeytens/dnsenum")
        return {"error": "DNSenum not installed"}
    
    # Build dnsenum command
    cmd = ["dnsenum"]
    
    # Nameserver
    if nameserver:
        cmd.extend(["--dnsserver", nameserver])
    
    # Threads
    cmd.extend(["--threads", str(threads)])
    
    # Number of subdomains
    cmd.extend(["--subfile", "/usr/share/dnsenum/dns.txt"])  # Default wordlist
    
    # Zone transfer
    if not zone_transfer:
        cmd.append("--noreverse")
    
    # Disable options if requested
    if not google_scrape:
        cmd.append("--nogoogle")
    
    if not whois:
        cmd.append("--nowhois")
    
    # Output file
    output_dir = os.path.join(os.path.expanduser("~"), ".kali_tools_temp")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"dnsenum_{target}.txt")
    cmd.extend(["-o", output_file])
    
    # Add target
    cmd.append(target)
    
    print(f"[*] Running command: {' '.join(cmd)}")
    print()
    
    try:
        # Run dnsenum
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
        
        # Parse output file if available
        if os.path.exists(output_file):
            _parse_output_file(output_file, results)
        
    except FileNotFoundError:
        print("[ERROR] dnsenum command not found")
        print("[*] Install via: apt install dnsenum")
        return {"error": "dnsenum not installed"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}
    
    print("\n" + "=" * 60)
    print(f"[+] Name servers found: {len(results['name_servers'])}")
    print(f"[+] MX records found: {len(results['mx_records'])}")
    print(f"[+] Subdomains discovered: {len(results['subdomains'])}")
    print(f"[+] IP addresses found: {len(results['ip_addresses'])}")
    if results['zone_transfer_success']:
        print("[+] Zone transfer successful!")
    else:
        print("[-] Zone transfer failed or not attempted")
    print("=" * 60)
    print("[*] DNSenum scan complete")
    print(f"[*] Full results saved to: {output_file}")
    
    return results


def _check_dnsenum_installed() -> bool:
    """Check if dnsenum is installed."""
    try:
        subprocess.run(
            ["dnsenum", "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _parse_output_line(line: str, results: Dict) -> None:
    """Parse dnsenum output line for results."""
    # Name servers
    if "Name Server" in line or "NS" in line:
        # Extract NS records
        ns_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*)', line)
        if ns_match:
            ns = ns_match.group(1)
            if ns not in results['name_servers'] and "." in ns:
                results['name_servers'].append(ns)
    
    # MX records
    if "MX" in line or "Mail Server" in line:
        mx_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*)', line)
        if mx_match:
            mx = mx_match.group(1)
            if mx not in results['mx_records'] and "." in mx:
                results['mx_records'].append(mx)
    
    # Subdomains
    subdomain_match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})', line)
    if subdomain_match:
        subdomain = subdomain_match.group(1)
        if subdomain not in results['subdomains']:
            results['subdomains'].append(subdomain)
    
    # IP addresses
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
    if ip_match:
        ip = ip_match.group(0)
        if ip not in results['ip_addresses'] and not ip.startswith("127."):
            results['ip_addresses'].append(ip)
    
    # Zone transfer success
    if "AXFR" in line and "success" in line.lower():
        results['zone_transfer_success'] = True


def _parse_output_file(output_file: str, results: Dict) -> None:
    """Parse dnsenum output file for additional results."""
    try:
        with open(output_file, 'r') as f:
            content = f.read()
            
            # Extract subdomains from output file
            subdomain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})'
            for match in re.finditer(subdomain_pattern, content):
                subdomain = match.group(1)
                if subdomain not in results['subdomains']:
                    results['subdomains'].append(subdomain)
        
        print(f"\n[+] Parsed output file: {output_file}")
        
    except Exception as e:
        print(f"[!] Error parsing output file: {e}")
