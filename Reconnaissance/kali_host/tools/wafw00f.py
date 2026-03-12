"""
Wafw00f - Web Application Firewall (WAF) Detection Tool
Identifies and fingerprints WAF products protecting web applications
"""
import subprocess
import json
import os
from typing import Dict, Any, Callable


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run Wafw00f to detect Web Application Firewalls.
    
    Params:
        target: Target URL to test
        list_wafs: List all WAF signatures (info only)
        test_all: Test for all WAFs instead of stopping at first match
        follow_redirects: Follow HTTP redirects
        proxy: Proxy to use (format: http://proxy:port)
    """
    target = params.get("target", "")
    list_wafs = params.get("list_wafs", False)
    test_all = params.get("test_all", False)
    follow_redirects = params.get("follow_redirects", True)
    proxy = params.get("proxy", "")
    
    results = {
        "target": target,
        "waf_detected": False,
        "waf_name": None,
        "waf_manufacturer": None,
        "multiple_wafs": []
    }
    
    # List WAFs mode
    if list_wafs:
        print("[*] Listing all known WAF signatures...")
        print("=" * 60)
        _list_waf_signatures()
        return {"info": "WAF signatures listed"}
    
    if not target:
        print("[ERROR] No target URL specified")
        return {"error": "No target URL specified"}
    
    # Add http:// if no protocol specified
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    
    print(f"[*] Wafw00f starting for: {target}")
    print("=" * 60)
    
    # Check if wafw00f is installed
    if not _check_wafw00f_installed():
        print("[!] Wafw00f not found. Installing...")
        if not _install_wafw00f():
            print("[ERROR] Failed to install wafw00f")
            print("[*] Manual install: pip install wafw00f")
            return {"error": "wafw00f installation failed"}
    
    # Build wafw00f command
    cmd = ["wafw00f", target]
    
    if test_all:
        cmd.append("-a")
    
    if not follow_redirects:
        cmd.append("-r")
    
    if proxy:
        cmd.extend(["-p", proxy])
    
    # Output format
    cmd.append("-v")  # Verbose
    
    output_dir = os.path.join(os.path.expanduser("~"), ".kali_tools_temp")
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Running command: {' '.join(cmd)}")
    print()
    
    try:
        # Run wafw00f
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
                
                # Parse results
                _parse_output_line(line, results)
        
        process.wait()
        
    except FileNotFoundError:
        print("[ERROR] wafw00f command not found")
        print("[*] Install with: pip install wafw00f")
        return {"error": "wafw00f not installed"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}
    
    print("\n" + "=" * 60)
    if results['waf_detected']:
        print(f"[+] WAF DETECTED: {results['waf_name']}")
        if results['waf_manufacturer']:
            print(f"[*] Manufacturer: {results['waf_manufacturer']}")
        if results['multiple_wafs']:
            print(f"[*] Multiple WAFs found: {len(results['multiple_wafs'])}")
            for waf in results['multiple_wafs']:
                print(f"    - {waf}")
    else:
        print("[-] No WAF detected")
    print("=" * 60)
    print("[*] Wafw00f scan complete")
    
    return results


def _check_wafw00f_installed() -> bool:
    """Check if wafw00f is installed."""
    try:
        subprocess.run(
            ["wafw00f", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _install_wafw00f() -> bool:
    """Attempt to install wafw00f via pip."""
    try:
        print("[*] Installing wafw00f...")
        subprocess.run(
            ["pip", "install", "wafw00f"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print("[+] wafw00f installed successfully")
        return True
    except subprocess.CalledProcessError:
        return False


def _list_waf_signatures():
    """List all known WAF signatures."""
    try:
        result = subprocess.run(
            ["wafw00f", "-l"],
            capture_output=True,
            text=True,
            timeout=10
        )
        print(result.stdout)
    except Exception as e:
        print(f"[!] Error listing WAF signatures: {e}")


def _parse_output_line(line: str, results: Dict) -> None:
    """Parse wafw00f output line for results."""
    # Check for WAF detection
    if "is behind" in line.lower():
        results['waf_detected'] = True
        # Extract WAF name (usually after "is behind")
        parts = line.split("is behind")
        if len(parts) > 1:
            waf_info = parts[1].strip()
            results['waf_name'] = waf_info.split("(")[0].strip()
            
            # Extract manufacturer if present
            if "(" in waf_info and ")" in waf_info:
                start = waf_info.index("(") + 1
                end = waf_info.index(")")
                results['waf_manufacturer'] = waf_info[start:end]
    
    # Check for "No WAF detected"
    if "no waf" in line.lower() or "not behind" in line.lower():
        results['waf_detected'] = False
    
    # Collect multiple WAFs if testing all
    if "detected" in line.lower() and "-" in line:
        waf_name = line.split("-")[-1].strip()
        if waf_name and waf_name not in results['multiple_wafs']:
            results['multiple_wafs'].append(waf_name)
