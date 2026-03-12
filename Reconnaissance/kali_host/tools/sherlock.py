"""
Sherlock - Hunt down social media accounts by username across 300+ platforms
"""
import subprocess
import json
import os
import re
import sys
import shutil
from typing import Dict, Any, Callable, List


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run Sherlock username search across social media platforms.
    
    Params:
        username: Username to search for
        timeout: Timeout per request in seconds
        proxy: Proxy to use (e.g., socks5://127.0.0.1:1080)
        platforms: Specific platforms to check (comma-separated)
        csv_output: Generate CSV report
        print_found: Only print found sites
    """
    username = params.get("username", "")
    timeout = params.get("timeout", 60)
    proxy = params.get("proxy", "")
    platforms = params.get("platforms", "")
    csv_output = params.get("csv_output", False)
    print_found = params.get("print_found", True)
    
    if not username:
        print("[ERROR] No username specified")
        return {"error": "No username specified"}
    
    results = {
        "username": username,
        "found": [],
        "not_found": [],
        "errors": []
    }
    
    print(f"[*] Sherlock starting for username: {username}")
    print(f"[*] Timeout: {timeout}s per site")
    if proxy:
        print(f"[*] Using proxy: {proxy}")
    if platforms:
        print(f"[*] Target platforms: {platforms}")
    print("=" * 60)
    
    # Check if Sherlock is installed
    if not _check_sherlock_installed():
        print("[!] Sherlock not found. Installing...")
        if not _install_sherlock():
            print("[ERROR] Failed to install Sherlock")
            print("[*] Manual install: pip install sherlock-project")
            return {"error": "Sherlock installation failed"}
    
    command_prefix = _resolve_sherlock_command()
    if not command_prefix:
        print("[ERROR] Could not find a runnable Sherlock command in this Python environment")
        print("[*] Try reinstalling in this venv: python -m pip install --upgrade sherlock-project")
        return {"error": "Sherlock executable not found"}

    # Build Sherlock command
    cmd = [*command_prefix, username, "--timeout", str(timeout)]
    
    if proxy:
        cmd.extend(["--proxy", proxy])
    
    if platforms:
        for platform in platforms.split(","):
            cmd.extend(["--site", platform.strip()])
    
    if print_found:
        cmd.append("--print-found")
    
    # Create output directory
    output_dir = os.path.join(os.path.expanduser("~"), ".kali_tools_temp")
    os.makedirs(output_dir, exist_ok=True)
    
    if csv_output:
        csv_file = os.path.join(output_dir, f"sherlock_{username}.csv")
        cmd.extend(["--csv"])
    
    # Add JSON output
    json_file = os.path.join(output_dir, f"sherlock_{username}.json")
    cmd.extend(["--print-all", "--json", json_file])
    
    print(f"[*] Running command: {' '.join(cmd)}")
    print()
    
    try:
        # Run Sherlock
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Stream output
        found_count = 0
        checked_count = 0
        
        for line in iter(process.stdout.readline, ''):
            if is_cancelled and is_cancelled():
                process.terminate()
                print("\n[!] Scan cancelled")
                return results
            
            line = line.rstrip()
            if line:
                print(line)
                
                # Count progress
                if "[+]" in line:
                    found_count += 1
                    # Parse platform name
                    match = re.search(r'\[\+\]\s+(\w+):', line)
                    if match:
                        platform = match.group(1)
                        url_match = re.search(r'https?://[^\s]+', line)
                        if url_match:
                            results["found"].append({
                                "platform": platform,
                                "url": url_match.group(0)
                            })
                
                if "[-]" in line:
                    match = re.search(r'\[-\]\s+(\w+):', line)
                    if match:
                        results["not_found"].append(match.group(1))
                
                checked_count += 1
                if on_progress and checked_count % 10 == 0:
                    on_progress(checked_count, 300)  # Approximate total sites
        
        process.wait()
        
        # Parse JSON output if available
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    json_data = json.load(f)
                    # Merge with existing results
                    for platform, data in json_data.items():
                        if isinstance(data, dict) and data.get("url_user"):
                            if not any(r["platform"] == platform for r in results["found"]):
                                results["found"].append({
                                    "platform": platform,
                                    "url": data["url_user"]
                                })
            except Exception as e:
                print(f"[!] Error parsing JSON: {e}")
        
    except FileNotFoundError:
        print("[ERROR] Sherlock command not found")
        print("[*] Install with: pip install sherlock-project")
        return {"error": "Sherlock not installed"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}
    
    print("\n" + "=" * 60)
    print(f"[+] Found on {len(results['found'])} platforms")
    print(f"[-] Not found on {len(results['not_found'])} platforms")
    
    if results["found"]:
        print("\n[*] Profile Links:")
        for item in results["found"]:
            print(f"  [{item['platform']}] {item['url']}")
    
    print("=" * 60)
    print("[*] Sherlock scan complete")
    
    if csv_output and os.path.exists(csv_file):
        print(f"[*] CSV report saved to: {csv_file}")
    
    return results


def _check_sherlock_installed() -> bool:
    """Check if Sherlock is installed."""
    return _resolve_sherlock_command() is not None


def _install_sherlock() -> bool:
    """Attempt to install Sherlock via pip."""
    try:
        print("[*] Installing Sherlock...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "sherlock-project"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if _resolve_sherlock_command() is not None:
            print("[+] Sherlock installed successfully")
            return True

        print("[!] Sherlock package installed but command was not found")
        return False
    except subprocess.CalledProcessError:
        return False


def _resolve_sherlock_command() -> List[str] | None:
    """Resolve a runnable Sherlock command from the active Python environment."""
    script_dir = os.path.dirname(sys.executable)
    if os.name == "nt":
        script_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
        candidates = [
            os.path.join(script_dir, "sherlock.exe"),
            os.path.join(script_dir, "sherlock.cmd"),
            os.path.join(script_dir, "sherlock.bat"),
            os.path.join(script_dir, "sherlock"),
        ]
    else:
        candidates = [os.path.join(script_dir, "sherlock")]

    for candidate in candidates:
        if os.path.exists(candidate):
            return [candidate]

    resolved = shutil.which("sherlock")
    if resolved:
        return [resolved]

    try:
        subprocess.run(
            [sys.executable, "-m", "sherlock", "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        return [sys.executable, "-m", "sherlock"]
    except (subprocess.TimeoutExpired, OSError):
        return None
