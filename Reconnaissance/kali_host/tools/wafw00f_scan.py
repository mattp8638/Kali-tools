"""
WAFw00f Scan - Detect Web Application Firewalls in front of a target URL.
Uses the wafw00f Python library if available, falls back to CLI if needed.
"""
from typing import Dict, Any, Callable, List
import subprocess
import shlex


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run WAF detection against a target URL.

    Params:
        url: Target URL (e.g. "https://example.com")
        generic_detection: Boolean, try generic detection even if vendor is unknown
        force_ssl: Boolean, force HTTPS
        extra_args: Optional extra CLI args for wafw00f
    """
    url = params.get("url", "").strip()
    generic_detection = params.get("generic_detection", True)
    force_ssl = params.get("force_ssl", False)
    extra_args = params.get("extra_args", "")

    if not url:
        print("[ERROR] No URL specified")
        return {"error": "No URL specified"}

    print(f"[*] WAFw00f scan starting for: {url}")
    print(f"[*] Generic detection: {'yes' if generic_detection else 'no'}")
    print(f"[*] Force SSL: {'yes' if force_ssl else 'no'}")
    print("=" * 60)

    results: Dict[str, Any] = {
        "url": url,
        "waf_detected": False,
        "waf_name": None,
        "manufacturer": None,
        "generic": False,
        "raw_output": "",
    }

    # Try Python API first (preferred)
    try:
        from wafw00f.main import WAFW00F

        print("[*] Using wafw00f Python API")

        w = WAFW00F(target=url)

        if is_cancelled and is_cancelled():
            print("[!] Scan cancelled before start")
            return results

        waf_name = w.identwaf()

        if waf_name:
            results["waf_detected"] = True
            results["waf_name"] = waf_name
            try:
                results["manufacturer"] = w.get_manufacturer()
            except Exception:
                results["manufacturer"] = None
            results["generic"] = False
            print(f"[+] WAF detected: {waf_name}")
            if results["manufacturer"]:
                print(f"[+] Manufacturer: {results['manufacturer']}")
        else:
            if generic_detection:
                print("[-] No specific WAF identified")
            results["waf_detected"] = False

        if on_progress:
            on_progress(1, 1)

        print("=" * 60)
        print("[*] WAFw00f scan complete")
        return results

    except ImportError:
        print("[*] wafw00f Python API not available, falling back to CLI")

    cmd: List[str] = ["wafw00f", url, "-a"]
    if force_ssl:
        cmd.append("--https")
    if extra_args:
        cmd.extend(shlex.split(extra_args))

    print(f"[*] Running command: {' '.join(cmd)}\n")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        lines: List[str] = []

        for line in iter(proc.stdout.readline, ""):
            if is_cancelled and is_cancelled():
                proc.terminate()
                print("\n[!] Scan cancelled")
                break

            line = line.rstrip("\n")
            if not line:
                continue

            print(line)
            lines.append(line)
            if on_output:
                on_output(line)

            parsed = line.lower()
            if "is behind" in parsed or "waf detected" in parsed:
                results["waf_detected"] = True

            if "identified as" in parsed:
                parts = line.split("identified as", 1)
                if len(parts) == 2:
                    results["waf_name"] = parts[1].strip().strip(".")

        proc.wait()
        results["raw_output"] = "\n".join(lines)

        if on_progress:
            on_progress(1, 1)

        print("\n" + "=" * 60)
        if results["waf_detected"]:
            print(f"[+] WAF detected: {results.get('waf_name') or 'unknown'}")
        else:
            print("[-] No WAF detected")
        print("=" * 60)
        print("[*] WAFw00f scan complete")

    except FileNotFoundError:
        print("[ERROR] wafw00f CLI not found and Python module not available")
        return {
            "error": "wafw00f not installed (neither Python module nor CLI found)",
            **results,
        }
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e), **results}

    return results
