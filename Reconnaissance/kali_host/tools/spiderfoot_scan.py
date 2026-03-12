"""
SpiderFoot Scan - Automated OSINT framework runner.
SpiderFoot must be installed separately (python sf.py or sfcli.py).
This wrapper locates a local SpiderFoot installation or a sfcli entry point
and runs a targeted scan, then parses results back into the tool format.

Installation: git clone https://github.com/smicallef/spiderfoot
              pip install -r spiderfoot/requirements.txt
Then set the SpiderFoot path in the params.
"""
import os
import csv
import json
import subprocess
import tempfile
from typing import Dict, Any, Callable, List, Optional


# Modules that work well without API keys for passive recon
DEFAULT_MODULES = [
    "sfp_dnsresolve",
    "sfp_dns",
    "sfp_dnsdumpster",
    "sfp_crt",
    "sfp_hackertarget",
    "sfp_whois",
    "sfp_ipinfo",
    "sfp_arin",
    "sfp_sublist3r",
    "sfp_threatcrowd",
    "sfp_virustotal",
    "sfp_fullcontact",
    "sfp_github",
]


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run a SpiderFoot scan via sfcli.py.

    Params:
        target: Domain, IP, email or username
        spiderfoot_path: Path to SpiderFoot directory (e.g. C:\\tools\\spiderfoot)
        modules: Comma-separated SpiderFoot module IDs, or 'default' for a safe passive set
        scan_name: Optional name for the scan
        timeout_minutes: Max scan duration (default 10)
    """
    target = params.get("target", "").strip()
    sf_path = params.get("spiderfoot_path", "").strip()
    modules_str = params.get("modules", "default").strip()
    scan_name = params.get("scan_name", f"KaliAppHost_{target}").strip()
    timeout_minutes = int(params.get("timeout_minutes", 10))

    if not target:
        print("[ERROR] No target specified")
        return {"error": "No target specified"}

    if not sf_path:
        sf_path = _find_spiderfoot()

    if not sf_path:
        print("[ERROR] SpiderFoot not found.")
        print("[*] Clone it with: git clone https://github.com/smicallef/spiderfoot")
        print("[*] Then set the 'SpiderFoot Path' parameter to its directory.")
        return {"error": "SpiderFoot not found. Please clone it and set the path."}

    sfcli = os.path.join(sf_path, "sfcli.py")
    if not os.path.exists(sfcli):
        print(f"[ERROR] sfcli.py not found in: {sf_path}")
        return {"error": f"sfcli.py not found in {sf_path}"}

    if modules_str.lower() == "default" or not modules_str:
        modules = ",".join(DEFAULT_MODULES)
    else:
        modules = modules_str

    print(f"[*] SpiderFoot scan starting")
    print(f"[*] Target: {target}")
    print(f"[*] SpiderFoot path: {sf_path}")
    print(f"[*] Modules: {modules[:120]}..." if len(modules) > 120 else f"[*] Modules: {modules}")
    print(f"[*] Timeout: {timeout_minutes} minute(s)")
    print("=" * 60)

    results: Dict[str, Any] = {
        "target": target,
        "findings": [],
        "type_counts": {},
        "raw_output": "",
    }

    # Create temp directory for output
    tmp_dir = os.path.join(os.path.expanduser("~"), ".kali_tools_temp")
    os.makedirs(tmp_dir, exist_ok=True)
    output_csv = os.path.join(tmp_dir, f"sf_{target.replace('.', '_')}.csv")

    # Build sfcli command
    # sfcli.py usage: -s <target> -t <type> -m <modules> -o csv -q
    cmd: List[str] = [
        "python", sfcli,
        "-s", target,
        "-m", modules,
        "-o", "csv",
        "-q",           # quiet, no interactive
    ]

    # Output to a named file requires sfcli -R flag in some versions
    # We capture stdout directly

    print(f"[*] Running: {' '.join(cmd[:6])} ...\n")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=sf_path,
            timeout=timeout_minutes * 60,
        )

        all_lines: List[str] = []
        for line in iter(proc.stdout.readline, ""):
            if is_cancelled and is_cancelled():
                proc.terminate()
                print("\n[!] Scan cancelled")
                break

            line = line.rstrip("\n")
            if not line:
                continue

            print(line)
            all_lines.append(line)

        proc.wait()
        results["raw_output"] = "\n".join(all_lines)

        # Parse CSV output from stdout lines
        findings, type_counts = _parse_csv_output(all_lines)
        results["findings"] = findings
        results["type_counts"] = type_counts

    except subprocess.TimeoutExpired:
        print(f"\n[!] SpiderFoot scan timed out after {timeout_minutes} minutes")
        results["warning"] = f"Scan timed out after {timeout_minutes} minutes"
    except FileNotFoundError:
        print("[ERROR] Python or sfcli.py not accessible")
        return {"error": "Python or sfcli.py not found"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e), **results}

    print("\n" + "=" * 60)
    print(f"[+] SpiderFoot found {len(results['findings'])} result(s)")
    if results["type_counts"]:
        print("\n[*] Results by type:")
        for t, c in sorted(results["type_counts"].items(), key=lambda x: -x[1]):
            print(f"    {t:<40} {c}")
    print("=" * 60)
    print("[*] SpiderFoot scan complete")

    return results


def _find_spiderfoot() -> Optional[str]:
    """Try to locate a SpiderFoot installation in common Windows paths."""
    candidates = [
        os.path.join(os.path.expanduser("~"), "spiderfoot"),
        os.path.join(os.path.expanduser("~"), "tools", "spiderfoot"),
        r"C:\tools\spiderfoot",
        r"C:\spiderfoot",
    ]
    for path in candidates:
        if os.path.exists(os.path.join(path, "sfcli.py")):
            return path
    return None


def _parse_csv_output(lines: List[str]) -> tuple:
    """Parse CSV lines from sfcli stdout output."""
    findings: List[Dict[str, str]] = []
    type_counts: Dict[str, int] = {}

    import io
    csv_text = "\n".join(lines)
    reader = csv.DictReader(io.StringIO(csv_text))

    try:
        for row in reader:
            finding_type = row.get("Type", row.get("type", "Unknown"))
            data = row.get("Data", row.get("data", ""))
            source = row.get("Source", row.get("source", ""))

            if finding_type and data:
                findings.append({
                    "type": finding_type,
                    "data": data,
                    "source": source,
                })
                type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
    except Exception:
        pass

    return findings, type_counts
