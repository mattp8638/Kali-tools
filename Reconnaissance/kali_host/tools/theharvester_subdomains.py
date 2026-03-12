"""
theHarvester Subdomain OSINT - Focused on discovering subdomains/hosts.
Uses theHarvester as a Python module or CLI if available.
"""
from typing import Dict, Any, Callable, List
import subprocess
import os
import json
import re
import sys
import shutil


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run a subdomain-focused theHarvester scan.

    Params:
        domain: Target domain (e.g. "example.com")
        sources: Comma-separated sources, or "all"
        limit: Result limit per source
    """
    domain = params.get("domain", "").strip()
    sources = params.get("sources", "all").strip()

    try:
        limit = int(params.get("limit", 500))
    except (TypeError, ValueError):
        limit = 500

    if not domain:
        print("[ERROR] No domain specified")
        return {"error": "No domain specified"}

    print(f"[*] theHarvester subdomain scan for: {domain}")
    print(f"[*] Sources: {sources}")
    print(f"[*] Limit: {limit}")
    print("=" * 60)

    results: Dict[str, Any] = {
        "domain": domain,
        "hosts": [],
        "ips": [],
        "emails": [],
        "raw_output": "",
    }

    # Try Python module first
    try:
        from theHarvester.discovery import theHarvester  # noqa: F401

        print("[*] Using theHarvester Python API (experimental on Windows)")
        print("[!] theHarvester Python API is not officially supported on Windows.")
        print("[!] Consider using the CLI integration or a custom OSINT tool.")
        return {
            "error": "theHarvester Python API not fully supported on Windows; use CLI or custom OSINT tool",
            **results,
        }

    except Exception:
        print("[*] Falling back to theHarvester CLI (if installed)")

    command_prefix = _resolve_theharvester_command()
    if not command_prefix:
        print("[ERROR] theHarvester CLI not found")
        return {
            "error": "theHarvester not installed (CLI not found)",
            **results,
        }

    cmd: List[str] = [*command_prefix, "-d", domain, "-b", sources, "-l", str(limit)]

    out_dir = os.path.join(os.path.expanduser("~"), ".kali_tools_temp")
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"theharvester_{domain}_subdomains")
    cmd.extend(["-f", base])

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
            _parse_realtime_line(line, results)
            if on_output:
                on_output(line)

        proc.wait()
        results["raw_output"] = "\n".join(lines)

        json_file = base + ".json"
        if os.path.exists(json_file):
            _merge_json_output(json_file, results)

        if on_progress:
            on_progress(1, 1)

        print("\n" + "=" * 60)
        print(f"[+] Hosts found: {len(results['hosts'])}")
        print(f"[+] IPs found: {len(results['ips'])}")
        print(f"[+] Emails found (not primary focus): {len(results['emails'])}")
        print("=" * 60)
        print("[*] theHarvester subdomain scan complete")

    except FileNotFoundError:
        print("[ERROR] theHarvester CLI not found")
        return {
            "error": "theHarvester not installed (CLI not found)",
            **results,
        }
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e), **results}

    return results


def _parse_realtime_line(line: str, results: Dict[str, Any]) -> None:
    """Very loose parsing of stdout to collect hosts / IPs / emails."""
    email_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", line)
    if email_match:
        email = email_match.group(0)
        if email not in results["emails"]:
            results["emails"].append(email)

    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    if ip_match:
        ip = ip_match.group(0)
        if ip not in results["ips"]:
            results["ips"].append(ip)

    domain = results.get("domain")
    if domain and domain in line:
        for token in line.split():
            if domain in token and "." in token:
                host = token.strip(" ,;:()[]{}<>'\"")
                if host.endswith(domain) and host not in results["hosts"]:
                    results["hosts"].append(host)


def _merge_json_output(json_file: str, results: Dict[str, Any]) -> None:
    """Merge theHarvester JSON output into results, if possible."""
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return

    hosts = data.get("hosts") or data.get("ip_hostnames") or []
    for host_item in hosts:
        if isinstance(host_item, str):
            host = host_item
        else:
            host = host_item.get("hostname") or host_item.get("host") or ""

        if host and host not in results["hosts"]:
            results["hosts"].append(host)

    emails = data.get("emails") or []
    for email_item in emails:
        if isinstance(email_item, str):
            email = email_item
        else:
            email = email_item.get("value") or ""

        if email and email not in results["emails"]:
            results["emails"].append(email)

    ips = data.get("ips") or []
    for ip_item in ips:
        if isinstance(ip_item, str):
            ip = ip_item
        else:
            ip = ip_item.get("ip") or ""

        if ip and ip not in results["ips"]:
            results["ips"].append(ip)


def _resolve_theharvester_command() -> List[str] | None:
    """Resolve a runnable theHarvester command from the active Python environment."""
    if os.name == "nt":
        script_dir = os.path.join(os.path.dirname(sys.executable), "Scripts")
        candidates = [
            os.path.join(script_dir, "theHarvester.exe"),
            os.path.join(script_dir, "theHarvester.cmd"),
            os.path.join(script_dir, "theHarvester.bat"),
            os.path.join(script_dir, "theHarvester"),
        ]
    else:
        script_dir = os.path.dirname(sys.executable)
        candidates = [os.path.join(script_dir, "theHarvester")]

    for candidate in candidates:
        if os.path.exists(candidate):
            return [candidate]

    resolved = shutil.which("theHarvester")
    if resolved:
        return [resolved]

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
