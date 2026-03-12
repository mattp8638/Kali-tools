import re
from typing import Any, Dict, List

from scanning_host.core.common import normalize_host, resolve_command, run_command, safe_int


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    host = normalize_host(params.get("target", ""))
    ports = str(params.get("ports", "1-1000")).strip()
    timeout = safe_int(params.get("timeout", 900), 900)
    timing = max(0, min(5, safe_int(params.get("timing", 3), 3)))
    script = str(params.get("script", "vuln")).strip() or "vuln"

    if not host:
        return {"error": "target is required"}

    nmap = resolve_command(["nmap.exe", "nmap"])
    if not nmap:
        return {"error": "Nmap CLI not found. Install Nmap and ensure it is on PATH."}

    print("[*] Nmap vulnerability scan starting")
    print(f"[*] Target: {host}")
    print(f"[*] Ports: {ports} | Scripts: {script} | Timing: T{timing}")

    cmd = [nmap, "-sV", "--script", script, f"-T{timing}", "-Pn"]
    if ports:
        cmd.extend(["-p", ports])
    cmd.append(host)

    code, stdout, stderr = run_command(cmd, timeout=timeout)

    open_ports: List[Dict[str, Any]] = []
    seen_ports = set()
    for line in stdout.splitlines():
        m = re.search(r"(\d+)\/(tcp|udp)\s+open\b", line, flags=re.IGNORECASE)
        if not m:
            continue
        key = (int(m.group(1)), m.group(2).lower())
        if key in seen_ports:
            continue
        seen_ports.add(key)
        open_ports.append({"port": key[0], "protocol": key[1], "state": "open"})

    indicators: List[str] = []
    for line in stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        upper = text.upper()
        if "VULNERABLE" in upper or "CVE-" in upper or "RISK FACTOR" in upper:
            indicators.append(text)

    print(f"[+] Open ports discovered: {len(open_ports)}")
    print(f"[+] Vulnerability indicators: {len(indicators)}")
    print("[*] Nmap vulnerability scan complete")

    return {
        "target": host,
        "command": cmd,
        "exit_code": code,
        "open_ports": open_ports,
        "open_port_count": len(open_ports),
        "vulnerability_indicators": indicators,
        "indicator_count": len(indicators),
        "raw_stdout": stdout,
        "raw_stderr": stderr,
    }
