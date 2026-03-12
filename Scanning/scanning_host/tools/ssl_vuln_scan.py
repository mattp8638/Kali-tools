import re
from typing import Any, Dict, List

from scanning_host.core.common import normalize_host, resolve_command, run_command, safe_int


WEAK_CIPHER_RE = re.compile(r"\b(rc4|3des|des-cbc|md5|null|export)\b", flags=re.IGNORECASE)


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    host = normalize_host(params.get("target", ""))
    port = safe_int(params.get("port", 443), 443)
    timeout = safe_int(params.get("timeout", 900), 900)

    if not host:
        return {"error": "target is required"}

    nmap = resolve_command(["nmap.exe", "nmap"])
    if not nmap:
        return {"error": "Nmap CLI not found. Install Nmap and ensure it is on PATH."}

    scripts = "ssl-enum-ciphers,ssl-heartbleed,ssl-ccs-injection,sslv2,sslv3"
    cmd = [nmap, "-Pn", "-p", str(port), "--script", scripts, host]
    code, stdout, stderr = run_command(cmd, timeout=timeout)

    vulnerabilities: List[Dict[str, str]] = []
    weak_ciphers: List[str] = []

    for line in stdout.splitlines():
        text = line.strip()
        if not text:
            continue

        upper = text.upper()
        if "VULNERABLE" in upper or "HEARTBLEED" in upper or "POODLE" in upper or "BEAST" in upper:
            vulnerabilities.append({"severity": "high", "line": text})
            continue

        if "TLSV1.0" in upper or "TLSV1.1" in upper or "SSLV2" in upper or "SSLV3" in upper:
            vulnerabilities.append({"severity": "medium", "line": text})

        if WEAK_CIPHER_RE.search(text):
            weak_ciphers.append(text)

    # Deduplicate while preserving order.
    seen = set()
    dedup_weak_ciphers = []
    for row in weak_ciphers:
        if row in seen:
            continue
        seen.add(row)
        dedup_weak_ciphers.append(row)

    return {
        "target": host,
        "port": port,
        "command": cmd,
        "exit_code": code,
        "vulnerability_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "weak_cipher_lines": dedup_weak_ciphers,
        "raw_stdout": stdout,
        "raw_stderr": stderr,
    }
