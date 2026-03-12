"""
dnsrecon - Advanced DNS enumeration, zone transfers, brute force.
Wraps the dnsrecon CLI. Requires dnsrecon installed.
"""
import shlex
import subprocess
from typing import Any, Callable, Dict, List


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run dnsrecon.

    Params:
        domain: Target domain
        brute_force: Boolean, enable -D wordlist brute force
        wordlist: Wordlist path
        zone_transfer: Boolean, attempt zone transfers (-a)
        std: Standard enumeration (-t std)
        bing: Use Bing search (-t bing)
        google: Use Google search (-t google)
        wildcard: Check wildcard (-w)
        extra_args: Extra dnsrecon arguments
    """
    domain = params.get("domain", "")
    brute_force = params.get("brute_force", False)
    wordlist = params.get("wordlist", "")
    zone_transfer = params.get("zone_transfer", True)
    use_std = params.get("std", True)
    use_bing = params.get("bing", False)
    use_google = params.get("google", False)
    wildcard = params.get("wildcard", False)
    extra_args = params.get("extra_args", "")

    if not domain:
        print("[ERROR] No domain specified")
        return {"error": "No domain specified"}

    result: Dict[str, Any] = {
        "domain": domain,
        "records": [],
        "raw_output": "",
    }

    print(f"[*] dnsrecon starting for: {domain}")
    print(f"[*] Brute force: {'yes' if brute_force else 'no'}")
    if brute_force:
        print(f"[*] Wordlist: {wordlist or '(default)'}")
    print(f"[*] Zone transfer attempts: {'yes' if zone_transfer else 'no'}")
    print("=" * 60)

    cmd: List[str] = ["dnsrecon", "-d", domain]

    scan_types: List[str] = []
    if use_std:
        scan_types.append("std")
    if use_bing:
        scan_types.append("bing")
    if use_google:
        scan_types.append("google")

    if not scan_types:
        scan_types.append("std")

    for stype in scan_types:
        cmd.extend(["-t", stype])

    if wildcard:
        cmd.append("-w")
    if zone_transfer:
        cmd.append("-a")

    if brute_force:
        cmd.append("-b")
        if wordlist:
            cmd.extend(["-D", wordlist])

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

        all_lines: List[str] = []
        for line in iter(proc.stdout.readline, ""):
            if is_cancelled and is_cancelled():
                proc.terminate()
                print("\n[!] Scan cancelled")
                break

            line = line.rstrip("\n")
            if line:
                print(line)
                all_lines.append(line)
                _parse_dnsrecon_line(line, result)

                if on_output:
                    on_output(line)

        proc.wait()
        result["raw_output"] = "\n".join(all_lines)

        if on_progress:
            on_progress(1, 1)

        print("\n" + "=" * 60)
        print(f"[+] Records collected: {len(result['records'])}")
        print("=" * 60)
        print("[*] dnsrecon complete")

    except FileNotFoundError:
        print("[ERROR] dnsrecon not found on PATH")
        return {"error": "dnsrecon not installed or not in PATH"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}

    return result


def _parse_dnsrecon_line(line: str, result: Dict[str, Any]) -> None:
    """
    Try to parse CSV-ish output lines from dnsrecon.
    Example style: "[*] A,example.com,1.2.3.4"
    """
    cleaned = line.strip()
    if not cleaned:
        return

    if cleaned.startswith("[*]") or cleaned.startswith("[+]") or cleaned.startswith("[-]"):
        marker_end = cleaned.find("]")
        if marker_end != -1:
            cleaned = cleaned[marker_end + 1 :].strip()

    parts = [p.strip() for p in cleaned.split(",")]
    if len(parts) < 3:
        return

    rtype = parts[0].upper()
    if rtype not in {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV"}:
        return

    record = {
        "type": rtype,
        "name": parts[1],
        "value": parts[2],
    }
    if record not in result["records"]:
        result["records"].append(record)
