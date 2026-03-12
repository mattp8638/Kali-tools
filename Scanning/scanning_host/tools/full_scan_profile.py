import importlib
import os
import re
from datetime import datetime
from typing import Any, Dict, List

from scanning_host.core.common import resolve_command


TOOL_CHAIN = [
    "dependency_checker",
    "nikto_scan",
    "dirb_scan",
    "banner_grab",
    "nmap_vuln_scan",
    "ssl_vuln_scan",
    "cve_lookup",
    "smb_enum",
    "ssh_probe",
    "rdp_probe",
    "ftp_probe",
    "snmp_enum",
    "nuclei_scan",
    "udp_scan",
    "arp_scan",
    "traceroute",
    "exploit_search",
]


def _derive_intel_query(open_port_rows: List[Dict[str, Any]], fallback: str) -> str:
    patterns = [
        r"OpenSSH[_\s-]?([0-9][^\s,;]*)",
        r"Apache[/\s-]([0-9][^\s,;]*)",
        r"nginx[/\s-]([0-9][^\s,;]*)",
        r"Microsoft-IIS[/\s-]([0-9][^\s,;]*)",
        r"vsFTPd\s+([0-9][^\s,;]*)",
        r"ProFTPD\s+([0-9][^\s,;]*)",
        r"Postfix\s+([0-9][^\s,;]*)",
    ]

    for row in open_port_rows:
        banner = str(row.get("banner", ""))
        if not banner:
            continue
        for pat in patterns:
            match = re.search(pat, banner, flags=re.IGNORECASE)
            if match:
                token = re.sub(r"[_-]", " ", match.group(0))
                return token.strip()

    return fallback


def _tool_params(tool_name: str, base: Dict[str, Any], derived: Dict[str, Any]) -> Dict[str, Any]:
    target = base.get("target", "")
    mapping = {
        "dependency_checker": {},
        "nikto_scan": {"target": target},
        "dirb_scan": {"target": target},
        "banner_grab": {"target": target, "ports": base.get("ports", "21,22,25,80,110,143,443,445")},
        "nmap_vuln_scan": {
            "target": target,
            "ports": base.get("nmap_vuln_ports", "1-1000"),
            "script": base.get("nmap_vuln_script", "vuln"),
            "timing": base.get("nmap_vuln_timing", 3),
            "timeout": base.get("nmap_vuln_timeout", 900),
        },
        "ssl_vuln_scan": {
            "target": target,
            "port": base.get("ssl_port", 443),
            "timeout": base.get("ssl_timeout", 900),
        },
        "cve_lookup": {"query": base.get("cve_query", "Apache 2.4")},
        "smb_enum": {
            "target": target,
            "username": base.get("smb_username", ""),
            "password": base.get("smb_password", ""),
            "domain": base.get("smb_domain", ""),
        },
        "ssh_probe": {"target": target},
        "rdp_probe": {
            "target": target,
            "port": base.get("rdp_port", 3389),
            "timeout": base.get("rdp_timeout", 5),
        },
        "ftp_probe": {"target": target},
        "snmp_enum": {"target": target, "communities": base.get("snmp_communities", "public,private")},
        "nuclei_scan": {"target": target, "severity": base.get("nuclei_severity", "")},
        "udp_scan": {"target": target, "ports": base.get("udp_ports", "53,69,123,161,500,1900")},
        "arp_scan": {"target": base.get("local_cidr", "")},
        "traceroute": {"target": target},
        "exploit_search": {
            "query": base.get("exploit_query") or derived.get("exploit_query") or "OpenSSH",
        },
    }
    if tool_name == "cve_lookup":
        return {
            "query": base.get("cve_query") or derived.get("cve_query") or "Apache 2.4",
            "limit": base.get("cve_limit", 10),
        }
    return mapping.get(tool_name, {"target": target})


def run(params: Dict[str, Any], on_progress=None, on_output=None, is_cancelled=None) -> Dict[str, Any]:
    started = datetime.utcnow().isoformat()
    results: List[Dict[str, Any]] = []
    open_ports = set()
    derived_queries: Dict[str, Any] = {}

    service_port_map = {
        "smb_enum": 445,
        "ssh_probe": 22,
        "rdp_probe": 3389,
        "ftp_probe": 21,
        "snmp_enum": 161,
    }

    def _append_skip(tool: str, reason: str):
        print(f"  [*] skipped: {reason}")
        results.append({
            "tool": tool,
            "ok": True,
            "skipped": True,
            "result": {"skipped": True, "reason": reason},
        })

    print("[*] Full Scan Profile starting")
    print(f"[*] Target: {params.get('target', 'N/A')}")

    enabled_raw = str(params.get("enabled_tools", "all")).strip().lower()
    if enabled_raw == "all":
        enabled = TOOL_CHAIN
    else:
        enabled = [x.strip() for x in enabled_raw.split(",") if x.strip()]

    for idx, name in enumerate(TOOL_CHAIN, start=1):
        if name not in enabled:
            continue
        if is_cancelled and is_cancelled():
            break
        if on_progress:
            on_progress(idx, len(TOOL_CHAIN))

        try:
            print(f"\n--- [{idx}/{len(TOOL_CHAIN)}] {name} ---")

            # Skip local-only ARP scan unless local CIDR is explicitly provided.
            if name == "arp_scan" and not str(params.get("local_cidr", "")).strip():
                _append_skip(name, "local_cidr not provided (ARP scan is local network only)")
                continue

            # Skip CLI wrappers when the external command is not installed.
            if name == "nikto_scan":
                has_nikto = bool(resolve_command(["nikto.bat", "nikto"]))
                has_perl_pl = bool(resolve_command(["perl.exe", "perl"])) and os.path.exists(
                    r"C:\tools\nikto\program\nikto.pl"
                )
                if not has_nikto and not has_perl_pl:
                    _append_skip(name, "Nikto CLI not found")
                    continue
            if name == "nuclei_scan" and not resolve_command(["nuclei.exe", "nuclei"]):
                _append_skip(name, "Nuclei CLI not found")
                continue
            if name == "nmap_vuln_scan" and not resolve_command(["nmap.exe", "nmap"]):
                _append_skip(name, "Nmap CLI not found")
                continue
            if name == "ssl_vuln_scan" and not resolve_command(["nmap.exe", "nmap"]):
                _append_skip(name, "Nmap CLI not found")
                continue

            # Only run protocol probes when the corresponding service port was discovered open.
            req_port = service_port_map.get(name)
            if req_port and open_ports and req_port not in open_ports:
                _append_skip(name, f"required port {req_port} was not open in banner_grab")
                continue

            mod = importlib.import_module(f"scanning_host.tools.{name}")
            payload = _tool_params(name, params, derived_queries)
            out = mod.run(payload, on_progress=None, on_output=None, is_cancelled=is_cancelled)

            # Carry forward discovered open ports for downstream protocol checks.
            if name == "banner_grab":
                open_rows = out.get("open_ports", [])
                for row in open_rows:
                    if isinstance(row, dict) and isinstance(row.get("port"), int):
                        open_ports.add(row["port"])

                # Build intelligence-driven defaults for CVE and exploit search.
                derived = _derive_intel_query(open_rows, "OpenSSH")
                derived_queries["cve_query"] = derived
                derived_queries["exploit_query"] = derived.split()[0] if derived else "OpenSSH"

            err = str(out.get("error", ""))
            if err and name in service_port_map and any(x in err.lower() for x in ["timed out", "refused", "unreachable", "no working community"]):
                out["warning"] = err
                out.pop("error", None)
                ok = True
            else:
                ok = "error" not in out

            results.append({"tool": name, "ok": ok, "result": out})
            if ok:
                if "hit_count" in out:
                    print(f"  [+] hit_count={out.get('hit_count', 0)}")
                elif "count" in out:
                    print(f"  [+] count={out.get('count', 0)}")
                elif "finding_count" in out:
                    print(f"  [+] finding_count={out.get('finding_count', 0)}")
                elif "findings_count" in out:
                    print(f"  [+] findings_count={out.get('findings_count', 0)}")
                elif "open_ports" in out:
                    print(f"  [+] open_ports={len(out.get('open_ports', []))}")
                elif "skipped" in out:
                    print(f"  [*] skipped")
                else:
                    print("  [+] completed")
            else:
                print(f"  [!] error: {out.get('error', 'unknown error')}")
        except Exception as e:
            results.append({"tool": name, "ok": False, "result": {"error": str(e)}})
            print(f"  [!] exception: {e}")

    ended = datetime.utcnow().isoformat()
    ok_count = sum(1 for r in results if r["ok"])
    failed_rows = [r for r in results if not r["ok"]]
    skipped_rows = [r for r in results if r.get("skipped") or r.get("result", {}).get("skipped")]

    print("\n[*] Full Scan Profile complete")
    print(f"[*] Executed: {len(results)} | Success: {ok_count} | Failed: {len(results) - ok_count} | Skipped: {len(skipped_rows)}")
    if failed_rows:
        print("\n[!] Failed tools:")
        for row in failed_rows:
            err = row.get("result", {}).get("error", "unknown")
            print(f"    - {row.get('tool')}: {err}")

    return {
        "started_at": started,
        "ended_at": ended,
        "target": params.get("target", ""),
        "executed": len(results),
        "success": ok_count,
        "failed": len(results) - ok_count,
        "skipped": len(skipped_rows),
        "failed_tools": [
            {"tool": r.get("tool"), "error": r.get("result", {}).get("error", "unknown")}
            for r in failed_rows
        ],
        "results": results,
    }
