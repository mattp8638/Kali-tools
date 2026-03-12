"""
Nmap Scan - Wrapper around nmap for service and OS detection.
Requires nmap installed and available in PATH.
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
    Run an Nmap scan.

    Params:
        target: IP / hostname / CIDR
        ports: Port range (e.g. "1-1000", "80,443")
        scan_type: "SYN", "Connect", "UDP", "Ping Sweep"
        os_detect: Boolean, enable OS detection
        service_versions: Boolean, enable -sV
        scripts: Comma-separated NSE script names or categories
        extra_args: Free-form Nmap args
    """
    target = params.get("target", "")
    ports = params.get("ports", "")
    scan_type = params.get("scan_type", "SYN")
    os_detect = params.get("os_detect", False)
    service_versions = params.get("service_versions", True)
    scripts = params.get("scripts", "")
    extra_args = params.get("extra_args", "")

    if not target:
        print("[ERROR] No target specified")
        return {"error": "No target specified"}

    result: Dict[str, Any] = {
        "target": target,
        "ports": [],
        "raw_xml": "",
    }

    print(f"[*] Nmap scan starting for: {target}")
    if ports:
        print(f"[*] Ports: {ports}")
    print(f"[*] Scan type: {scan_type}")
    print(f"[*] OS detection: {'yes' if os_detect else 'no'}")
    print(f"[*] Service versions: {'yes' if service_versions else 'no'}")
    if scripts:
        print(f"[*] NSE scripts: {scripts}")
    if extra_args:
        print(f"[*] Extra args: {extra_args}")
    print("=" * 60)

    cmd: List[str] = ["nmap", "-oX", "-"]

    if scan_type == "SYN":
        cmd.append("-sS")
    elif scan_type == "Connect":
        cmd.append("-sT")
    elif scan_type == "UDP":
        cmd.append("-sU")
    elif scan_type == "Ping Sweep":
        cmd.append("-sn")

    if os_detect:
        cmd.append("-O")
    if service_versions:
        cmd.append("-sV")

    if ports:
        cmd.extend(["-p", ports])

    if scripts:
        cmd.extend(["--script", scripts])

    if extra_args:
        cmd.extend(shlex.split(extra_args))

    cmd.append(target)

    print(f"[*] Running command: {' '.join(cmd)}\n")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        xml_output_lines: List[str] = []
        for line in iter(proc.stdout.readline, ""):
            if is_cancelled and is_cancelled():
                proc.terminate()
                print("\n[!] Scan cancelled")
                break

            line = line.rstrip("\n")
            if line:
                print(line)
                xml_output_lines.append(line)

                if on_output:
                    on_output(line)

        proc.wait()
        xml_output = "\n".join(xml_output_lines)
        result["raw_xml"] = xml_output

        result["ports"] = _parse_ports_from_xml(xml_output)

        if on_progress:
            on_progress(1, 1)

        open_count = sum(1 for p in result["ports"] if p.get("state") == "open")
        print("\n" + "=" * 60)
        print(f"[+] Open ports: {open_count}")
        print(f"[*] Total ports reported: {len(result['ports'])}")
        print("=" * 60)
        print("[*] Nmap scan complete")

    except FileNotFoundError:
        print("[ERROR] nmap not found on PATH")
        return {"error": "nmap not installed or not in PATH"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}

    return result


def _parse_ports_from_xml(xml_text: str) -> List[Dict[str, Any]]:
    """Minimal XML parsing to extract host/port/service info."""
    import xml.etree.ElementTree as ET

    ports: List[Dict[str, Any]] = []
    if not xml_text.strip():
        return ports

    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return ports

    for host in root.findall("host"):
        addr_elem = host.find("address")
        ip = addr_elem.get("addr") if addr_elem is not None else "unknown"

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            port_id = port_elem.get("portid")
            proto = port_elem.get("protocol")
            state_elem = port_elem.find("state")
            service_elem = port_elem.find("service")

            state = state_elem.get("state") if state_elem is not None else "unknown"
            service = service_elem.get("name") if service_elem is not None else ""
            product = service_elem.get("product") if service_elem is not None else ""
            version = service_elem.get("version") if service_elem is not None else ""

            ports.append(
                {
                    "ip": ip,
                    "port": int(port_id) if port_id and port_id.isdigit() else port_id,
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                }
            )

    return ports
