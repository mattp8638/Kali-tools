"""
Nmap Scanner - Advanced network port scanning and OS detection
Wrapper for the Nmap security scanner
"""
import subprocess
import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, Callable, List


def run(
    params: Dict[str, Any],
    on_progress: Callable[[int, int], None] = None,
    on_output: Callable[[str], None] = None,
    is_cancelled: Callable[[], bool] = None,
) -> Dict[str, Any]:
    """
    Run Nmap port scan with various options.
    
    Params:
        target: Target IP, hostname, or CIDR range
        scan_type: Type of scan (syn, tcp, udp, version, os)
        ports: Port specification (e.g., '1-1000', '80,443,8080')
        timing: Timing template (0-5, paranoid to insane)
        scripts: NSE scripts to run (comma-separated)
        os_detection: Enable OS detection
        service_detection: Enable service/version detection
        aggressive: Enable aggressive scan options
    """
    target = params.get("target", "")
    scan_type = params.get("scan_type", "syn")
    ports = params.get("ports", "1-1000")
    timing = params.get("timing", 3)
    scripts = params.get("scripts", "")
    os_detection = params.get("os_detection", False)
    service_detection = params.get("service_detection", True)
    aggressive = params.get("aggressive", False)
    
    if not target:
        print("[ERROR] No target specified")
        return {"error": "No target specified"}
    
    results = {
        "target": target,
        "hosts": [],
        "open_ports": [],
        "services": [],
        "os_matches": []
    }
    
    print(f"[*] Nmap starting for target: {target}")
    print(f"[*] Scan type: {scan_type}")
    print(f"[*] Ports: {ports}")
    print(f"[*] Timing: T{timing}")
    print("=" * 60)
    
    # Check if Nmap is installed
    if not _check_nmap_installed():
        print("[ERROR] Nmap not found")
        print("[*] Install from: https://nmap.org/download.html")
        return {"error": "Nmap not installed"}
    
    # Build Nmap command
    cmd = ["nmap"]
    
    # Scan type
    scan_type_map = {
        "syn": "-sS",
        "tcp": "-sT",
        "udp": "-sU",
        "version": "-sV",
        "os": "-O"
    }
    cmd.append(scan_type_map.get(scan_type, "-sS"))
    
    # Port specification
    if ports:
        cmd.extend(["-p", ports])
    
    # Timing
    cmd.append(f"-T{timing}")
    
    # OS detection
    if os_detection:
        cmd.append("-O")
    
    # Service/version detection
    if service_detection:
        cmd.append("-sV")
    
    # Aggressive scan
    if aggressive:
        cmd.append("-A")
    
    # NSE scripts
    if scripts:
        cmd.extend(["--script", scripts])
    
    # Output format
    output_dir = os.path.join(os.path.expanduser("~"), ".kali_tools_temp")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"nmap_{target.replace('/', '_')}")
    
    cmd.extend(["-oX", f"{output_file}.xml"])
    cmd.extend(["-oN", f"{output_file}.txt"])
    
    # Add target
    cmd.append(target)
    
    print(f"[*] Running command: {' '.join(cmd)}")
    print()
    
    try:
        # Run Nmap
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
                
                # Parse progress
                if "% done" in line:
                    match = re.search(r'(\d+\.\d+)% done', line)
                    if match and on_progress:
                        progress = float(match.group(1))
                        on_progress(int(progress), 100)
        
        process.wait()
        
        # Parse XML output
        xml_file = f"{output_file}.xml"
        if os.path.exists(xml_file):
            results = _parse_xml_output(xml_file, results)
        
    except FileNotFoundError:
        print("[ERROR] Nmap command not found")
        print("[*] Install from: https://nmap.org/download.html")
        return {"error": "Nmap not installed"}
    except Exception as e:
        print(f"[ERROR] {e}")
        return {"error": str(e)}
    
    print("\n" + "=" * 60)
    print(f"[+] Hosts discovered: {len(results['hosts'])}")
    print(f"[+] Open ports found: {len(results['open_ports'])}")
    print(f"[+] Services identified: {len(results['services'])}")
    if results['os_matches']:
        print(f"[+] OS matches: {len(results['os_matches'])}")
    print("=" * 60)
    print("[*] Nmap scan complete")
    
    return results


def _check_nmap_installed() -> bool:
    """Check if Nmap is installed."""
    try:
        subprocess.run(
            ["nmap", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _parse_xml_output(xml_file: str, results: Dict) -> Dict:
    """Parse Nmap XML output."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        # Parse hosts
        for host in root.findall(".//host"):
            status = host.find("status")
            if status is not None and status.get("state") == "up":
                # Get address
                address = host.find("address")
                if address is not None:
                    ip = address.get("addr")
                    
                    # Get hostname
                    hostname = ""
                    hostnames = host.find("hostnames")
                    if hostnames is not None:
                        hostname_elem = hostnames.find("hostname")
                        if hostname_elem is not None:
                            hostname = hostname_elem.get("name", "")
                    
                    results["hosts"].append({
                        "ip": ip,
                        "hostname": hostname
                    })
                    
                    # Parse ports
                    ports = host.find("ports")
                    if ports is not None:
                        for port in ports.findall("port"):
                            state = port.find("state")
                            if state is not None and state.get("state") == "open":
                                port_id = port.get("portid")
                                protocol = port.get("protocol")
                                
                                # Get service info
                                service = port.find("service")
                                service_name = ""
                                service_product = ""
                                service_version = ""
                                
                                if service is not None:
                                    service_name = service.get("name", "")
                                    service_product = service.get("product", "")
                                    service_version = service.get("version", "")
                                
                                port_info = {
                                    "host": ip,
                                    "port": port_id,
                                    "protocol": protocol,
                                    "state": "open"
                                }
                                
                                results["open_ports"].append(port_info)
                                
                                if service_name:
                                    service_info = {
                                        "host": ip,
                                        "port": port_id,
                                        "service": service_name,
                                        "product": service_product,
                                        "version": service_version
                                    }
                                    results["services"].append(service_info)
                    
                    # Parse OS detection
                    os_elem = host.find("os")
                    if os_elem is not None:
                        for osmatch in os_elem.findall("osmatch"):
                            os_name = osmatch.get("name", "")
                            accuracy = osmatch.get("accuracy", "0")
                            results["os_matches"].append({
                                "host": ip,
                                "os": os_name,
                                "accuracy": accuracy
                            })
        
        print(f"\n[+] Parsed XML output from {xml_file}")
        
    except Exception as e:
        print(f"[!] Error parsing XML: {e}")
    
    return results
