#!/usr/bin/env python3
"""
nmap_parser.py — Parse nmap XML output into typed records for world_model.

Usage:
    python3 nmap_parser.py <nmap_output.xml> [--db /path/to/world_model.db]

Reads nmap -oX output and extracts hosts, services, scripts, OS detection.
If --db is provided, writes directly to world_model. Otherwise prints JSON.
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(xml_path: str) -> list[dict]:
    """Parse nmap XML output into structured host/service records."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    results = []

    for host_elem in root.findall("host"):
        # Skip hosts that are down
        status = host_elem.find("status")
        if status is not None and status.get("state") != "up":
            continue

        host = {"ip": None, "hostname": None, "os": None, "services": []}

        # IP address
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host["ip"] = addr.get("addr")

        # Hostname
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                host["hostname"] = hn.get("name")
                break

        # OS detection
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                host["os"] = osmatch.get("name")
                break

        # Ports/services
        ports = host_elem.find("ports")
        if ports is not None:
            for port_elem in ports.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None:
                    continue

                svc = {
                    "port": int(port_elem.get("portid")),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state": state_elem.get("state", "unknown"),
                }

                service_elem = port_elem.find("service")
                if service_elem is not None:
                    svc["product"] = service_elem.get("name")
                    svc["version"] = service_elem.get("version")
                    svc["extra_info"] = service_elem.get("extrainfo")
                    cpe_elem = service_elem.find("cpe")
                    if cpe_elem is not None:
                        svc["cpe"] = cpe_elem.text

                    # Banner from servicefp or product+version
                    parts = [service_elem.get("product", ""), service_elem.get("version", "")]
                    if service_elem.get("extrainfo"):
                        parts.append(service_elem.get("extrainfo"))
                    svc["banner"] = " ".join(p for p in parts if p).strip() or None

                # NSE script output
                scripts = {}
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id")
                    script_output = script_elem.get("output", "")
                    if script_id:
                        scripts[script_id] = script_output.strip()
                if scripts:
                    svc["scripts"] = scripts

                host["services"].append(svc)

        # Host-level scripts (e.g., smb-os-discovery)
        hostscript = host_elem.find("hostscript")
        if hostscript is not None:
            for script_elem in hostscript.findall("script"):
                sid = script_elem.get("id", "")
                sout = script_elem.get("output", "")
                if "os-discovery" in sid and not host["os"]:
                    for line in sout.split("\n"):
                        if "OS:" in line:
                            host["os"] = line.split("OS:")[-1].strip()
                        elif "Domain name:" in line or "Domain:" in line:
                            host["domain"] = line.split(":")[-1].strip()

        if host["ip"]:
            results.append(host)

    return results


def parse_nmap_text(text: str) -> list[dict]:
    """Fallback parser for nmap normal/greppable output (less structured)."""
    import re
    results = []
    current_host = None

    for line in text.split("\n"):
        # Host discovery line
        host_match = re.match(r"Nmap scan report for (\S+?)(?:\s+\((\d+\.\d+\.\d+\.\d+)\))?", line)
        if host_match:
            if current_host and current_host["ip"]:
                results.append(current_host)
            hostname = host_match.group(1)
            ip = host_match.group(2) or hostname
            current_host = {"ip": ip, "hostname": hostname if hostname != ip else None, "os": None, "services": []}
            continue

        # Port line: 445/tcp open microsoft-ds
        port_match = re.match(r"\s*(\d+)/(tcp|udp)\s+(\w+)\s+(.*)", line)
        if port_match and current_host:
            port = int(port_match.group(1))
            protocol = port_match.group(2)
            state = port_match.group(3)
            rest = port_match.group(4).strip()

            svc = {"port": port, "protocol": protocol, "state": state}
            parts = rest.split(None, 1)
            if parts:
                svc["product"] = parts[0]
            if len(parts) > 1:
                svc["version"] = parts[1]
            svc["banner"] = rest if rest else None
            current_host["services"].append(svc)
            continue

        # OS detection
        os_match = re.match(r"OS details:\s+(.*)", line)
        if os_match and current_host:
            current_host["os"] = os_match.group(1).strip()

    if current_host and current_host["ip"]:
        results.append(current_host)

    return results


def write_to_world_model(results: list[dict], db_path: str):
    """Write parsed nmap results into world_model DB."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    for host in results:
        domain = host.get("domain")
        os_name = host.get("os")
        if os_name:
            os_name = "windows" if "windows" in os_name.lower() else "linux" if "linux" in os_name.lower() else os_name

        host_id = wm.add_host(
            ip=host["ip"],
            hostname=host.get("hostname"),
            os=os_name,
            domain=domain,
        )

        for svc in host.get("services", []):
            if svc.get("state") not in ("open", "open|filtered"):
                continue
            wm.add_service(
                host_id=host_id,
                port=svc["port"],
                protocol=svc.get("protocol", "tcp"),
                state=svc.get("state", "open"),
                product=svc.get("product"),
                version=svc.get("version"),
                cpe=svc.get("cpe"),
                banner=svc.get("banner"),
                scripts=svc.get("scripts"),
            )
    wm.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse nmap output for TAR world_model")
    parser.add_argument("input", help="Nmap XML file or - for stdin text")
    parser.add_argument("--db", help="World model DB path (writes directly)")
    parser.add_argument("--format", choices=["xml", "text"], default="xml")
    args = parser.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
        results = parse_nmap_text(text)
    elif args.format == "text":
        results = parse_nmap_text(Path(args.input).read_text())
    else:
        results = parse_nmap_xml(args.input)

    if args.db:
        write_to_world_model(results, args.db)
        total_svc = sum(len(h.get("services", [])) for h in results)
        print(json.dumps({"hosts": len(results), "services": total_svc, "written_to": args.db}))
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
