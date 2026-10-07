"""Output renderers for NAMI Maps."""

import json
import xml.etree.ElementTree as ET


def normal(results: list[dict], verbose: bool = False) -> str:
    lines = []
    for host in results:
        lines.append(f"NAMI scan report for {host['host']}")
        if host.get("hostname"):
            lines.append(f"Hostname: {host['hostname']}")
        lines.append(f"Host is {'up' if host.get('up') else 'down'}.")
        if host.get("ports"):
            lines.append("PORT\tSTATE\tSERVICE\tVERSION")
            for p in host["ports"]:
                version = p.get("version") or p.get("product") or ""
                lines.append(f"{p['port']}/{p['protocol']}\t{p['state']}\t{p['service']}\t{version}")
        if verbose:
            lines.append(f"Latency: {host.get('latency_ms', 0):.2f} ms")
        lines.append("")
    return "\n".join(lines)


def write_json(results: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)


def write_xml(results: list[dict], path: str) -> None:
    root = ET.Element("nami")
    for host in results:
        node = ET.SubElement(root, "host", address=host["host"], status="up" if host.get("up") else "down")
        if host.get("hostname"):
            ET.SubElement(node, "hostname").text = host["hostname"]
        ports = ET.SubElement(node, "ports")
        for p in host.get("ports", []):
            ET.SubElement(
                ports,
                "port",
                protocol=p["protocol"],
                portid=str(p["port"]),
                state=p["state"],
                service=p.get("service", ""),
                product=p.get("product", ""),
                version=p.get("version", ""),
            )
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
