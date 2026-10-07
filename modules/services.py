"""Service identification probes for NAMI Maps."""

import re
import socket
import ssl


COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt",
}


def identify(host: str, port: int, timeout: float = 1.0) -> dict:
    service = COMMON_SERVICES.get(port, "unknown")
    result = {"service": service, "product": "", "version": "", "banner": ""}

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        if service in {"https", "https-alt"}:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
            sock.sendall(
                b"HEAD / HTTP/1.0\r\nHost: scan\r\nConnection: close\r\n\r\n"
            )
        elif service in {"http", "http-proxy"}:
            sock.sendall(
                b"HEAD / HTTP/1.0\r\nHost: scan\r\nConnection: close\r\n\r\n"
            )

        try:
            data = sock.recv(4096)
            result["banner"] = data.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            pass
        finally:
            sock.close()

    except (OSError, ssl.SSLError):
        return result

    banner = result["banner"]

    if banner.startswith("SSH-"):
        result["service"] = "ssh"
        match = re.search(r"SSH-[0-9.]+-([^\s]+)", banner)
        if match:
            result["product"] = match.group(1)
    elif banner.startswith("HTTP/"):
        result["service"] = "https" if port in {443, 8443} else "http"
        server = re.search(r"(?im)^server:\s*(.+)$", banner)
        if server:
            result["product"] = server.group(1).strip()
        powered = re.search(r"(?im)^x-powered-by:\s*(.+)$", banner)
        if powered and not result["product"]:
            result["product"] = powered.group(1).strip()
    elif port == 21 and banner.startswith("220"):
        result["service"] = "ftp"
    elif port in {25, 465, 587} and banner.startswith("220"):
        result["service"] = "smtp"

    match = re.search(
        r"(?:version|/)([0-9]+(?:\.[0-9]+){1,3})",
        banner,
        re.I,
    )
    if match:
        result["version"] = match.group(1)

    return result
