import socket
from typing import List

from cyber_hygiene_scanner.models import PortCheck

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP alternate",
}


def is_port_open(host: str, port: int, timeout: float = 0.8) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        return result == 0


def scan_common_ports(host: str, ports: List[int] | None = None) -> List[PortCheck]:
    ports_to_scan = ports or list(COMMON_PORTS.keys())
    results: List[PortCheck] = []

    for port in ports_to_scan:
        service = COMMON_PORTS.get(port, "Unknown")
        try:
            open_port = is_port_open(host, port)
        except OSError:
            open_port = False

        results.append(PortCheck(port=port, service=service, open=open_port))

    return results
