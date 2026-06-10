from typing import List

from cyber_hygiene_scanner.models import HeaderCheck, PortCheck


def calculate_score(
    https_enabled: bool,
    redirects_to_https: bool,
    headers: List[HeaderCheck],
    ports: List[PortCheck],
    exposes_server_header: bool,
    exposes_powered_by_header: bool,
) -> int:
    score = 100

    if not https_enabled:
        score -= 30

    if not redirects_to_https:
        score -= 10

    missing_headers = [header for header in headers if not header.present]
    score -= len(missing_headers) * 7

    risky_open_ports = [port for port in ports if port.open and port.port not in {80, 443}]
    score -= len(risky_open_ports) * 8

    if exposes_server_header:
        score -= 4

    if exposes_powered_by_header:
        score -= 6

    return max(0, min(100, score))


def risk_level(score: int) -> str:
    if score >= 85:
        return "Low"
    if score >= 65:
        return "Medium"
    if score >= 40:
        return "High"
    return "Critical"
