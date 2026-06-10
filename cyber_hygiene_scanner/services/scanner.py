from cyber_hygiene_scanner.models import ScanSummary
from cyber_hygiene_scanner.services.http_checks import (
    check_security_headers,
    fetch_url,
    redirects_to_https,
)
from cyber_hygiene_scanner.services.port_scanner import scan_common_ports
from cyber_hygiene_scanner.services.scorer import calculate_score, risk_level
from cyber_hygiene_scanner.utils.targets import hostname_from_url, normalize_url


def build_recommendations(summary: ScanSummary) -> list[str]:
    recommendations: list[str] = []

    if not summary.https_enabled:
        recommendations.append("Enable HTTPS with a valid TLS certificate.")

    if not summary.redirects_to_https:
        recommendations.append("Redirect all HTTP traffic to HTTPS.")

    for header in summary.headers:
        if not header.present:
            recommendations.append(header.recommendation)

    risky_ports = [port for port in summary.ports if port.open and port.port not in {80, 443}]
    for port in risky_ports:
        recommendations.append(
            f"Review exposed port {port.port} ({port.service}) and restrict access if it is not public."
        )

    if summary.server_header:
        recommendations.append("Avoid exposing detailed Server headers when possible.")

    if summary.powered_by_header:
        recommendations.append("Remove or hide X-Powered-By headers to reduce technology fingerprinting.")

    if not recommendations:
        recommendations.append("Baseline hygiene looks good. Keep dependencies updated and monitor changes.")

    return recommendations


def scan_target(target: str, skip_ports: bool = False) -> ScanSummary:
    normalized_url = normalize_url(target)
    response = fetch_url(normalized_url)
    host = hostname_from_url(normalized_url)

    headers = check_security_headers(response.headers)
    ports = [] if skip_ports else scan_common_ports(host)

    https_enabled = response.url.startswith("https://")
    has_https_redirect = redirects_to_https(response)
    server_header = response.headers.get("Server")
    powered_by_header = response.headers.get("X-Powered-By")

    score = calculate_score(
        https_enabled=https_enabled,
        redirects_to_https=has_https_redirect,
        headers=headers,
        ports=ports,
        exposes_server_header=server_header is not None,
        exposes_powered_by_header=powered_by_header is not None,
    )

    summary = ScanSummary(
        target=target,
        normalized_url=normalized_url,
        score=score,
        risk_level=risk_level(score),
        https_enabled=https_enabled,
        redirects_to_https=has_https_redirect,
        server_header=server_header,
        powered_by_header=powered_by_header,
        headers=headers,
        ports=ports,
        recommendations=[],
    )

    summary.recommendations = build_recommendations(summary)
    return summary
