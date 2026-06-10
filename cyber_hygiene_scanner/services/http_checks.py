from typing import Dict, List

import requests

from cyber_hygiene_scanner.models import HeaderCheck

SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "Add HSTS to force browsers to use HTTPS.",
    "Content-Security-Policy": "Add a Content Security Policy to reduce XSS risk.",
    "X-Frame-Options": "Add X-Frame-Options or frame-ancestors to reduce clickjacking risk.",
    "X-Content-Type-Options": "Add X-Content-Type-Options: nosniff.",
    "Referrer-Policy": "Add a Referrer-Policy to limit sensitive referrer leakage.",
    "Permissions-Policy": "Add a Permissions-Policy to restrict browser features.",
}


class HttpScanError(Exception):
    pass


def fetch_url(url: str, timeout: int = 8) -> requests.Response:
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        return response
    except requests.RequestException as exc:
        raise HttpScanError(f"Could not connect to target: {exc}") from exc


def check_security_headers(headers: requests.structures.CaseInsensitiveDict) -> List[HeaderCheck]:
    results: List[HeaderCheck] = []

    for header, recommendation in SECURITY_HEADERS.items():
        value = headers.get(header)
        results.append(
            HeaderCheck(
                name=header,
                present=value is not None,
                value=value,
                recommendation=recommendation,
            )
        )

    return results


def redirects_to_https(response: requests.Response) -> bool:
    urls = [item.url for item in response.history] + [response.url]
    return any(url.startswith("https://") for url in urls)
