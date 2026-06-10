from urllib.parse import urlparse


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    if not parsed.netloc:
        raise ValueError("Invalid target URL.")

    return target.rstrip("/")


def hostname_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.split(":")[0]
