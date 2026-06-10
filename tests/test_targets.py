import pytest

from cyber_hygiene_scanner.utils.targets import hostname_from_url, normalize_url


def test_normalize_url_adds_https():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_https():
    assert normalize_url("https://example.com") == "https://example.com"


def test_hostname_from_url():
    assert hostname_from_url("https://example.com/path") == "example.com"


def test_empty_target_fails():
    with pytest.raises(ValueError):
        normalize_url("")
