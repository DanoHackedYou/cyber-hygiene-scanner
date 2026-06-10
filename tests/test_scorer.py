from cyber_hygiene_scanner.models import HeaderCheck, PortCheck
from cyber_hygiene_scanner.services.scorer import calculate_score, risk_level


def test_risk_level_low():
    assert risk_level(90) == "Low"


def test_risk_level_critical():
    assert risk_level(20) == "Critical"


def test_score_penalizes_missing_headers():
    headers = [
        HeaderCheck(name="A", present=False, recommendation="Add A"),
        HeaderCheck(name="B", present=True, value="ok", recommendation="Add B"),
    ]
    ports = [PortCheck(port=443, service="HTTPS", open=True)]

    score = calculate_score(
        https_enabled=True,
        redirects_to_https=True,
        headers=headers,
        ports=ports,
        exposes_server_header=False,
        exposes_powered_by_header=False,
    )

    assert score == 93
