from __future__ import annotations

from tests.test_v09_security_api import (
    auth_header,
    login,
    security_environment,  # noqa: F401 - imported pytest fixture is discovered by name
)


def test_unrecognized_telemetry_returns_controlled_422(
    security_environment,  # noqa: F811 - pytest injects the imported fixture
) -> None:
    client, _ = security_environment
    analyst = login(client, "analyst", "AnalystPass!234")

    response = client.post(
        "/api/v1/analyses/upload",
        headers=auth_header(analyst),
        data={
            "analysis_name": "Phase 3C unsupported telemetry regression",
            "allow_duplicate": "false",
        },
        files=[
            (
                "files",
                (
                    "unsupported.txt",
                    b"phase3c intentionally unrecognized telemetry qzxv-917 no parser markers\n",
                    "text/plain",
                ),
            )
        ],
    )

    assert response.status_code == 422
    payload = response.json()
    assert payload["error"]["code"] == "unsupported_telemetry"
    assert payload["error"]["request_id"] == response.headers["x-request-id"]
    assert "traceback" not in response.text.lower()
    assert "connectornotfounderror" not in response.text.lower()
