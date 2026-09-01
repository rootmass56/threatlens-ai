from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_batch6_production_frontend_uses_same_origin_api_proxy() -> None:
    api_source = (ROOT / "frontend" / "src" / "api.ts").read_text(
        encoding="utf-8"
    )
    compose = (ROOT / "compose.batch6.yml").read_text(
        encoding="utf-8"
    )
    nginx = (ROOT / "frontend" / "nginx.conf").read_text(
        encoding="utf-8"
    )

    # Empty is intentional in the production container. Nullish
    # coalescing must preserve it instead of falling back to :8000.
    assert (
        "VITE_THREATLENS_API_URL ?? "
        "'http://127.0.0.1:8000'"
        in api_source
    )

    assert 'VITE_THREATLENS_API_URL: ""' in compose

    # The public production boundary is Nginx :8080, with /api
    # proxied to the private FastAPI service.
    assert "location /api/" in nginx
    assert "proxy_pass http://api:10000;" in nginx


def test_batch6_login_shows_same_origin_boundary() -> None:
    app_source = (ROOT / "frontend" / "src" / "App.tsx").read_text(
        encoding="utf-8"
    )

    assert "same-origin (/api)" in app_source