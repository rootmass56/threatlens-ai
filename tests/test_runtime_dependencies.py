
from importlib.metadata import PackageNotFoundError, version


def test_security_api_runtime_and_test_versions_are_pinned() -> None:
    """Prevent dependency drift across the verified Windows release environment."""

    expected = {
        "pip": "26.2.1",
        "setuptools": "84.0.0",
        "wheel": "0.48.0",
        "streamlit": "1.66.1",
        "fastapi": "0.141.1",
        "starlette": "1.7.0",
        "uvicorn": "0.53.0",
        "argon2-cffi": "25.1.0",
        "PyJWT": "2.15.0",
        "python-multipart": "0.0.32",
        "email-validator": "2.3.0",
        "pandas": "2.2.3",
        "Pillow": "13.0.0",
        "plotly": "6.5.2",
        "reportlab": "5.0.1",
        "python-dotenv": "1.2.3",
        "pydantic": "2.13.5",
        "requests": "2.34.2",
        "sqlalchemy": "2.0.54",
        "alembic": "1.20.0",
        "psycopg": "3.3.6",
        "pgvector": "0.5.0",
        "redis": "8.1.0",
        "PyYAML": "6.0.3",
        "pytest": "9.1.1",
        "pytest-cov": "7.1.0",
        "httpx2": "2.13.1",
        "ruff": "0.16.8",
    }
    assert {package: version(package) for package in expected} == expected
    try:
        chroma_version = version("chromadb")
    except PackageNotFoundError:
        chroma_version = None
    assert chroma_version is None, "ChromaDB must not be installed in the v0.12.0 environment."
