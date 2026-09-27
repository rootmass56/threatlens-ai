
from importlib.metadata import PackageNotFoundError, version


def test_security_api_runtime_and_test_versions_are_pinned() -> None:
    """Prevent dependency drift across the verified Windows release environment."""

    expected = {
        "pip": "26.2.1",
        "setuptools": "84.0.0",
        "wheel": "0.47.0",
        "streamlit": "1.61.1",
        "fastapi": "0.141.1",
        "starlette": "1.3.1",
        "uvicorn": "0.48.0",
        "argon2-cffi": "25.1.0",
        "PyJWT": "2.13.0",
        "python-multipart": "0.0.32",
        "email-validator": "2.3.0",
        "pandas": "2.2.3",
        "plotly": "6.5.2",
        "reportlab": "4.4.9",
        "python-dotenv": "1.2.2",
        "pydantic": "2.13.4",
        "requests": "2.34.2",
        "sqlalchemy": "2.0.50",
        "alembic": "1.18.4",
        "psycopg": "3.3.4",
        "pgvector": "0.5.0",
        "redis": "8.1.0",
        "PyYAML": "6.0.3",
        "pytest": "9.0.3",
        "pytest-cov": "7.0.0",
        "httpx2": "2.12.0",
        "ruff": "0.15.22",
    }
    assert {package: version(package) for package in expected} == expected
    try:
        chroma_version = version("chromadb")
    except PackageNotFoundError:
        chroma_version = None
    assert chroma_version is None, "ChromaDB must not be installed in the v0.12.0 environment."
