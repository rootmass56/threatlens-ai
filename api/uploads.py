from __future__ import annotations

from pathlib import PurePath

from fastapi import HTTPException, UploadFile, status

_ALLOWED_UPLOAD_SUFFIXES = frozenset({".log", ".txt", ".json", ".jsonl", ".ndjson", ".csv"})
_GENERIC_CONTENT_TYPES = frozenset({"", "application/octet-stream"})
_CONTENT_TYPES_BY_SUFFIX: dict[str, frozenset[str]] = {
    ".log": frozenset({"text/plain"}),
    ".txt": frozenset({"text/plain"}),
    ".json": frozenset({"application/json", "text/json", "text/plain"}),
    ".jsonl": frozenset(
        {
            "application/json",
            "application/jsonl",
            "application/x-ndjson",
            "text/plain",
        }
    ),
    ".ndjson": frozenset(
        {
            "application/json",
            "application/jsonl",
            "application/x-ndjson",
            "text/plain",
        }
    ),
    ".csv": frozenset({"text/csv", "application/csv", "text/plain"}),
}


def safe_upload_filename(value: str | None) -> str:
    normalized = (value or "telemetry.log").replace("\\", "/")
    filename = PurePath(normalized).name
    suffix = PurePath(filename).suffix.lower()
    if (
        not filename
        or filename in {".", ".."}
        or any(ord(char) < 32 for char in filename)
        or suffix not in _ALLOWED_UPLOAD_SUFFIXES
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "invalid_filename",
                "message": (
                    "Upload filename is invalid or uses an unsupported extension. "
                    "Allowed: .log, .txt, .json, .jsonl, .ndjson, .csv."
                ),
            },
        )
    return filename[:255]


def validate_upload_content_type(upload: UploadFile, filename: str) -> None:
    content_type = (upload.content_type or "").split(";", 1)[0].strip().lower()
    suffix = PurePath(filename).suffix.lower()
    allowed = _CONTENT_TYPES_BY_SUFFIX[suffix] | _GENERIC_CONTENT_TYPES
    if content_type not in allowed:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={
                "code": "unsupported_media_type",
                "message": (
                    f"{filename} declares unsupported media type {content_type or 'unknown'}."
                ),
            },
        )


async def read_limited_upload(
    upload: UploadFile,
    *,
    maximum_bytes: int,
) -> tuple[str, bytes]:
    filename = safe_upload_filename(upload.filename)
    validate_upload_content_type(upload, filename)
    content = await upload.read(maximum_bytes + 1)
    if not content:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"code": "empty_upload", "message": f"{filename} is empty."},
        )
    if len(content) > maximum_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "code": "upload_too_large",
                "message": f"{filename} exceeds the configured upload limit.",
            },
        )
    return filename, content
