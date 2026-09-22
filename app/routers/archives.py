"""Archive endpoints: list, inspect, download."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from ..config import get_settings
from ..db import db_conn
from ..schemas import ArchiveResponse
from ..storage import object_path

router = APIRouter()

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _validate_sha(sha256: str) -> str:
    sha = sha256.lower()
    if not _SHA256_RE.fullmatch(sha):
        raise HTTPException(status_code=400, detail="sha256 must be 64 hex chars")
    return sha


def _get_archive(sha256: str):
    with db_conn() as conn:
        row = conn.execute(
            "SELECT * FROM archives WHERE sha256=?", (sha256,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="archive not found")
    return row


@router.get("", response_model=list[ArchiveResponse])
def list_archives() -> list[ArchiveResponse]:
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM archives ORDER BY created_at DESC"
        ).fetchall()
    return [
        ArchiveResponse(
            sha256=row["sha256"],
            file_name=row["file_name"],
            size=row["size"],
            ref_count=row["ref_count"],
            created_at=row["created_at"],
        )
        for row in rows
    ]


@router.get("/{sha256}", response_model=ArchiveResponse)
def get_archive(sha256: str) -> ArchiveResponse:
    row = _get_archive(_validate_sha(sha256))
    return ArchiveResponse(
        sha256=row["sha256"],
        file_name=row["file_name"],
        size=row["size"],
        ref_count=row["ref_count"],
        created_at=row["created_at"],
    )


@router.get("/{sha256}/download")
def download_archive(sha256: str) -> FileResponse:
    row = _get_archive(_validate_sha(sha256))
    path = object_path(get_settings(), row["sha256"])
    if not path.exists():
        raise HTTPException(status_code=500, detail="archive object missing on disk")
    return FileResponse(
        path,
        filename=row["file_name"],
        media_type="application/octet-stream",
    )
