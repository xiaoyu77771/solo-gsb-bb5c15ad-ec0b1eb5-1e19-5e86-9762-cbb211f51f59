"""Controlled share downloads: create a share, download by token, revoke.

The raw token is returned exactly once (at creation); only its SHA-256 is
stored, so a database leak does not expose usable tokens. Download validation
and the quota decrement happen atomically inside a single BEGIN IMMEDIATE
transaction — a failed validation never consumes a download — while the file
itself is streamed after the commit, keeping long I/O out of the transaction.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from ..config import get_settings
from ..db import db_conn, immediate_tx
from ..schemas import CreateShareRequest, RevokeShareResponse, ShareResponse
from ..service import utcnow
from ..storage import object_path

router = APIRouter()

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _hash_token(token: str) -> str:
    """Irreversible lookup key: only the token's SHA-256 ever touches the DB."""
    return hashlib.sha256(token.encode()).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@router.post(
    "/v1/archives/{sha256}/shares",
    response_model=ShareResponse,
    status_code=201,
    tags=["shares"],
)
def create_share(sha256: str, payload: CreateShareRequest) -> ShareResponse:
    """Create a controlled share for an existing archive.

    The token is shown only in this response and cannot be recovered later.
    """
    sha = sha256.lower()
    if not _SHA256_RE.fullmatch(sha):
        raise HTTPException(status_code=400, detail="sha256 must be 64 hex chars")

    token = secrets.token_urlsafe(32)
    now = _utcnow()
    expires_at = now + timedelta(seconds=payload.expires_in)
    with db_conn() as conn, immediate_tx(conn):
        archive = conn.execute(
            "SELECT sha256 FROM archives WHERE sha256=?", (sha,)
        ).fetchone()
        if archive is None:
            raise HTTPException(status_code=404, detail="archive not found")
        conn.execute(
            "INSERT INTO shares (id, token_hash, archive_sha256, expires_at,"
            " max_downloads, downloads_used, created_at)"
            " VALUES (?,?,?,?,?,0,?)",
            (
                uuid.uuid4().hex,
                _hash_token(token),
                sha,
                expires_at.isoformat(),
                payload.max_downloads,
                now.isoformat(),
            ),
        )
    return ShareResponse(
        token=token,
        archive_sha256=sha,
        expires_at=expires_at.isoformat(),
        max_downloads=payload.max_downloads,
        created_at=now.isoformat(),
    )


def _validated_share(conn: sqlite3.Connection, token: str) -> sqlite3.Row:
    """Fetch a share and enforce its access rules (caller holds the write lock)."""
    row = conn.execute(
        "SELECT * FROM shares WHERE token_hash=?", (_hash_token(token),)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="share not found")
    if row["status"] == "revoked":
        raise HTTPException(status_code=410, detail="share has been revoked")
    if datetime.fromisoformat(row["expires_at"]) <= _utcnow():
        raise HTTPException(status_code=410, detail="share has expired")
    if row["downloads_used"] >= row["max_downloads"]:
        raise HTTPException(status_code=410, detail="share download limit reached")
    return row


@router.get("/v1/shares/{token}/download", tags=["shares"])
def download_share(token: str) -> FileResponse:
    """Download an archive through a share token.

    Validation and the atomic quota decrement are committed in one
    transaction; any validation failure rolls back and leaves the remaining
    count untouched. The bytes are streamed after the commit.
    """
    settings = get_settings()
    with db_conn() as conn, immediate_tx(conn):
        share = _validated_share(conn, token)
        archive_sha = share["archive_sha256"]
        path = object_path(settings, archive_sha)
        if not path.exists():
            raise HTTPException(status_code=500, detail="archive object missing on disk")
        conn.execute(
            "UPDATE shares SET downloads_used=downloads_used+1 WHERE id=?",
            (share["id"],),
        )
        file_name = conn.execute(
            "SELECT file_name FROM archives WHERE sha256=?", (archive_sha,)
        ).fetchone()["file_name"]

    return FileResponse(
        path,
        filename=file_name,
        media_type="application/octet-stream",
    )


@router.delete("/v1/shares/{token}", response_model=RevokeShareResponse, tags=["shares"])
def revoke_share(token: str) -> RevokeShareResponse:
    """Revoke a share. Idempotent: a repeat revoke reports already_revoked."""
    with db_conn() as conn, immediate_tx(conn):
        row = conn.execute(
            "SELECT status FROM shares WHERE token_hash=?", (_hash_token(token),)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="share not found")
        if row["status"] == "revoked":
            return RevokeShareResponse(revoked=True, already_revoked=True)
        conn.execute(
            "UPDATE shares SET status='revoked', revoked_at=? WHERE token_hash=?",
            (utcnow(), _hash_token(token)),
        )
    return RevokeShareResponse(revoked=True, already_revoked=False)
