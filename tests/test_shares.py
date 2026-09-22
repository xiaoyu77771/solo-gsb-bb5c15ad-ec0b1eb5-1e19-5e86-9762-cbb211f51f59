"""Tests for controlled share downloads (create / download / revoke)."""
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    from app.config import get_settings

    get_settings.cache_clear()
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def _gen(size: int, seed: bytes) -> bytes:
    """Deterministic pseudo-random content."""
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:size]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _db(sql: str, params: tuple = ()):
    """Run a read query against the test database."""
    from app.config import get_settings
    from app.db import connect

    conn = connect(get_settings().db_path)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def _db_exec(sql: str, params: tuple = ()) -> None:
    from app.config import get_settings
    from app.db import connect

    conn = connect(get_settings().db_path)
    try:
        conn.execute(sql, params)
    finally:
        conn.close()


def make_archive(client: TestClient, data: bytes, chunk_size: int = 100_000,
                 name: str = "blob.bin") -> tuple[str, str]:
    """Upload and complete a session; returns (session_id, archive_sha256)."""
    total = len(data)
    total_chunks = -(-total // chunk_size)
    resp = client.post(
        "/v1/sessions",
        json={
            "file_name": name,
            "total_size": total,
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
            "file_sha256": sha256(data),
        },
    )
    assert resp.status_code == 201, resp.text
    sid = resp.json()["session_id"]
    if resp.json()["status"] != "completed":
        for index in range(total_chunks):
            piece = data[index * chunk_size : (index + 1) * chunk_size]
            r = client.put(
                f"/v1/sessions/{sid}/chunks/{index}",
                content=piece,
                headers={"X-Chunk-SHA256": sha256(piece)},
            )
            assert r.status_code == 200, r.text
        done = client.post(f"/v1/sessions/{sid}/complete")
        assert done.status_code == 200, done.text
    return sid, sha256(data)


def create_share(client: TestClient, archive_sha: str,
                 expires_in: int = 3600, max_downloads: int = 3) -> dict:
    resp = client.post(
        f"/v1/archives/{archive_sha}/shares",
        json={"expires_in": expires_in, "max_downloads": max_downloads},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_share_full_flow_and_quota(client):
    data = _gen(250_000, b"share-flow")
    _, archive = make_archive(client, data)
    share = create_share(client, archive, expires_in=3600, max_downloads=2)
    token = share["token"]
    assert share["archive_sha256"] == archive
    assert share["max_downloads"] == 2

    for _ in range(2):
        resp = client.get(f"/v1/shares/{token}/download")
        assert resp.status_code == 200
        assert resp.content == data

    # Quota exhausted: clear 410, and the counter stays at max.
    resp = client.get(f"/v1/shares/{token}/download")
    assert resp.status_code == 410
    assert "limit" in resp.json()["detail"]
    assert _db("SELECT downloads_used FROM shares")[0]["downloads_used"] == 2

    # The original download endpoint is unaffected by share quotas.
    direct = client.get(f"/v1/archives/{archive}/download")
    assert direct.status_code == 200
    assert direct.content == data


def test_token_is_irreversible_and_shown_once(client):
    data = _gen(50_000, b"token-hash")
    _, archive = make_archive(client, data)
    share = create_share(client, archive)
    token = share["token"]

    rows = _db("SELECT token_hash FROM shares")
    assert len(rows) == 1
    # Only the SHA-256 of the token is stored; the raw token appears nowhere.
    assert rows[0]["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert rows[0]["token_hash"] != token


def test_create_share_unknown_archive_404(client):
    missing = sha256(b"no such archive")
    resp = client.post(
        f"/v1/archives/{missing}/shares",
        json={"expires_in": 60, "max_downloads": 1},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "archive not found"


def test_create_share_rejects_bad_sha_and_bad_params(client):
    resp = client.post(
        "/v1/archives/not-a-hash/shares",
        json={"expires_in": 60, "max_downloads": 1},
    )
    assert resp.status_code == 400

    data = _gen(50_000, b"params")
    _, archive = make_archive(client, data)
    for body in (
        {"expires_in": 0, "max_downloads": 1},
        {"expires_in": -5, "max_downloads": 1},
        {"expires_in": 60, "max_downloads": 0},
        {"expires_in": 60},
        {"max_downloads": 1},
    ):
        assert client.post(f"/v1/archives/{archive}/shares", json=body).status_code == 422


def test_expired_share_rejected_without_consuming_quota(client):
    data = _gen(50_000, b"expired")
    _, archive = make_archive(client, data)
    share = create_share(client, archive, expires_in=3600, max_downloads=2)
    token = share["token"]

    # Push the expiry into the past.
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    _db_exec("UPDATE shares SET expires_at=?", (past,))

    resp = client.get(f"/v1/shares/{token}/download")
    assert resp.status_code == 410
    assert "expired" in resp.json()["detail"]
    # Failed validation must not consume a download.
    assert _db("SELECT downloads_used FROM shares")[0]["downloads_used"] == 0


def test_revoke_share(client):
    data = _gen(50_000, b"revoke")
    _, archive = make_archive(client, data)
    share = create_share(client, archive)
    token = share["token"]

    resp = client.delete(f"/v1/shares/{token}")
    assert resp.status_code == 200
    assert resp.json() == {"revoked": True, "already_revoked": False}

    resp = client.get(f"/v1/shares/{token}/download")
    assert resp.status_code == 410
    assert "revoked" in resp.json()["detail"]
    assert _db("SELECT downloads_used FROM shares")[0]["downloads_used"] == 0

    # Revoking again is idempotent.
    resp = client.delete(f"/v1/shares/{token}")
    assert resp.status_code == 200
    assert resp.json() == {"revoked": True, "already_revoked": True}


def test_unknown_token_404(client):
    assert client.get("/v1/shares/no-such-token/download").status_code == 404
    assert client.delete("/v1/shares/no-such-token").status_code == 404


def test_share_dies_with_archive(client):
    data = _gen(50_000, b"cascade")
    sid, archive = make_archive(client, data)
    share = create_share(client, archive)

    # Releasing the last reference deletes the archive and cascades to shares.
    resp = client.delete(f"/v1/sessions/{sid}")
    assert resp.json()["archive_deleted"] is True
    assert client.get(f"/v1/shares/{share['token']}/download").status_code == 404
    assert client.delete(f"/v1/shares/{share['token']}").status_code == 404
    assert _db("SELECT COUNT(*) AS c FROM shares")[0]["c"] == 0


def test_concurrent_downloads_decrement_atomically(client):
    data = _gen(200_000, b"race")
    _, archive = make_archive(client, data)
    share = create_share(client, archive, max_downloads=5)
    token = share["token"]

    def hit(_: int):
        return client.get(f"/v1/shares/{token}/download")

    with ThreadPoolExecutor(max_workers=10) as pool:
        responses = list(pool.map(hit, range(20)))

    ok = [r for r in responses if r.status_code == 200]
    gone = [r for r in responses if r.status_code == 410]
    # Exactly max_downloads requests win; the rest are rejected, never more.
    assert len(ok) == 5
    assert len(gone) == 15
    for resp in ok:
        assert resp.content == data
    assert _db("SELECT downloads_used FROM shares")[0]["downloads_used"] == 5


def test_share_state_survives_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    from app.config import get_settings
    from app.main import app

    data = _gen(150_000, b"restart")
    get_settings.cache_clear()
    with TestClient(app) as client:
        _, archive = make_archive(client, data)
        share = create_share(client, archive, max_downloads=2)
        token = share["token"]
        first = client.get(f"/v1/shares/{token}/download")
        assert first.status_code == 200

    # Simulate a process restart: fresh app instance over the same data dir.
    get_settings.cache_clear()
    with TestClient(app) as client:
        second = client.get(f"/v1/shares/{token}/download")
        assert second.status_code == 200
        assert second.content == data
        # The used quota persisted across the restart: 2 of 2 are gone.
        third = client.get(f"/v1/shares/{token}/download")
        assert third.status_code == 410
    get_settings.cache_clear()
