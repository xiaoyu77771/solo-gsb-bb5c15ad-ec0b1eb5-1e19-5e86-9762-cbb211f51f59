"""Pydantic request/response models."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator, model_validator

_SHA256_PATTERN = r"^[0-9a-fA-F]{64}$"


class CreateSessionRequest(BaseModel):
    file_name: str = Field(min_length=1, max_length=255)
    total_size: int = Field(ge=1, description="Total file size in bytes")
    chunk_size: int = Field(ge=1, description="Size of every chunk except the last")
    total_chunks: int = Field(ge=1)
    file_sha256: str = Field(pattern=_SHA256_PATTERN, description="SHA-256 of the whole file")

    @field_validator("file_sha256")
    @classmethod
    def _normalize_sha(cls, value: str) -> str:
        return value.lower()

    @model_validator(mode="after")
    def _check_chunk_math(self) -> "CreateSessionRequest":
        expected = -(-self.total_size // self.chunk_size)  # ceil division
        if self.total_chunks != expected:
            raise ValueError(
                f"total_chunks must equal ceil(total_size / chunk_size) = {expected}"
            )
        return self


class SessionResponse(BaseModel):
    session_id: str
    status: str
    file_name: str
    total_size: int
    chunk_size: int
    total_chunks: int
    file_sha256: str
    instant: bool = Field(description="True when the file already existed and no upload is needed")
    archive_sha256: str | None
    created_at: str


class ChunkUploadResponse(BaseModel):
    session_id: str
    chunk_index: int
    size: int
    sha256: str
    duplicate: bool = Field(description="True when this exact chunk was already stored")
    received_chunks: int
    total_chunks: int


class SessionStatusResponse(BaseModel):
    session_id: str
    status: str
    file_name: str
    total_size: int
    chunk_size: int
    total_chunks: int
    file_sha256: str
    received_chunks: int
    uploaded_chunks: list[int]
    missing_chunks: list[int]
    archive_sha256: str | None
    last_error: str | None
    created_at: str
    updated_at: str
    completed_at: str | None


class CompleteResponse(BaseModel):
    session_id: str
    status: str
    archive_sha256: str
    size: int
    deduplicated: bool = Field(description="True when an existing object was reused")


class ArchiveResponse(BaseModel):
    sha256: str
    file_name: str
    size: int
    ref_count: int
    created_at: str


class DeleteSessionResponse(BaseModel):
    session_id: str
    deleted: bool
    archive_released: bool = Field(description="The session held an archive reference that was released")
    archive_deleted: bool = Field(description="The archive object was removed (refcount reached zero)")


class CreateShareRequest(BaseModel):
    expires_in: int = Field(
        ge=1, le=2_592_000, description="Share lifetime in seconds (max 30 days)"
    )
    max_downloads: int = Field(
        ge=1, le=10_000, description="Maximum number of allowed downloads"
    )


class ShareResponse(BaseModel):
    token: str = Field(
        description="Download token, returned only here; the server stores just its hash"
    )
    archive_sha256: str
    expires_at: str
    max_downloads: int
    created_at: str


class RevokeShareResponse(BaseModel):
    revoked: bool
    already_revoked: bool = Field(description="True when the share was already revoked")
