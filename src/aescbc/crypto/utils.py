"""Utility helpers for key handling and randomness."""

from __future__ import annotations

import hashlib
import secrets


VALID_AES_KEY_LENGTHS = {16, 24, 32}


def validate_aes_key(key: bytes) -> None:
    if len(key) not in VALID_AES_KEY_LENGTHS:
        raise ValueError("AES key must be 16, 24, or 32 bytes")


def derive_auth_key(aes_key: bytes) -> bytes:
    validate_aes_key(aes_key)
    return hashlib.sha256(b"aescbc-auth:" + aes_key).digest()


def random_iv() -> bytes:
    return secrets.token_bytes(16)


def hex_to_bytes(value: str, field_name: str) -> bytes:
    try:
        parsed = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid hex") from exc
    return parsed
