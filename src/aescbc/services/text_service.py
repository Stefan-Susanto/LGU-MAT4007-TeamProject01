"""Service layer for text encryption/decryption with AES-CBC and HMAC."""

from __future__ import annotations

from typing import TypedDict

from aescbc.crypto.aes import AESCore
from aescbc.crypto.auth.hmac_sha256 import compute_hmac_sha256, verify_hmac_sha256
from aescbc.crypto.modes.cbc import CBCMode
from aescbc.crypto.padding.pkcs7 import pkcs7_pad, pkcs7_unpad
from aescbc.crypto.utils import derive_auth_key, random_iv, validate_aes_key


class PayloadResult(TypedDict):
    iv: bytes
    ciphertext: bytes
    tag: bytes


def encrypt_payload(plaintext: bytes, key: bytes, iv: bytes | None = None) -> PayloadResult:
    validate_aes_key(key)

    use_iv = iv if iv is not None else random_iv()
    if len(use_iv) != 16:
        raise ValueError("IV must be 16 bytes")

    padded = pkcs7_pad(plaintext, block_size=16)
    cipher = AESCore(key)
    cbc = CBCMode(cipher, use_iv)
    ciphertext = cbc.encrypt(padded)

    auth_key = derive_auth_key(key)
    tag = compute_hmac_sha256(auth_key, use_iv + ciphertext)

    return {
        "iv": use_iv,
        "ciphertext": ciphertext,
        "tag": tag,
    }


def decrypt_payload(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    validate_aes_key(key)

    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    if len(tag) != 32:
        raise ValueError("HMAC-SHA256 tag must be 32 bytes")

    auth_key = derive_auth_key(key)
    if not verify_hmac_sha256(auth_key, iv + ciphertext, tag):
        raise ValueError("Authentication failed: invalid HMAC")

    cipher = AESCore(key)
    cbc = CBCMode(cipher, iv)
    padded = cbc.decrypt(ciphertext)
    return pkcs7_unpad(padded, block_size=16)


def encrypt_text(
    plaintext: str,
    key: bytes,
    iv: bytes | None = None,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> PayloadResult:
    return encrypt_payload(plaintext.encode(encoding, errors=errors), key, iv=iv)


def decrypt_text(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    tag: bytes,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> str:
    raw = decrypt_payload(ciphertext, key, iv, tag)
    return raw.decode(encoding, errors=errors)
