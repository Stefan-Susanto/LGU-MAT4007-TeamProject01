"""HTTP routes for text encryption/decryption."""

from fastapi import APIRouter, HTTPException

from aescbc.api.schemas import (
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
    HealthResponse,
)
from aescbc.crypto.utils import hex_to_bytes, validate_aes_key
from aescbc.services.text_service import decrypt_text, encrypt_text

router = APIRouter(prefix="/api", tags=["api"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.post("/encrypt", response_model=EncryptResponse)
def encrypt(req: EncryptRequest) -> EncryptResponse:
    try:
        key = hex_to_bytes(req.key_hex, "key_hex")
        validate_aes_key(key)
        iv = None if req.iv_hex is None else hex_to_bytes(req.iv_hex, "iv_hex")

        result = encrypt_text(
            plaintext=req.plaintext,
            key=key,
            iv=iv,
            encoding=req.encoding,
            errors=req.errors,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return EncryptResponse(
        iv_hex=result["iv"].hex(),
        ciphertext_hex=result["ciphertext"].hex(),
        tag_hex=result["tag"].hex(),
    )


@router.post("/decrypt", response_model=DecryptResponse)
def decrypt(req: DecryptRequest) -> DecryptResponse:
    try:
        key = hex_to_bytes(req.key_hex, "key_hex")
        validate_aes_key(key)
        ciphertext = hex_to_bytes(req.ciphertext_hex, "ciphertext_hex")
        iv = hex_to_bytes(req.iv_hex, "iv_hex")
        tag = hex_to_bytes(req.tag_hex, "tag_hex")

        plaintext = decrypt_text(
            ciphertext=ciphertext,
            key=key,
            iv=iv,
            tag=tag,
            encoding=req.encoding,
            errors=req.errors,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return DecryptResponse(plaintext=plaintext)
