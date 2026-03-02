# Design Notes

## Goal

Provide a clear educational stack that shows how a block cipher composes into a practical encrypted message workflow.

## Pipeline

1. AES core (`crypto/aes`) encrypts/decrypts 16-byte blocks.
2. CBC mode (`crypto/modes/cbc.py`) chains blocks with IV.
3. PKCS#7 (`crypto/padding/pkcs7.py`) handles variable-length plaintext.
4. HMAC-SHA256 (`crypto/auth/hmac_sha256.py`) authenticates `iv || ciphertext`.
5. FastAPI (`api/routes.py`) exposes HTTP endpoints.
6. Frontend (`web/templates` + `web/static`) calls API endpoints from the browser.

## API Endpoints

- `GET /api/health`
- `POST /api/encrypt`
- `POST /api/decrypt`

## Security Decisions

- Separate AES and HMAC key material via SHA-256-based derivation in `crypto/utils.py`.
- Verify HMAC before decryption to avoid processing unauthenticated ciphertext.
- Reject malformed key/IV/ciphertext/tag lengths early.
