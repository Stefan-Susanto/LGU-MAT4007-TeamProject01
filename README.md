# aes-cbc-project

A small AES-CBC encryption implementation with a from-scratch AES core, PKCS#7 padding, HMAC-SHA256 authentication, FastAPI backend, and a web UI for text workflows.

## Quick Start

```bash
uv sync --group dev
uv run pytest
uv run uvicorn aescbc.main:app --reload --app-dir src
```

Open `http://127.0.0.1:8000`.

## API Endpoints

- `GET /api/health`
- `POST /api/encrypt` (JSON text encrypt)
- `POST /api/decrypt` (JSON text decrypt)

## Security Note

This repository is for coursework and demonstration. Do not use this implementation as-is for production cryptographic workloads.

## Tip

For AES key generation, we recommend: [randomkeygen](https://randomkeygen.com/aes-key)
