# TXT Extractor (Modernized API Service)

Backend-only extraction service for Appx-style LMS APIs.  
It authenticates with either `email/password` or `token`, fetches both purchased + non-purchased batches, extracts media/resource URLs, and stores them in `.txt` output files.

## Why the old repo stopped working
The previous codebase was tightly coupled to Telegram chat flows and older API assumptions. Key breakages identified:

1. **Outdated auth assumptions**: token flow used a placeholder user id (`"extracted_userid_from_token"`) which breaks downstream course APIs.
2. **Hardcoded transport headers and brittle parsing**: old code relied on static mobile headers and in one path parsed API payload with HTML parser.
3. **Single-endpoint dependency**: login/course methods assumed one endpoint version only; no fallback for moved/versioned routes.
4. **Mixed runtime architecture**: Telegram client + flask keepalive + legacy start scripts made Render deployments fragile.
5. **Dependency drift**: many unused, heavy, and stale libraries increased startup time and failure points.

## What is updated
- Added a clean REST API service with:
  - `GET /health`
  - `POST /extract`
  - `GET /files/<filename>` for generated txt downloads
- Refactored extraction into `service/extractor.py` with:
  - Retry-enabled HTTP session
  - Login endpoint fallbacks
  - Purchased + non-purchased batch collection
  - Batch extraction across both folder-wise(v2) and subject/topic(v3) content trees
  - AES decrypt-or-plain logic for encrypted links
  - URL dedupe and safe file naming
- Removed hardcoded secrets/tokens and made decrypt key/IV environment-overridable.
- Updated deployment/runtime config for Render free tier (`Procfile`, `start.sh`, `requirements.txt`, `Dockerfile`).

## API usage

### 1) Health check
```bash
curl http://localhost:10000/health
```

### 2) Trigger extraction
```bash
curl -X POST http://localhost:10000/extract \
  -H "Content-Type: application/json" \
  -d '{
    "api_base": "https://example-api-domain.com",
    "email": "user@example.com",
    "password": "secret123"
  }'
```

Token login example:
```bash
curl -X POST http://localhost:10000/extract \
  -H "Content-Type: application/json" \
  -d '{
    "api_base": "https://example-api-domain.com",
    "token": "your_access_token",
    "user_id": "12345"
  }'
```

Optional course filter:
```json
"course_ids": ["123", "456"]
```

### 3) Download output file
Use `download_url` from `/extract` response:
```bash
curl -OJ http://localhost:10000/files/<generated-file>.txt
```

## Environment variables
| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PORT` | No | `10000` | Web service port |
| `LOG_LEVEL` | No | `INFO` | Logging verbosity |
| `OUTPUT_DIR` | No | `outputs` | Where txt files are stored |
| `EXTRACTOR_USER_AGENT` | No | modern mobile UA | Override request UA |
| `APPX_DECRYPT_KEY` | No | `638udh3829162018` | AES key override |
| `APPX_DECRYPT_IV` | No | `fedcba9876543210` | AES iv override |
| `WEB_CONCURRENCY` | No | `2` | Gunicorn workers |
| `GUNICORN_THREADS` | No | `4` | Gunicorn threads |
| `GUNICORN_TIMEOUT` | No | `120` | Gunicorn timeout |

## Local run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Render deployment (free web service)
1. Push this repo to GitHub.
2. In Render: **New +** → **Web Service** → connect repo.
3. Runtime: **Python**.
4. Build Command:
   ```bash
   pip install -r requirements.txt
   ```
5. Start Command:
   ```bash
   ./start.sh
   ```
6. Set env vars (optional): `LOG_LEVEL`, `OUTPUT_DIR`, `WEB_CONCURRENCY` etc.
7. Deploy and verify:
   - `GET /health`
   - `POST /extract`

## Notes
- Keep credentials outside code (Render environment variables or caller-provided body).
- No frontend/UI is required.
- Service is lightweight for free-tier deployment.
