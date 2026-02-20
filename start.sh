#!/usr/bin/env bash
set -euo pipefail

export PORT="${PORT:-10000}"
exec gunicorn --bind "0.0.0.0:${PORT}" app:app --workers "${WEB_CONCURRENCY:-2}" --threads "${GUNICORN_THREADS:-4}" --timeout "${GUNICORN_TIMEOUT:-120}"
