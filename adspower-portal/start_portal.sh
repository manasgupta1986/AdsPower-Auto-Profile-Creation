#!/usr/bin/env bash
set -euo pipefail
export PORTAL_DB_PATH="${PORTAL_DB_PATH:-$(pwd)/portal.db}"
export PORTAL_SECRET_KEY="${PORTAL_SECRET_KEY:-change-me-in-production}"
export PORTAL_ADMIN_USERNAME="${PORTAL_ADMIN_USERNAME:-admin}"
export PORTAL_ADMIN_PASSWORD="${PORTAL_ADMIN_PASSWORD:-ChangeMe123!}"
export PORTAL_CONNECTOR_SHARED_TOKEN="${PORTAL_CONNECTOR_SHARED_TOKEN:-change-connector-token}"
uvicorn app.main:app --host 0.0.0.0 --port "${PORTAL_PORT:-8000}"
