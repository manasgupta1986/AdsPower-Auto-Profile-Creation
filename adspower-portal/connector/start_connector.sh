#!/usr/bin/env bash
set -euo pipefail
export PORTAL_BASE_URL="${PORTAL_BASE_URL:-http://127.0.0.1:8000}"
export CONNECTOR_NAME="${CONNECTOR_NAME:-$(hostname)}"
export CONNECTOR_HOST_OS="${CONNECTOR_HOST_OS:-$(uname -s)}"
export PORTAL_CONNECTOR_SHARED_TOKEN="${PORTAL_CONNECTOR_SHARED_TOKEN:-change-connector-token}"
export ADSP_LOCAL_API_BASE="${ADSP_LOCAL_API_BASE:-http://localhost:50325}"
python3 connector.py
