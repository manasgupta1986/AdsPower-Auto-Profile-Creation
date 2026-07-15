import json
import os
import platform
import time

import requests

PORTAL_BASE_URL = os.getenv("PORTAL_BASE_URL", "http://127.0.0.1:8000")
CONNECTOR_NAME = os.getenv("CONNECTOR_NAME", platform.node() or "local-connector")
CONNECTOR_HOST_OS = os.getenv("CONNECTOR_HOST_OS", platform.system())
CONNECTOR_TOKEN = os.getenv("PORTAL_CONNECTOR_SHARED_TOKEN", "change-connector-token")
ADSP_LOCAL_API_BASE = os.getenv("ADSP_LOCAL_API_BASE", "http://localhost:50325")
ADSP_LOCAL_API_BEARER = os.getenv("ADSP_LOCAL_API_BEARER", "")
POLL_SECONDS = int(os.getenv("CONNECTOR_POLL_SECONDS", "5"))


def portal_headers():
    return {"x-connector-token": CONNECTOR_TOKEN, "Content-Type": "application/json"}


def adsp_headers():
    headers = {"Content-Type": "application/json"}
    if ADSP_LOCAL_API_BEARER:
        headers["Authorization"] = f"Bearer {ADSP_LOCAL_API_BEARER}"
    return headers


def heartbeat():
    payload = {"name": CONNECTOR_NAME, "host_os": CONNECTOR_HOST_OS}
    requests.post(f"{PORTAL_BASE_URL}/api/connector/heartbeat", headers=portal_headers(), data=json.dumps(payload), timeout=20).raise_for_status()


def fetch_job():
    payload = {"name": CONNECTOR_NAME, "host_os": CONNECTOR_HOST_OS}
    res = requests.post(f"{PORTAL_BASE_URL}/api/connector/fetch-job", headers=portal_headers(), data=json.dumps(payload), timeout=30)
    res.raise_for_status()
    return res.json().get("job")


def send_result(job_id, status, result):
    payload = {"status": status, "result": result}
    res = requests.post(f"{PORTAL_BASE_URL}/api/connector/jobs/{job_id}/result", headers=portal_headers(), data=json.dumps(payload), timeout=30)
    res.raise_for_status()


def create_profile_in_adspower(payload):
    endpoint = f"{ADSP_LOCAL_API_BASE}/api/v2/browser-profile/create"
    res = requests.post(endpoint, headers=adsp_headers(), data=json.dumps(payload), timeout=60)
    return {"status_code": res.status_code, "body": res.json() if 'application/json' in res.headers.get('content-type', '') else res.text}


def main():
    print(f"Starting connector {CONNECTOR_NAME} for {PORTAL_BASE_URL} -> {ADSP_LOCAL_API_BASE}")
    while True:
        try:
            heartbeat()
            job = fetch_job()
            if not job:
                time.sleep(POLL_SECONDS)
                continue
            result = create_profile_in_adspower(job["payload"])
            status = "completed" if result.get("status_code") == 200 and isinstance(result.get("body"), dict) and result["body"].get("code") == 0 else "failed"
            send_result(job["id"], status, result)
        except Exception as exc:
            print(f"Connector loop error: {exc}")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
