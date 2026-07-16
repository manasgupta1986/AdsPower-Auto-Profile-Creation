import json
import os
import platform
import time
from typing import Dict, List, Optional, Tuple

import requests

PORTAL_BASE_URL = os.getenv("PORTAL_BASE_URL", "http://127.0.0.1:8000")
CONNECTOR_NAME = os.getenv("CONNECTOR_NAME", platform.node() or "local-connector")
CONNECTOR_HOST_OS = os.getenv("CONNECTOR_HOST_OS", platform.system())
CONNECTOR_TOKEN = os.getenv("PORTAL_CONNECTOR_SHARED_TOKEN", "change-connector-token")
ADSP_LOCAL_API_BASE = os.getenv("ADSP_LOCAL_API_BASE", "http://localhost:50325")
ADSP_LOCAL_API_BEARER = os.getenv("ADSP_LOCAL_API_BEARER", "")
POLL_SECONDS = int(os.getenv("CONNECTOR_POLL_SECONDS", "5"))
CATEGORY_REFRESH_SECONDS = int(os.getenv("CONNECTOR_CATEGORY_REFRESH_SECONDS", "300"))

CATEGORY_CACHE: Dict[str, Dict[str, str]] = {
    "extension": {},
    "application": {},
}
CONNECTOR_CATEGORY_SNAPSHOT: List[Dict] = []
LAST_CATEGORY_REFRESH_TS = 0.0


def portal_headers():
    return {"x-connector-token": CONNECTOR_TOKEN, "Content-Type": "application/json"}


def adsp_headers():
    headers = {"Content-Type": "application/json"}
    if ADSP_LOCAL_API_BEARER:
        headers["Authorization"] = f"Bearer {ADSP_LOCAL_API_BEARER}"
    return headers


def normalize_label(value: Optional[str]) -> str:
    return " ".join(str(value or "").strip().lower().split())


def get_connector_extension_categories_snapshot(force_refresh: bool = False) -> List[Dict]:
    global CONNECTOR_CATEGORY_SNAPSHOT, LAST_CATEGORY_REFRESH_TS
    now = time.time()
    if not force_refresh and CONNECTOR_CATEGORY_SNAPSHOT and (now - LAST_CATEGORY_REFRESH_TS) < CATEGORY_REFRESH_SECONDS:
        return CONNECTOR_CATEGORY_SNAPSHOT
    rows = fetch_all_extension_categories()
    snapshot = []
    for row in rows:
        category_id = str(row.get("category_id") or "").strip()
        category_name = str(row.get("category_name") or "").strip()
        if not category_id or not category_name:
            continue
        snapshot.append({"category_id": category_id, "category_name": category_name})
    CONNECTOR_CATEGORY_SNAPSHOT = snapshot
    LAST_CATEGORY_REFRESH_TS = now
    return CONNECTOR_CATEGORY_SNAPSHOT


def heartbeat():
    try:
        extension_categories = get_connector_extension_categories_snapshot()
    except Exception as exc:
        print(f"Category sync warning: {exc}")
        extension_categories = []
    payload = {"name": CONNECTOR_NAME, "host_os": CONNECTOR_HOST_OS, "extension_categories": extension_categories}
    requests.post(f"{PORTAL_BASE_URL}/api/connector/heartbeat", headers=portal_headers(), data=json.dumps(payload), timeout=20).raise_for_status()


def fetch_job():
    payload = {"name": CONNECTOR_NAME, "host_os": CONNECTOR_HOST_OS, "extension_categories": CONNECTOR_CATEGORY_SNAPSHOT}
    res = requests.post(f"{PORTAL_BASE_URL}/api/connector/fetch-job", headers=portal_headers(), data=json.dumps(payload), timeout=30)
    res.raise_for_status()
    return res.json().get("job")


def send_result(job_id, status, result):
    payload = {"status": status, "result": result}
    res = requests.post(f"{PORTAL_BASE_URL}/api/connector/jobs/{job_id}/result", headers=portal_headers(), data=json.dumps(payload), timeout=30)
    res.raise_for_status()


def adsp_get(path: str, params: Optional[Dict] = None) -> Dict:
    endpoint = f"{ADSP_LOCAL_API_BASE}{path}"
    res = requests.get(endpoint, headers=adsp_headers(), params=params or {}, timeout=30)
    res.raise_for_status()
    return res.json() if "application/json" in res.headers.get("content-type", "") else {"raw": res.text}


def fetch_all_extension_categories() -> List[Dict]:
    rows = []
    page = 1
    while True:
        data = adsp_get("/api/v2/category/list", {"page": page, "limit": 100})
        batch = (((data or {}).get("data") or {}).get("list") or [])
        if not batch:
            break
        rows.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return rows


def fetch_all_application_categories() -> List[Dict]:
    rows = []
    page = 1
    while True:
        data = adsp_get("/api/v1/application/list", {"page": page, "page_size": 100})
        batch = (((data or {}).get("data") or {}).get("list") or [])
        if not batch:
            break
        rows.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return rows


def resolve_extension_category_id(category_name: str) -> Tuple[str, Dict]:
    clean_name = str(category_name or "").strip()
    if not clean_name:
        raise ValueError("Extension category name is empty")
    if clean_name.isdigit():
        return clean_name, {"source": "direct_numeric", "matched_name": clean_name}

    wanted = normalize_label(clean_name)
    if wanted in CATEGORY_CACHE["extension"]:
        return CATEGORY_CACHE["extension"][wanted], {"source": "extension_cache", "matched_name": clean_name}
    if wanted in CATEGORY_CACHE["application"]:
        return CATEGORY_CACHE["application"][wanted], {"source": "application_cache", "matched_name": clean_name}

    extension_rows = fetch_all_extension_categories()
    for row in extension_rows:
        name = row.get("category_name") or ""
        normalized = normalize_label(name)
        category_id = str(row.get("category_id") or "").strip()
        if normalized and category_id:
            CATEGORY_CACHE["extension"][normalized] = category_id
    if wanted in CATEGORY_CACHE["extension"]:
        return CATEGORY_CACHE["extension"][wanted], {"source": "extension_category", "matched_name": clean_name}

    application_rows = fetch_all_application_categories()
    for row in application_rows:
        name = row.get("name") or ""
        normalized = normalize_label(name)
        category_id = str(row.get("id") or "").strip()
        if normalized and category_id:
            CATEGORY_CACHE["application"][normalized] = category_id
    if wanted in CATEGORY_CACHE["application"]:
        return CATEGORY_CACHE["application"][wanted], {"source": "application_category", "matched_name": clean_name}

    suggestions = []
    for row in extension_rows:
        name = row.get("category_name") or ""
        if wanted in normalize_label(name) or normalize_label(name) in wanted:
            suggestions.append(name)
    for row in application_rows:
        name = row.get("name") or ""
        if wanted in normalize_label(name) or normalize_label(name) in wanted:
            suggestions.append(name)
    suggestions = list(dict.fromkeys([s for s in suggestions if s]))[:5]
    suffix = f" Suggested matches: {', '.join(suggestions)}" if suggestions else ""
    raise ValueError(f"Extension category '{clean_name}' was not found in AdsPower.{suffix}")


def mask_payload_preview(payload: Dict, extension_resolution: Optional[Dict] = None) -> Dict:
    proxy_cfg = payload.get("user_proxy_config") or {}
    masked_proxy = {}
    if proxy_cfg:
        masked_proxy = {
            "proxy_soft": proxy_cfg.get("proxy_soft"),
            "proxy_type": proxy_cfg.get("proxy_type"),
            "proxy_host": proxy_cfg.get("proxy_host"),
            "proxy_port": proxy_cfg.get("proxy_port"),
            "proxy_user": proxy_cfg.get("proxy_user"),
            "proxy_password": "***" if proxy_cfg.get("proxy_password") else "",
        }
    return {
        "name": payload.get("name"),
        "group_id": payload.get("group_id"),
        "country": payload.get("country"),
        "ipchecker": payload.get("ipchecker"),
        "sys_app_cate_id": payload.get("sys_app_cate_id"),
        "extension_resolution": extension_resolution or {},
        "user_proxy_config": masked_proxy,
    }


def prepare_payload_for_adspower(payload: Dict) -> Tuple[Dict, Dict]:
    prepared = json.loads(json.dumps(payload))
    extension_name = str(prepared.pop("extension_category_name", "") or "").strip()
    extension_resolution = {}

    if extension_name:
        category_id, extension_resolution = resolve_extension_category_id(extension_name)
        prepared["sys_app_cate_id"] = str(category_id)
        extension_resolution = {
            **extension_resolution,
            "input_name": extension_name,
            "resolved_sys_app_cate_id": str(category_id),
        }

    ipchecker = str(prepared.get("ipchecker", "") or "").strip().lower()
    if ipchecker not in {"ip2location", "ipapi"}:
        prepared.pop("ipchecker", None)
    else:
        prepared["ipchecker"] = ipchecker

    return prepared, extension_resolution


def create_profile_in_adspower(payload):
    prepared_payload, extension_resolution = prepare_payload_for_adspower(payload)
    endpoint = f"{ADSP_LOCAL_API_BASE}/api/v2/browser-profile/create"
    res = requests.post(endpoint, headers=adsp_headers(), data=json.dumps(prepared_payload), timeout=60)
    body = res.json() if "application/json" in res.headers.get("content-type", "") else res.text
    return {
        "status_code": res.status_code,
        "body": body,
        "payload_preview": mask_payload_preview(prepared_payload, extension_resolution),
    }


def main():
    print(f"Starting connector {CONNECTOR_NAME} for {PORTAL_BASE_URL} -> {ADSP_LOCAL_API_BASE}")
    while True:
        try:
            heartbeat()
            job = fetch_job()
            if not job:
                time.sleep(POLL_SECONDS)
                continue
            try:
                result = create_profile_in_adspower(job["payload"])
                status = "completed" if result.get("status_code") == 200 and isinstance(result.get("body"), dict) and result["body"].get("code") == 0 else "failed"
            except Exception as job_exc:
                status = "failed"
                result = {"error": str(job_exc)}
            send_result(job["id"], status, result)
        except Exception as exc:
            print(f"Connector loop error: {exc}")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
