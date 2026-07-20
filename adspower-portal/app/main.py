import csv
import io
import json
import math
import os
import secrets
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, inspect, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from itsdangerous import URLSafeSerializer, BadSignature

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("PORTAL_DB_PATH", os.path.join(os.path.dirname(BASE_DIR), "portal.db"))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SECRET_KEY = os.getenv("PORTAL_SECRET_KEY", "change-me-in-production")
ADMIN_USERNAME = os.getenv("PORTAL_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("PORTAL_ADMIN_PASSWORD", "ChangeMe123!")
CONNECTOR_SHARED_TOKEN = os.getenv("PORTAL_CONNECTOR_SHARED_TOKEN", "change-connector-token")
CONNECTOR_STALE_SECONDS = int(os.getenv("PORTAL_CONNECTOR_STALE_SECONDS", "120"))


def normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return "postgresql+psycopg://" + database_url[len("postgres://"):]
    if database_url.startswith("postgresql://") and "+psycopg" not in database_url:
        return "postgresql+psycopg://" + database_url[len("postgresql://"):]
    return database_url


SQLALCHEMY_DATABASE_URL = normalize_database_url(DATABASE_URL) if DATABASE_URL else f"sqlite:///{DB_PATH}"
engine_kwargs = {"pool_pre_ping": True}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(SQLALCHEMY_DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
serializer = URLSafeSerializer(SECRET_KEY, salt="adspower-portal-session")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="admin")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    code: Mapped[str] = mapped_column(String(100), unique=True)
    ads_group: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    extension_category: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    naming_pattern: Mapped[str] = mapped_column(String(255), default="Analyst_Project_Country_Device_OS_Sequence")
    desktop_pct: Mapped[float] = mapped_column(Float, default=50)
    mobile_pct: Mapped[float] = mapped_column(Float, default=50)
    windows_pct: Mapped[float] = mapped_column(Float, default=50)
    mac_pct: Mapped[float] = mapped_column(Float, default=50)
    android_pct: Mapped[float] = mapped_column(Float, default=50)
    iphone_pct: Mapped[float] = mapped_column(Float, default=50)
    default_proxy_type: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    default_proxy_soft: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    default_ipchecker: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    remark_template: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    connector_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    analysts: Mapped[List["Analyst"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    countries: Mapped[List["CountryPlan"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    proxies: Mapped[List["ProxyRecord"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    jobs: Mapped[List["ProvisionJob"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Analyst(Base):
    __tablename__ = "analysts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(255))
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    project: Mapped[Project] = relationship(back_populates="analysts")


class CountryPlan(Base):
    __tablename__ = "country_plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    country_code: Mapped[str] = mapped_column(String(50))
    total_profiles: Mapped[int] = mapped_column(Integer)
    analyst_ids_csv: Mapped[str] = mapped_column(Text, default="")
    project: Mapped[Project] = relationship(back_populates="countries")


class ProxyRecord(Base):
    __tablename__ = "proxy_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    provider: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    country_code: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    proxy_kind: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    proxy_type: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    proxy_soft: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    ipchecker: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    proxy_host: Mapped[str] = mapped_column(String(255))
    proxy_port: Mapped[str] = mapped_column(String(20))
    proxy_username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    proxy_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    raw_proxy: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    assigned: Mapped[bool] = mapped_column(Boolean, default=False)
    project: Mapped[Project] = relationship(back_populates="proxies")


class ProvisionJob(Base):
    __tablename__ = "provision_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    connector_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    profile_name: Mapped[str] = mapped_column(String(255))
    analyst_name: Mapped[str] = mapped_column(String(255))
    country_code: Mapped[str] = mapped_column(String(50))
    device_type: Mapped[str] = mapped_column(String(50))
    os_type: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50), default="pending")
    payload_json: Mapped[str] = mapped_column(Text)
    result_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    project: Mapped[Project] = relationship(back_populates="jobs")


class ConnectorHeartbeat(Base):
    __tablename__ = "connector_heartbeats"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    host_os: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    extension_categories_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category_synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(bind=engine)


def ensure_runtime_schema():
    schema_additions = {
        "projects": {
            "default_proxy_type": "VARCHAR(20)",
            "default_proxy_soft": "VARCHAR(100)",
            "default_ipchecker": "VARCHAR(50)",
        },
        "proxy_records": {
            "proxy_kind": "VARCHAR(30)",
            "proxy_type": "VARCHAR(20)",
            "proxy_soft": "VARCHAR(100)",
            "ipchecker": "VARCHAR(50)",
        },
        "connector_heartbeats": {
            "extension_categories_json": "TEXT",
            "category_synced_at": "TIMESTAMP",
        },
    }
    with engine.begin() as conn:
        inspector = inspect(conn)
        for table_name, columns in schema_additions.items():
            existing = {col["name"] for col in inspector.get_columns(table_name)}
            for column_name, column_type in columns.items():
                if column_name not in existing:
                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


ensure_runtime_schema()


def first_existing_dir(paths, required_file=None):
    for p in paths:
        if required_file:
            if os.path.isfile(os.path.join(p, required_file)):
                return p
        elif os.path.isdir(p):
            return p
    return None


STATIC_DIR = first_existing_dir([
    os.path.join(BASE_DIR, "static"),
    os.path.join(os.getcwd(), "app", "static"),
    os.path.join(os.getcwd(), "static"),
    os.path.join(os.getcwd(), "adspower-portal", "app", "static"),
])

TEMPLATE_DIR = first_existing_dir([
    os.path.join(BASE_DIR, "templates"),
    os.path.join(os.getcwd(), "app", "templates"),
    os.path.join(os.getcwd(), "templates"),
    os.path.join(os.getcwd(), "adspower-portal", "app", "templates"),
], required_file="login.html")

if not STATIC_DIR:
    STATIC_DIR = os.path.join(BASE_DIR, "static")
    os.makedirs(STATIC_DIR, exist_ok=True)

if not TEMPLATE_DIR:
    raise RuntimeError(
        f"Could not find templates folder. BASE_DIR={BASE_DIR}, CWD={os.getcwd()}"
    )

app = FastAPI(title="AdsPower Profile Provisioning Portal")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATE_DIR)




DEFAULT_EXTENSION_CATEGORY = "Use team's extensions"
DEFAULT_NAMING_PATTERN = "Analyst_Project_Country_Device_OS_Sequence"


class ProjectCreate(BaseModel):
    name: str
    code: Optional[str] = None
    ads_group: Optional[str] = None
    extension_category: Optional[str] = DEFAULT_EXTENSION_CATEGORY
    default_proxy_type: Optional[str] = "http"
    default_proxy_soft: Optional[str] = "other"
    default_ipchecker: Optional[str] = "ip2location"
    naming_pattern: str = DEFAULT_NAMING_PATTERN


class ProjectSettings(BaseModel):
    desktop_pct: float
    mobile_pct: float
    windows_pct: float
    mac_pct: float
    android_pct: float
    iphone_pct: float
    ads_group: Optional[str] = None
    extension_category: Optional[str] = DEFAULT_EXTENSION_CATEGORY
    default_proxy_type: Optional[str] = "http"
    default_proxy_soft: Optional[str] = "other"
    default_ipchecker: Optional[str] = "ip2location"
    connector_name: Optional[str] = None
    remark_template: Optional[str] = None


class CountryPlanIn(BaseModel):
    country_code: str
    total_profiles: int
    analyst_ids: List[int]


class ConnectorIn(BaseModel):
    name: str
    host_os: str
    extension_categories: Optional[List[Dict]] = None


class JobResultIn(BaseModel):
    status: str
    result: Dict


class LoginIn(BaseModel):
    username: str
    password: str


def utcnow():
    return datetime.now(timezone.utc)


def ensure_aware_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_admin():
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.username == ADMIN_USERNAME))
        if not existing:
            db.add(User(username=ADMIN_USERNAME, password_hash=pwd_context.hash(ADMIN_PASSWORD), role="admin"))
            db.commit()


seed_admin()


def set_session(response: RedirectResponse, user_id: int):
    token = serializer.dumps({"user_id": user_id})
    response.set_cookie("portal_session", token, httponly=True, samesite="lax")


def clear_session(response: RedirectResponse):
    response.delete_cookie("portal_session")


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("portal_session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = serializer.loads(token)
    except BadSignature:
        raise HTTPException(status_code=401, detail="Invalid session")
    user = db.get(User, payload.get("user_id"))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid user")
    return user


def require_connector_token(request: Request):
    auth = request.headers.get("x-connector-token", "")
    if auth != CONNECTOR_SHARED_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid connector token")


def normalize_name(value: str) -> str:
    return "_".join(value.strip().replace("/", " ").replace("-", " ").split())


def normalize_extension_category(value: Optional[str]) -> str:
    cleaned = str(value or "").strip()
    return cleaned or DEFAULT_EXTENSION_CATEGORY


def country_display_name(country_code: str) -> str:
    code = str(country_code or "").strip().upper()
    return COUNTRY_NAME_MAP.get(code, code or "UNKNOWN")


def build_profile_name(analyst_name: str, project_name: str, country_code: str, device_type: str, os_type: str, sequence: int) -> str:
    analyst_part = normalize_name(analyst_name)
    project_part = normalize_name(project_name)
    country_part = normalize_name(country_display_name(country_code))
    device_part = normalize_name(device_type).upper()
    os_part = normalize_name(os_type).upper()
    return f"{analyst_part}_{project_part}_{country_part}_{device_part}_{os_part}_{sequence:03d}"


def normalize_proxy_kind(value: Optional[str]) -> Optional[str]:
    raw = " ".join(str(value or "").strip().lower().replace("_", " ").replace("-", " ").split())
    if not raw:
        return None
    if raw in {"residential", "resi", "desktop", "desktop only", "desktop proxy"}:
        return "residential"
    if raw in {"mobile", "mobile proxy", "4g", "5g", "lte", "cellular", "mobile only"}:
        return "mobile"
    return raw


def generate_unique_project_code(db: Session, name: str) -> str:
    base = normalize_name(name).upper() or "PROJECT"
    base = "".join(ch for ch in base if ch.isalnum() or ch == "_")[:30] or "PROJECT"
    candidate = base
    index = 2
    while db.scalar(select(Project).where(Project.code == candidate)):
        suffix = f"_{index}"
        candidate = (base[: max(1, 30 - len(suffix))] + suffix)[:30]
        index += 1
    return candidate


def split_even(total: int, buckets: List[str]) -> Dict[str, int]:
    if not buckets:
        return {}
    base = total // len(buckets)
    remainder = total % len(buckets)
    result = {}
    for idx, key in enumerate(sorted(buckets)):
        result[key] = base + (1 if idx < remainder else 0)
    return result


def allocate_segments(total: int, project: Project) -> Dict[str, int]:
    desktop = round(total * (project.desktop_pct / 100.0))
    mobile = total - desktop
    windows = round(desktop * (project.windows_pct / 100.0))
    mac = desktop - windows
    android = round(mobile * (project.android_pct / 100.0))
    iphone = mobile - android
    return {
        "desktop": desktop,
        "mobile": mobile,
        "windows": windows,
        "mac": mac,
        "android": android,
        "iphone": iphone,
    }


def validate_project_settings(data: ProjectSettings):
    def near(a, b):
        return abs(a - b) < 0.01

    if not near(data.desktop_pct + data.mobile_pct, 100.0):
        raise HTTPException(status_code=400, detail="Desktop and Mobile percentages must total 100")
    if not near(data.windows_pct + data.mac_pct, 100.0):
        raise HTTPException(status_code=400, detail="Windows and Mac percentages must total 100")
    if not near(data.android_pct + data.iphone_pct, 100.0):
        raise HTTPException(status_code=400, detail="Android and iPhone percentages must total 100")
    if data.default_proxy_type and data.default_proxy_type.strip().lower() not in {"http", "https", "socks5"}:
        raise HTTPException(status_code=400, detail="Default proxy type must be http, https, or socks5")
    if data.default_ipchecker and data.default_ipchecker.strip().lower() not in {"ip2location", "ipapi"}:
        raise HTTPException(status_code=400, detail="Default IP checker must be ip2location or ipapi")


def project_to_dict(project: Project):
    return {
        "id": project.id,
        "name": project.name,
        "code": project.code,
        "ads_group": project.ads_group,
        "extension_category": normalize_extension_category(project.extension_category),
        "naming_pattern": project.naming_pattern or DEFAULT_NAMING_PATTERN,
        "desktop_pct": project.desktop_pct,
        "mobile_pct": project.mobile_pct,
        "windows_pct": project.windows_pct,
        "mac_pct": project.mac_pct,
        "android_pct": project.android_pct,
        "iphone_pct": project.iphone_pct,
        "default_proxy_type": project.default_proxy_type,
        "default_proxy_soft": project.default_proxy_soft,
        "default_ipchecker": project.default_ipchecker,
        "remark_template": project.remark_template,
        "connector_name": project.connector_name,
    }


def analyst_to_dict(a: Analyst):
    return {"id": a.id, "name": a.name, "email": a.email}


def country_to_dict(c: CountryPlan):
    analyst_ids = [int(x) for x in c.analyst_ids_csv.split(",") if x.strip()]
    return {"id": c.id, "country_code": c.country_code, "total_profiles": c.total_profiles, "analyst_ids": analyst_ids}


COUNTRY_NAME_MAP = {
    "US": "United States", "IN": "India", "GB": "United Kingdom", "AE": "United Arab Emirates", "AU": "Australia", "CA": "Canada", "DE": "Germany", "FR": "France", "IT": "Italy", "ES": "Spain", "NL": "Netherlands", "SG": "Singapore", "JP": "Japan", "KR": "South Korea", "CN": "China", "HK": "Hong Kong", "TW": "Taiwan", "BR": "Brazil", "MX": "Mexico", "ZA": "South Africa", "SA": "Saudi Arabia", "QA": "Qatar", "KW": "Kuwait", "OM": "Oman", "BH": "Bahrain", "TR": "Turkey", "ID": "Indonesia", "MY": "Malaysia", "TH": "Thailand", "VN": "Vietnam", "PH": "Philippines", "PK": "Pakistan", "BD": "Bangladesh", "LK": "Sri Lanka", "NP": "Nepal", "EG": "Egypt", "NG": "Nigeria", "KE": "Kenya", "RU": "Russia", "UA": "Ukraine", "PL": "Poland", "SE": "Sweden", "NO": "Norway", "DK": "Denmark", "CH": "Switzerland", "BE": "Belgium", "AT": "Austria", "IE": "Ireland", "PT": "Portugal", "NZ": "New Zealand", "AR": "Argentina", "CL": "Chile", "CO": "Colombia", "PE": "Peru", "IL": "Israel", "GR": "Greece", "CZ": "Czech Republic", "HU": "Hungary", "RO": "Romania"
}

COUNTRY_PREFIX_MAP = {
    "ar": "AR", "cn": "CN", "us": "US", "in": "IN", "gb": "GB", "ae": "AE", "au": "AU", "ca": "CA", "de": "DE", "fr": "FR", "it": "IT", "es": "ES", "nl": "NL", "sg": "SG", "jp": "JP", "kr": "KR", "hk": "HK", "tw": "TW", "br": "BR", "mx": "MX", "za": "ZA", "sa": "SA", "qa": "QA", "kw": "KW", "om": "OM", "bh": "BH", "tr": "TR", "id": "ID", "my": "MY", "th": "TH", "vn": "VN", "ph": "PH", "pk": "PK", "bd": "BD", "lk": "LK", "np": "NP", "eg": "EG", "ng": "NG", "ke": "KE", "ru": "RU", "ua": "UA", "pl": "PL", "se": "SE", "no": "NO", "dk": "DK", "ch": "CH", "be": "BE", "at": "AT", "ie": "IE", "pt": "PT", "nz": "NZ", "cl": "CL", "co": "CO", "pe": "PE", "il": "IL", "gr": "GR", "cz": "CZ", "hu": "HU", "ro": "RO"
}


def infer_proxy_defaults(provider: Optional[str], proxy_host: str, username: str, proxy_kind: Optional[str], proxy_type: Optional[str], country_code: Optional[str]) -> Dict[str, Optional[str]]:
    host = (proxy_host or "").strip().lower()
    user = (username or "").strip()
    provider_value = (provider or "").strip()
    kind_value = normalize_proxy_kind(proxy_kind)
    proxy_type_value = (proxy_type or "").strip().lower() or None
    country_value = (country_code or "").strip().upper() or None

    if not provider_value:
        if "ipb.cloud" in host or "ipburger" in host:
            provider_value = "IPBurger"
        elif "decodo.com" in host:
            provider_value = "Decodo"

    if not kind_value:
        if "mobile" in host or "mobile" in user.lower() or "-mobile-" in user.lower():
            kind_value = "mobile"
        elif "decodo.com" in host or "residential" in host or "residential" in user.lower():
            kind_value = "residential"

    if not proxy_type_value:
        proxy_type_value = "http"

    if not country_value:
        user_upper = user.upper()
        if "-CC-" in user_upper:
            try:
                country_value = user_upper.split("-CC-", 1)[1][:2]
            except Exception:
                pass
        if not country_value and host:
            prefix = host.split(".", 1)[0].lower()
            country_value = COUNTRY_PREFIX_MAP.get(prefix)

    return {
        "provider": provider_value or None,
        "proxy_kind": kind_value or None,
        "proxy_type": proxy_type_value or None,
        "country_code": country_value or None,
    }


def parse_proxy_line(line: str) -> Dict[str, Optional[str]]:
    raw = str(line or "").strip()
    if not raw:
        raise ValueError("Empty proxy line")
    host = port = username = password = proxy_type = ""
    if " " in raw and raw.split(" ", 1)[0].startswith(("http://", "https://", "socks5://")):
        endpoint, creds = raw.split(None, 1)
        parsed = urlparse(endpoint)
        host = parsed.hostname or ""
        port = str(parsed.port or "")
        proxy_type = (parsed.scheme or "").lower()
        if ":" not in creds:
            raise ValueError("Raw proxy line missing username:password after endpoint")
        username, password = creds.split(":", 1)
    elif raw.startswith(("http://", "https://", "socks5://")):
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = str(parsed.port or "")
        proxy_type = (parsed.scheme or "").lower()
        username = parsed.username or ""
        password = parsed.password or ""
    else:
        parts = raw.split(":")
        if len(parts) >= 4:
            host, port, username, password = parts[0], parts[1], parts[2], ":".join(parts[3:])
        elif len(parts) == 2:
            host, port = parts
        else:
            raise ValueError("Unsupported raw proxy line format")
        proxy_type = "http"
    if not host or not port:
        raise ValueError("Raw proxy line missing host or port")
    inferred = infer_proxy_defaults(None, host, username, None, proxy_type, None)
    return {
        "provider": inferred["provider"],
        "country_code": inferred["country_code"],
        "proxy_kind": inferred["proxy_kind"],
        "proxy_type": inferred["proxy_type"],
        "proxy_soft": "other",
        "ipchecker": None,
        "proxy_host": host,
        "proxy_port": port,
        "proxy_username": username or None,
        "proxy_password": password or None,
        "raw_proxy": raw,
    }


def parse_proxy_row(row: Dict[str, str]) -> Dict[str, Optional[str]]:
    norm = {str(k).strip().lower(): (str(v).strip() if v is not None else "") for k, v in row.items()}
    proxy_string = norm.get("proxy") or norm.get("proxy_string") or norm.get("raw_proxy") or norm.get("endpoint") or norm.get("server") or norm.get("address") or ""
    host = norm.get("proxy_host") or norm.get("host") or norm.get("server_host") or ""
    port = norm.get("proxy_port") or norm.get("port") or norm.get("server_port") or ""
    username = norm.get("proxy_username") or norm.get("username") or norm.get("user") or ""
    password = norm.get("proxy_password") or norm.get("password") or norm.get("pass") or ""
    proxy_type = (norm.get("proxy_type") or norm.get("type") or norm.get("protocol") or "").lower()
    proxy_soft = norm.get("proxy_soft") or norm.get("software") or ""
    ipchecker = (norm.get("ipchecker") or norm.get("ip_checker") or "").lower()
    proxy_kind = normalize_proxy_kind(norm.get("proxy_kind") or norm.get("proxy_profile_type") or norm.get("connection_type") or norm.get("network_type") or norm.get("proxy_category"))
    if not proxy_kind:
        inference_text = " ".join([
            norm.get("provider") or "",
            norm.get("proxy_provider") or "",
            norm.get("plan") or "",
            norm.get("product") or "",
            norm.get("label") or "",
            proxy_string,
        ]).lower()
        if "mobile" in inference_text or "4g" in inference_text or "5g" in inference_text or "lte" in inference_text:
            proxy_kind = "mobile"
        elif "residential" in inference_text or "resi" in inference_text:
            proxy_kind = "residential"
    if proxy_string and "://" in proxy_string and not host:
        parsed = urlparse(proxy_string)
        host = parsed.hostname or host
        port = str(parsed.port or "") or port
        username = parsed.username or username
        password = parsed.password or password
        if parsed.scheme and not proxy_type:
            proxy_type = parsed.scheme.lower()
    if proxy_string and not host and ":" in proxy_string:
        parts = proxy_string.split(":")
        if len(parts) >= 4:
            host, port, username, password = parts[0], parts[1], parts[2], ":".join(parts[3:])
        elif len(parts) >= 2:
            host, port = parts[0], parts[1]
    if not host or not port:
        raise ValueError("Proxy row missing host or port")
    if proxy_type and proxy_type not in {"http", "https", "socks5"}:
        raise ValueError("proxy_type must be one of: http, https, socks5")
    if ipchecker and ipchecker not in {"ip2location", "ipapi"}:
        raise ValueError("ipchecker must be ip2location or ipapi")
    if proxy_kind and proxy_kind not in {"residential", "mobile"}:
        raise ValueError("proxy_kind must be residential or mobile")
    inferred = infer_proxy_defaults(norm.get("provider") or norm.get("proxy_provider") or None, host, username, proxy_kind, proxy_type, (norm.get("country") or norm.get("country_code") or "").upper() or None)
    return {
        "provider": inferred["provider"],
        "country_code": inferred["country_code"],
        "proxy_kind": inferred["proxy_kind"],
        "proxy_type": inferred["proxy_type"],
        "proxy_soft": proxy_soft or None,
        "ipchecker": ipchecker or None,
        "proxy_host": host,
        "proxy_port": port,
        "proxy_username": username or None,
        "proxy_password": password or None,
        "raw_proxy": proxy_string or None,
    }


def build_review(project: Project, db: Session):
    analysts = {a.id: a for a in project.analysts}
    plans = list(project.countries)
    all_proxies = list(project.proxies)
    all_jobs = db.scalars(select(ProvisionJob).where(ProvisionJob.project_id == project.id)).all()

    proxies_by_country_kind = defaultdict(list)
    untagged_by_kind = defaultdict(list)
    for p in all_proxies:
        kind = normalize_proxy_kind(p.proxy_kind)
        if p.country_code:
            proxies_by_country_kind[(p.country_code.upper(), kind)].append(p)
        else:
            untagged_by_kind[kind].append(p)

    completed_counts = defaultdict(int)
    queued_counts = defaultdict(int)
    pending = running = completed = failed = 0
    completed_durations = []
    for job in all_jobs:
        key = (job.analyst_name, job.country_code.upper())
        queued_counts[key] += 1
        if job.status == "completed":
            completed += 1
            completed_counts[key] += 1
            try:
                completed_durations.append(max((job.updated_at - job.created_at).total_seconds(), 1))
            except Exception:
                completed_durations.append(5)
        elif job.status == "failed":
            failed += 1
        elif job.status == "running":
            running += 1
        else:
            pending += 1

    avg_duration = round(sum(completed_durations) / len(completed_durations), 1) if completed_durations else 8
    eta_seconds = int((pending + running) * avg_duration) if (pending + running) else 0

    proxy_used_ids = set()
    profile_rows = []
    summary_by_row = defaultdict(lambda: {
        "analyst": "",
        "country_code": "",
        "total_required": 0,
        "total_created": 0,
        "gap": 0,
        "desktop": 0,
        "mobile": 0,
        "windows": 0,
        "mac": 0,
        "android": 0,
        "iphone": 0,
        "mapped_proxies": 0,
        "extension_category": normalize_extension_category(project.extension_category),
    })
    seq_map = defaultdict(int)

    for plan in sorted(plans, key=lambda x: x.country_code):
        assigned_ids = [int(x) for x in plan.analyst_ids_csv.split(",") if x.strip() and int(x) in analysts]
        if not assigned_ids:
            continue
        shares = split_even(plan.total_profiles, [str(x) for x in assigned_ids])

        for analyst_id_str, share_count in shares.items():
            analyst = analysts[int(analyst_id_str)]
            seg = allocate_segments(share_count, project)
            row_key = (analyst.name, plan.country_code.upper())
            summary = summary_by_row[row_key]
            summary["analyst"] = analyst.name
            summary["country_code"] = plan.country_code.upper()
            summary["total_required"] += share_count
            summary["desktop"] += seg["desktop"]
            summary["mobile"] += seg["mobile"]
            summary["windows"] += seg["windows"]
            summary["mac"] += seg["mac"]
            summary["android"] += seg["android"]
            summary["iphone"] += seg["iphone"]

            device_chunks = [
                ("desktop", "windows", seg["windows"]),
                ("desktop", "mac", seg["mac"]),
                ("mobile", "android", seg["android"]),
                ("mobile", "iphone", seg["iphone"]),
            ]
            for device_type, os_type, count in device_chunks:
                required_proxy_kind = "residential" if device_type == "desktop" else "mobile"
                for _ in range(count):
                    seq_key = (project.name, plan.country_code.upper(), analyst.name, os_type.upper())
                    seq_map[seq_key] += 1
                    country_pool = [p for p in proxies_by_country_kind.get((plan.country_code.upper(), required_proxy_kind), []) if p.id not in proxy_used_ids]
                    fallback_pool = [p for p in untagged_by_kind.get(required_proxy_kind, []) if p.id not in proxy_used_ids]
                    proxy_obj = (country_pool + fallback_pool)[0] if (country_pool + fallback_pool) else None
                    proxy_reason = ""
                    if proxy_obj:
                        proxy_used_ids.add(proxy_obj.id)
                        summary["mapped_proxies"] += 1
                    else:
                        proxy_reason = f"No {required_proxy_kind} proxy available for {device_type} profile in {plan.country_code.upper()}"
                    profile_name = build_profile_name(
                        analyst.name,
                        project.name,
                        plan.country_code.upper(),
                        device_type,
                        os_type,
                        seq_map[seq_key],
                    )
                    proxy_type_value = ((proxy_obj.proxy_type if proxy_obj else None) or project.default_proxy_type or "http").strip().lower()
                    if proxy_type_value not in {"http", "https", "socks5"}:
                        proxy_type_value = "http"
                    proxy_soft_value = ((proxy_obj.proxy_soft if proxy_obj else None) or project.default_proxy_soft or "other").strip() or "other"
                    ipchecker_value = (((proxy_obj.ipchecker if proxy_obj else None) or project.default_ipchecker or "").strip().lower())
                    user_proxy_config = {
                        "proxy_soft": proxy_soft_value,
                        "proxy_type": proxy_type_value,
                        "proxy_host": proxy_obj.proxy_host,
                        "proxy_port": proxy_obj.proxy_port,
                        "proxy_user": proxy_obj.proxy_username or "",
                        "proxy_password": proxy_obj.proxy_password or "",
                    } if proxy_obj else {"proxy_soft": "no_proxy"}
                    payload = {
                        "name": profile_name,
                        "group_id": project.ads_group or "0",
                        "remark": project.remark_template or f"{project.name} | {analyst.name} | {plan.country_code.upper()} | {os_type}",
                        "user_proxy_config": user_proxy_config,
                        "fingerprint_config": {
                            "automatic_timezone": "1",
                            "random_ua": {
                                "ua_browser": ["chrome"],
                                "ua_system_version": [os_type_to_system(os_type)],
                            },
                        },
                        "country": plan.country_code.upper(),
                    }
                    if ipchecker_value in {"ip2location", "ipapi"}:
                        payload["ipchecker"] = ipchecker_value
                    if project.extension_category:
                        payload["extension_category_name"] = project.extension_category.strip()
                        payload["remark"] = f"{payload['remark']} | extension:{project.extension_category}"
                    profile_rows.append({
                        "profile_name": profile_name,
                        "analyst": analyst.name,
                        "country": plan.country_code.upper(),
                        "device_type": device_type,
                        "os_type": os_type,
                        "proxy_kind_required": required_proxy_kind,
                        "proxy_kind_actual": normalize_proxy_kind(proxy_obj.proxy_kind) if proxy_obj else None,
                        "proxy_reason": proxy_reason,
                        "proxy": proxy_to_string(proxy_obj) if proxy_obj else "UNMAPPED",
                        "extension_category": normalize_extension_category(project.extension_category),
                        "payload": payload,
                    })

    analyst_grid = []
    for row_key, summary in sorted(summary_by_row.items(), key=lambda kv: (kv[0][0].lower(), kv[0][1])):
        summary["total_created"] = completed_counts[row_key]
        summary["gap"] = max(summary["total_required"] - summary["total_created"], 0)
        summary["jobs_queued"] = queued_counts[row_key]
        analyst_grid.append(summary)

    totals = {
        "profiles_required": len(profile_rows),
        "profiles_created": completed,
        "proxy_count": len(all_proxies),
        "mapped_proxy_count": len(proxy_used_ids),
        "unmapped_profiles": sum(1 for r in profile_rows if r["proxy"] == "UNMAPPED"),
    }
    job_progress = {
        "total": len(all_jobs),
        "pending": pending,
        "running": running,
        "completed": completed,
        "failed": failed,
        "eta_seconds": eta_seconds,
        "average_seconds_per_profile": avg_duration,
    }
    return {"analyst_grid": analyst_grid, "profile_rows": profile_rows, "totals": totals, "job_progress": job_progress}

def proxy_to_string(proxy_obj: Optional[ProxyRecord]) -> str:
    if not proxy_obj:
        return ""
    return f"{proxy_obj.proxy_host}:{proxy_obj.proxy_port}:{proxy_obj.proxy_username or ''}:{proxy_obj.proxy_password or ''}"


def os_type_to_system(os_type: str) -> str:
    mapping = {
        "windows": "Windows 10",
        "mac": "Mac OS X 13",
        "android": "Android 13",
        "iphone": "iOS 15",
    }
    return mapping.get(os_type.lower(), "Windows 10")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})


@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", "")).strip()
    user = db.scalar(select(User).where(User.username == username))
    if not user or not pwd_context.verify(password, user.password_hash):
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Invalid credentials"}, status_code=400)
    response = RedirectResponse(url="/", status_code=303)
    set_session(response, user.id)
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    clear_session(response)
    return response


@app.get("/", response_class=HTMLResponse)
def index(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse(request, "app.html", {"request": request, "username": user.username})


@app.get("/api/me")
def api_me(user: User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role}


@app.get("/api/projects")
def list_projects(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    projects = db.scalars(select(Project).order_by(Project.created_at.desc())).all()
    return [project_to_dict(p) for p in projects]


@app.post("/api/projects")
def create_project(data: ProjectCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not data.name.strip():
        raise HTTPException(status_code=400, detail="Project name is required")
    requested_code = (data.code or "").strip().upper()
    final_code = requested_code or generate_unique_project_code(db, data.name)
    existing = db.scalar(select(Project).where(Project.code == final_code))
    if existing:
        raise HTTPException(status_code=400, detail="Project code already exists")
    project = Project(
        name=data.name.strip(),
        code=final_code,
        ads_group=data.ads_group,
        extension_category=normalize_extension_category(data.extension_category),
        default_proxy_type=data.default_proxy_type,
        default_proxy_soft=data.default_proxy_soft,
        default_ipchecker=data.default_ipchecker,
        naming_pattern=data.naming_pattern or DEFAULT_NAMING_PATTERN,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project_to_dict(project)


@app.get("/api/projects/{project_id}")
def get_project(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return {
        "project": project_to_dict(project),
        "analysts": [analyst_to_dict(a) for a in project.analysts],
        "countries": [country_to_dict(c) for c in project.countries],
        "proxies": len(project.proxies),
    }


@app.patch("/api/projects/{project_id}/settings")
def update_project_settings(project_id: int, data: ProjectSettings, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    validate_project_settings(data)
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    for field in ["desktop_pct", "mobile_pct", "windows_pct", "mac_pct", "android_pct", "iphone_pct", "ads_group", "default_proxy_type", "default_proxy_soft", "default_ipchecker", "connector_name", "remark_template"]:
        setattr(project, field, getattr(data, field))
    project.extension_category = normalize_extension_category(data.extension_category)
    project.naming_pattern = project.naming_pattern or DEFAULT_NAMING_PATTERN
    db.commit()
    db.refresh(project)
    return project_to_dict(project)


@app.get("/api/projects/{project_id}/analysts")
def list_analysts(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return [analyst_to_dict(a) for a in project.analysts]


@app.post("/api/projects/{project_id}/analysts")
def add_analysts(project_id: int, names_csv: str = Form(...), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    created = []
    for raw in names_csv.splitlines():
        name = raw.strip()
        if not name:
            continue
        analyst = Analyst(project_id=project_id, name=name)
        db.add(analyst)
        created.append(name)
    db.commit()
    return {"created": created}


@app.delete("/api/analysts/{analyst_id}")
def delete_analyst(analyst_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    analyst = db.get(Analyst, analyst_id)
    if not analyst:
        raise HTTPException(status_code=404, detail="Analyst not found")
    db.delete(analyst)
    db.commit()
    return {"deleted": analyst_id}


@app.get("/api/projects/{project_id}/countries")
def list_countries(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return [country_to_dict(c) for c in project.countries]


@app.post("/api/projects/{project_id}/countries")
def add_country_plan(project_id: int, data: CountryPlanIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if data.total_profiles <= 0:
        raise HTTPException(status_code=400, detail="Total profiles must be greater than 0")
    analyst_ids_csv = ",".join(str(x) for x in data.analyst_ids)
    existing = db.scalar(select(CountryPlan).where(CountryPlan.project_id == project_id, CountryPlan.country_code == data.country_code.upper()))
    if existing:
        existing.total_profiles = data.total_profiles
        existing.analyst_ids_csv = analyst_ids_csv
        db.commit()
        return country_to_dict(existing)
    plan = CountryPlan(project_id=project_id, country_code=data.country_code.upper(), total_profiles=data.total_profiles, analyst_ids_csv=analyst_ids_csv)
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return country_to_dict(plan)


@app.delete("/api/countries/{country_plan_id}")
def delete_country_plan(country_plan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    plan = db.get(CountryPlan, country_plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Country plan not found")
    db.delete(plan)
    db.commit()
    return {"deleted": country_plan_id}


@app.post("/api/projects/{project_id}/proxies/upload")
async def upload_proxies(project_id: int, file: UploadFile = File(...), replace_existing: bool = Form(False), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file received")
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 CSV text")

    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    if not lines:
        raise HTTPException(status_code=400, detail="No proxy rows found")

    parse_mode = "csv"
    headers = []
    rows = []
    first_line = lines[0]
    if "," not in first_line and ("://" in first_line or first_line.count(":") >= 2):
        parse_mode = "raw_lines"
    else:
        reader = csv.DictReader(io.StringIO(decoded))
        headers = [str(h).strip() for h in (reader.fieldnames or []) if h is not None]
        rows = list(reader)
        if not headers or (len(headers) == 1 and ("://" in headers[0] or headers[0].count(":") >= 2)):
            parse_mode = "raw_lines"
        else:
            required_any = [{"proxy_host", "host", "proxy", "proxy_string", "raw_proxy", "endpoint", "address"}, {"proxy_port", "port"}]
            normalized_headers = {h.lower() for h in headers}
            has_raw_proxy_column = bool({"proxy", "proxy_string", "raw_proxy", "endpoint", "address"} & normalized_headers)
            if not has_raw_proxy_column:
                missing_groups = [sorted(group)[0] for group in required_any if not (group & normalized_headers)]
                if missing_groups:
                    raise HTTPException(status_code=400, detail=f"CSV is missing required columns: {', '.join(missing_groups)}")
            if not rows:
                raise HTTPException(status_code=400, detail="No CSV rows found")
    try:
        if replace_existing:
            for p in list(project.proxies):
                db.delete(p)
            db.flush()
        created = 0
        errors = []
        if parse_mode == "raw_lines":
            for idx, line in enumerate(lines, start=1):
                try:
                    parsed = parse_proxy_line(line)
                    db.add(ProxyRecord(project_id=project_id, **parsed))
                    created += 1
                except Exception as exc:
                    errors.append({"row": idx, "error": str(exc)})
        else:
            for idx, row in enumerate(rows, start=2):
                try:
                    parsed = parse_proxy_row(row)
                    db.add(ProxyRecord(project_id=project_id, **parsed))
                    created += 1
                except Exception as exc:
                    errors.append({"row": idx, "error": str(exc)})
        db.commit()
        return {"created": created, "errors": errors, "headers": headers, "filename": file.filename, "parse_mode": parse_mode}
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Proxy upload failed on server: {exc}")


@app.get("/api/projects/{project_id}/proxies")
def list_proxies(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return [{
        "id": p.id,
        "provider": p.provider,
        "country_code": p.country_code,
        "proxy_kind": p.proxy_kind,
        "proxy_type": p.proxy_type,
        "proxy_soft": p.proxy_soft,
        "ipchecker": p.ipchecker,
        "proxy": proxy_to_string(p),
    } for p in project.proxies]


@app.get("/api/projects/{project_id}/review")
def get_review(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return build_review(project, db)


@app.post("/api/projects/{project_id}/create-jobs")
def create_jobs(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    review = build_review(project, db)
    if not review["profile_rows"]:
        raise HTTPException(status_code=400, detail="No generated profile rows to create")
    unmapped = [r for r in review["profile_rows"] if r["proxy"] == "UNMAPPED"]
    if unmapped:
        preview = "; ".join(f"{r['profile_name']}: {r['proxy_reason']}" for r in unmapped[:5])
        raise HTTPException(status_code=400, detail=f"Cannot create jobs until every profile has a matching proxy. {preview}")
    for existing in list(project.jobs):
        if existing.status in {"pending", "running"}:
            raise HTTPException(status_code=400, detail="There are already pending jobs for this project")
    created = 0
    for row in review["profile_rows"]:
        job = ProvisionJob(
            project_id=project.id,
            connector_name=project.connector_name,
            profile_name=row["profile_name"],
            analyst_name=row["analyst"],
            country_code=row["country"],
            device_type=row["device_type"],
            os_type=row["os_type"],
            status="pending",
            payload_json=json.dumps(row["payload"]),
            updated_at=utcnow(),
        )
        db.add(job)
        created += 1
    db.commit()
    return {"created_jobs": created}


@app.get("/api/projects/{project_id}/jobs")
def list_jobs(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    jobs = db.scalars(select(ProvisionJob).where(ProvisionJob.project_id == project_id).order_by(ProvisionJob.created_at.desc())).all()
    pending = sum(1 for j in jobs if j.status == "pending")
    running = sum(1 for j in jobs if j.status == "running")
    completed = sum(1 for j in jobs if j.status == "completed")
    failed = sum(1 for j in jobs if j.status == "failed")
    durations = []
    for j in jobs:
        if j.status == "completed":
            try:
                durations.append(max((j.updated_at - j.created_at).total_seconds(), 1))
            except Exception:
                durations.append(5)
    avg_duration = round(sum(durations) / len(durations), 1) if durations else 8
    eta_seconds = int((pending + running) * avg_duration) if (pending + running) else 0
    return {
        "summary": {
            "total": len(jobs),
            "pending": pending,
            "running": running,
            "completed": completed,
            "failed": failed,
            "eta_seconds": eta_seconds,
            "average_seconds_per_profile": avg_duration,
        },
        "jobs": [{
            "id": j.id,
            "profile_name": j.profile_name,
            "analyst_name": j.analyst_name,
            "country_code": j.country_code,
            "device_type": j.device_type,
            "os_type": j.os_type,
            "status": j.status,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "updated_at": j.updated_at.isoformat() if j.updated_at else None,
            "result_json": json.loads(j.result_json) if j.result_json else None,
        } for j in jobs]
    }


def serialize_connector(c: ConnectorHeartbeat) -> Dict:
    try:
        extension_categories = json.loads(c.extension_categories_json) if c.extension_categories_json else []
    except Exception:
        extension_categories = []
    last_seen = ensure_aware_utc(c.last_seen)
    category_synced_at = ensure_aware_utc(c.category_synced_at)
    age_seconds = None
    if last_seen:
        age_seconds = max(0.0, (utcnow() - last_seen).total_seconds())
    return {
        "name": c.name,
        "host_os": c.host_os,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "category_synced_at": category_synced_at.isoformat() if category_synced_at else None,
        "extension_categories": extension_categories,
        "online": bool(age_seconds is not None and age_seconds <= CONNECTOR_STALE_SECONDS),
        "age_seconds": age_seconds,
        "stale_threshold_seconds": CONNECTOR_STALE_SECONDS,
    }


@app.get("/api/connectors")
def list_connectors(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    connectors = db.scalars(select(ConnectorHeartbeat).order_by(ConnectorHeartbeat.name.asc())).all()
    return [serialize_connector(c) for c in connectors]


@app.get("/api/connectors/debug")
def debug_connectors(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    connectors = db.scalars(select(ConnectorHeartbeat).order_by(ConnectorHeartbeat.name.asc())).all()
    return {
        "server_time": utcnow().isoformat(),
        "count": len(connectors),
        "connectors": [serialize_connector(c) for c in connectors],
    }


@app.post("/api/connector/heartbeat")
def connector_heartbeat(data: ConnectorIn, request: Request, db: Session = Depends(get_db)):
    require_connector_token(request)
    connector = db.scalar(select(ConnectorHeartbeat).where(ConnectorHeartbeat.name == data.name))
    if not connector:
        connector = ConnectorHeartbeat(name=data.name, host_os=data.host_os, last_seen=utcnow())
        db.add(connector)
    else:
        connector.host_os = data.host_os
        connector.last_seen = utcnow()
    if data.extension_categories is not None:
        connector.extension_categories_json = json.dumps(data.extension_categories)
        connector.category_synced_at = utcnow()
    db.commit()
    return {"ok": True, "saved_categories": len(data.extension_categories or []), "name": data.name}


@app.post("/api/connector/fetch-job")
def connector_fetch_job(data: ConnectorIn, request: Request, db: Session = Depends(get_db)):
    require_connector_token(request)
    connector = db.scalar(select(ConnectorHeartbeat).where(ConnectorHeartbeat.name == data.name))
    if not connector:
        connector = ConnectorHeartbeat(name=data.name, host_os=data.host_os, last_seen=utcnow())
        db.add(connector)
        db.commit()
    else:
        connector.host_os = data.host_os
        connector.last_seen = utcnow()
        if data.extension_categories is not None:
            connector.extension_categories_json = json.dumps(data.extension_categories)
            connector.category_synced_at = utcnow()
        db.commit()
    job = db.scalar(select(ProvisionJob).where(
        ProvisionJob.status == "pending",
        (ProvisionJob.connector_name == data.name) | (ProvisionJob.connector_name.is_(None))
    ).order_by(ProvisionJob.created_at.asc()))
    if not job:
        return {"job": None, "connector": serialize_connector(connector)}
    job.status = "running"
    job.connector_name = data.name
    job.updated_at = utcnow()
    db.commit()
    return {"job": {
        "id": job.id,
        "profile_name": job.profile_name,
        "payload": json.loads(job.payload_json),
    }}


@app.post("/api/connector/jobs/{job_id}/result")
def connector_job_result(job_id: int, data: JobResultIn, request: Request, db: Session = Depends(get_db)):
    require_connector_token(request)
    job = db.get(ProvisionJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    job.status = data.status
    job.result_json = json.dumps(data.result)
    job.updated_at = utcnow()
    db.commit()
    return {"ok": True}


@app.get("/api/proxy-template.csv")
def download_proxy_template(user: User = Depends(get_current_user)):
    sample = "\n".join([
        "provider,country_code,proxy_kind,proxy_type,proxy_soft,ipchecker,proxy_host,proxy_port,proxy_username,proxy_password",
        "Decodo,US,residential,https,other,ipapi,res-us.example.com,8000,user1,pass1",
        "IPBurger,IN,mobile,http,other,ip2location,mob-in.example.com,9000,user2,pass2",
    ])
    headers = {"Content-Disposition": 'attachment; filename="proxy_template_example.csv"'}
    return Response(content=sample + "\n", media_type="text/csv", headers=headers)


@app.get("/health")
def health():
    return {"status": "ok", "time": utcnow().isoformat()}
