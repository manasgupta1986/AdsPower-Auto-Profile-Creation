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
    project_kind: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, default="master")
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
    subprojects: Mapped[List["SubProject"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    analysts: Mapped[List["Analyst"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    countries: Mapped[List["CountryPlan"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    proxies: Mapped[List["ProxyRecord"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    jobs: Mapped[List["ProvisionJob"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class SubProject(Base):
    __tablename__ = "subprojects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(255))
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    project: Mapped[Project] = relationship(back_populates="subprojects")


class Analyst(Base):
    __tablename__ = "analysts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    sub_project_id: Mapped[Optional[int]] = mapped_column(ForeignKey("subprojects.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    project: Mapped[Project] = relationship(back_populates="analysts")



class CountryPlan(Base):
    __tablename__ = "country_plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    sub_project_id: Mapped[Optional[int]] = mapped_column(ForeignKey("subprojects.id"), nullable=True)
    country_code: Mapped[str] = mapped_column(String(50))
    state_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    city_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    total_profiles: Mapped[int] = mapped_column(Integer)
    analyst_ids_csv: Mapped[str] = mapped_column(Text, default="")
    project: Mapped[Project] = relationship(back_populates="countries")

class ProxyRecord(Base):
    __tablename__ = "proxy_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    sub_project_id: Mapped[Optional[int]] = mapped_column(ForeignKey("subprojects.id"), nullable=True)
    provider: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    country_code: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    state_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    city_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
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
    assignment_status: Mapped[Optional[str]] = mapped_column(String(30), nullable=True, default="free")
    assigned_profile_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    assigned_job_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    assigned_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    assigned_adspower_profile_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    project: Mapped[Project] = relationship(back_populates="proxies")

class ProvisionJob(Base):
    __tablename__ = "provision_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    sub_project_id: Mapped[Optional[int]] = mapped_column(ForeignKey("subprojects.id"), nullable=True)
    connector_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    profile_name: Mapped[str] = mapped_column(String(255))
    analyst_name: Mapped[str] = mapped_column(String(255))
    country_code: Mapped[str] = mapped_column(String(50))
    state_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    city_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type: Mapped[str] = mapped_column(String(50))
    os_type: Mapped[str] = mapped_column(String(50))
    proxy_record_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    profile_signature: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    duplicate_risk_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    adspower_profile_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
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
            "project_kind": "VARCHAR(20)",
            "default_proxy_type": "VARCHAR(20)",
            "default_proxy_soft": "VARCHAR(100)",
            "default_ipchecker": "VARCHAR(50)",
        },
        "analysts": {
            "sub_project_id": "INTEGER",
        },
        "country_plans": {
            "sub_project_id": "INTEGER",
            "state_name": "VARCHAR(255)",
            "city_name": "VARCHAR(255)",
        },
        "proxy_records": {
            "sub_project_id": "INTEGER",
            "state_name": "VARCHAR(255)",
            "city_name": "VARCHAR(255)",
            "proxy_kind": "VARCHAR(30)",
            "proxy_type": "VARCHAR(20)",
            "proxy_soft": "VARCHAR(100)",
            "ipchecker": "VARCHAR(50)",
            "assignment_status": "VARCHAR(30)",
            "assigned_profile_name": "VARCHAR(255)",
            "assigned_job_id": "INTEGER",
            "assigned_at": "TIMESTAMP",
            "assigned_adspower_profile_id": "VARCHAR(255)",
        },
        "provision_jobs": {
            "sub_project_id": "INTEGER",
            "state_name": "VARCHAR(255)",
            "city_name": "VARCHAR(255)",
            "proxy_record_id": "INTEGER",
            "profile_signature": "VARCHAR(500)",
            "duplicate_risk_json": "TEXT",
            "adspower_profile_id": "VARCHAR(255)",
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


class SubProjectCreate(BaseModel):
    name: str
    notes: Optional[str] = None


class CountryPlanIn(BaseModel):
    country_code: str
    state_name: Optional[str] = "All"
    city_name: Optional[str] = "All"
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


def normalize_location_value(value: Optional[str], default: str = "All") -> str:
    cleaned = str(value or "").strip()
    return cleaned or default


def location_label(country_code: str, state_name: Optional[str], city_name: Optional[str]) -> str:
    country = country_display_name(country_code)
    state = normalize_location_value(state_name)
    city = normalize_location_value(city_name)
    parts = [country]
    if state != "All":
        parts.append(state)
    if city != "All":
        parts.append(city)
    return " | ".join(parts)


def proxy_identity_key(proxy_host: str, proxy_port: str, proxy_username: Optional[str]) -> str:
    host = str(proxy_host or "").strip().lower()
    port = str(proxy_port or "").strip()
    username = str(proxy_username or "").strip().lower()
    return f"{host}:{port}:{username}"


def build_profile_slot_signature(project_id: int, analyst_name: str, country_code: str, state_name: Optional[str], city_name: Optional[str], device_type: str, os_type: str, sequence: int) -> str:
    state_value = normalize_location_value(state_name)
    city_value = normalize_location_value(city_name)
    return "::".join([
        str(project_id),
        normalize_name(analyst_name).lower(),
        str(country_code or "").strip().upper(),
        normalize_name(state_value).lower(),
        normalize_name(city_value).lower(),
        normalize_name(device_type).lower(),
        normalize_name(os_type).lower(),
        f"{int(sequence):03d}",
    ])


def extract_profile_sequence(profile_name: str) -> int:
    tail = str(profile_name or "").rsplit("_", 1)[-1]
    return int(tail) if tail.isdigit() else 0


def safe_json_loads(raw: Optional[str], default):
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def extract_adspower_profile_id(result: Dict) -> Optional[str]:
    if not isinstance(result, dict):
        return None
    body = result.get("body")
    candidate_sources = []
    if isinstance(body, dict):
        data = body.get("data")
        if isinstance(data, dict):
            candidate_sources.append(data)
        candidate_sources.append(body)
    for source in candidate_sources:
        for key in ["id", "browser_id", "user_id", "profile_id", "serial_number"]:
            value = source.get(key)
            if value not in {None, ""}:
                return str(value)
    return None


def build_profile_name(analyst_name: str, project_name: str, country_code: str, state_name: Optional[str], city_name: Optional[str], device_type: str, os_type: str, sequence: int) -> str:
    analyst_part = normalize_name(analyst_name)
    project_part = normalize_name(project_name)
    country_part = normalize_name(country_display_name(country_code))
    parts = [analyst_part, project_part, country_part]
    state_value = normalize_location_value(state_name)
    city_value = normalize_location_value(city_name)
    if state_value != "All":
        parts.append(normalize_name(state_value))
    if city_value != "All":
        parts.append(normalize_name(city_value))
    parts.extend([normalize_name(device_type).upper(), normalize_name(os_type).upper(), f"{sequence:03d}"])
    return "_".join(parts)


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
    kind = str(getattr(project, "project_kind", None) or "").strip().lower() or "legacy"
    return {
        "id": project.id,
        "name": project.name,
        "code": project.code,
        "project_kind": kind,
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
        "created_at": project.created_at.isoformat() if project.created_at else None,
        "subproject_count": len(getattr(project, "subprojects", []) or []),
    }


def subproject_to_dict(s: SubProject):
    return {
        "id": s.id,
        "project_id": s.project_id,
        "name": s.name,
        "notes": s.notes,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


def ensure_default_subproject(project: Project, db: Session) -> SubProject:
    subproject = db.scalar(select(SubProject).where(SubProject.project_id == project.id).order_by(SubProject.created_at.asc(), SubProject.id.asc()))
    created = False
    if not subproject:
        subproject = SubProject(project_id=project.id, name="Main", notes="Default sub-project for existing data")
        db.add(subproject)
        db.flush()
        created = True
    target_id = subproject.id
    dirty = created
    for analyst in db.scalars(select(Analyst).where(Analyst.project_id == project.id, Analyst.sub_project_id.is_(None))).all():
        analyst.sub_project_id = target_id
        dirty = True
    for plan in db.scalars(select(CountryPlan).where(CountryPlan.project_id == project.id, CountryPlan.sub_project_id.is_(None))).all():
        plan.sub_project_id = target_id
        dirty = True
    for proxy_obj in db.scalars(select(ProxyRecord).where(ProxyRecord.project_id == project.id, ProxyRecord.sub_project_id.is_(None))).all():
        proxy_obj.sub_project_id = target_id
        dirty = True
    for job in db.scalars(select(ProvisionJob).where(ProvisionJob.project_id == project.id, ProvisionJob.sub_project_id.is_(None))).all():
        job.sub_project_id = target_id
        dirty = True
    if dirty:
        db.commit()
        db.refresh(subproject)
    return subproject


def resolve_subproject(project: Project, db: Session, sub_project_id: Optional[int]) -> SubProject:
    default_subproject = ensure_default_subproject(project, db)
    if sub_project_id in {None, 0, "0", ""}:
        return default_subproject
    subproject = db.get(SubProject, int(sub_project_id))
    if not subproject or subproject.project_id != project.id:
        raise HTTPException(status_code=404, detail="Sub-project not found")
    return subproject


def analyst_to_dict(a: Analyst):
    return {"id": a.id, "project_id": a.project_id, "sub_project_id": a.sub_project_id, "name": a.name, "email": a.email}


def country_to_dict(c: CountryPlan):
    analyst_ids = [int(x) for x in c.analyst_ids_csv.split(",") if x.strip()]
    return {
        "id": c.id,
        "project_id": c.project_id,
        "sub_project_id": c.sub_project_id,
        "country_code": c.country_code,
        "state_name": normalize_location_value(c.state_name),
        "city_name": normalize_location_value(c.city_name),
        "total_profiles": c.total_profiles,
        "analyst_ids": analyst_ids,
    }


COUNTRY_NAME_MAP = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AD": "Andorra", "AO": "Angola", "AG": "Antigua and Barbuda", "AR": "Argentina", "AM": "Armenia", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BT": "Bhutan", "BO": "Bolivia", "BA": "Bosnia and Herzegovina", "BW": "Botswana", "BR": "Brazil", "BN": "Brunei", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi", "CV": "Cabo Verde", "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada", "CF": "Central African Republic", "TD": "Chad", "CL": "Chile", "CN": "China", "CO": "Colombia", "KM": "Comoros", "CG": "Congo", "CR": "Costa Rica", "CI": "Côte d'Ivoire", "HR": "Croatia", "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic", "CD": "Democratic Republic of the Congo", "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica", "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea", "ER": "Eritrea", "EE": "Estonia", "SZ": "Eswatini", "ET": "Ethiopia", "FJ": "Fiji", "FI": "Finland", "FR": "France", "GA": "Gabon", "GM": "Gambia", "GE": "Georgia", "DE": "Germany", "GH": "Ghana", "GR": "Greece", "GD": "Grenada", "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana", "HT": "Haiti", "VA": "Holy See", "HN": "Honduras", "HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel", "IT": "Italy", "JM": "Jamaica", "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya", "KI": "Kiribati", "KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Laos", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia", "LY": "Libya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg", "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives", "ML": "Mali", "MT": "Malta", "MH": "Marshall Islands", "MR": "Mauritania", "MU": "Mauritius", "MX": "Mexico", "FM": "Micronesia", "MD": "Moldova", "MC": "Monaco", "MN": "Mongolia", "ME": "Montenegro", "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia", "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands", "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria", "KP": "North Korea", "MK": "North Macedonia", "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PW": "Palau", "PS": "Palestine", "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru", "PH": "Philippines", "PL": "Poland", "PT": "Portugal", "QA": "Qatar", "RO": "Romania", "RU": "Russia", "RW": "Rwanda", "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia", "VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino", "ST": "Sao Tome and Principe", "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia", "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa", "KR": "South Korea", "SS": "South Sudan", "ES": "Spain", "LK": "Sri Lanka", "SD": "Sudan", "SR": "Suriname", "SE": "Sweden", "CH": "Switzerland", "SY": "Syria", "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand", "TL": "Timor-Leste", "TG": "Togo", "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Turkey", "TM": "Turkmenistan", "TV": "Tuvalu", "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela", "VN": "Vietnam", "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe"
}

COUNTRY_PREFIX_MAP = {
    "af": "AF", "al": "AL", "dz": "DZ", "ad": "AD", "ao": "AO", "ag": "AG", "ar": "AR", "am": "AM", "au": "AU", "at": "AT", "az": "AZ", "bs": "BS", "bh": "BH", "bd": "BD", "bb": "BB", "by": "BY", "be": "BE", "bz": "BZ", "bj": "BJ", "bt": "BT", "bo": "BO", "ba": "BA", "bw": "BW", "br": "BR", "bn": "BN", "bg": "BG", "bf": "BF", "bi": "BI", "cv": "CV", "kh": "KH", "cm": "CM", "ca": "CA", "cf": "CF", "td": "TD", "cl": "CL", "cn": "CN", "co": "CO", "km": "KM", "cg": "CG", "cr": "CR", "ci": "CI", "hr": "HR", "cu": "CU", "cy": "CY", "cz": "CZ", "cd": "CD", "dk": "DK", "dj": "DJ", "dm": "DM", "do": "DO", "ec": "EC", "eg": "EG", "sv": "SV", "gq": "GQ", "er": "ER", "ee": "EE", "sz": "SZ", "et": "ET", "fj": "FJ", "fi": "FI", "fr": "FR", "ga": "GA", "gm": "GM", "ge": "GE", "de": "DE", "gh": "GH", "gr": "GR", "gd": "GD", "gt": "GT", "gn": "GN", "gw": "GW", "gy": "GY", "ht": "HT", "va": "VA", "hn": "HN", "hu": "HU", "is": "IS", "in": "IN", "id": "ID", "ir": "IR", "iq": "IQ", "ie": "IE", "il": "IL", "it": "IT", "jm": "JM", "jp": "JP", "jo": "JO", "kz": "KZ", "ke": "KE", "ki": "KI", "kw": "KW", "kg": "KG", "la": "LA", "lv": "LV", "lb": "LB", "ls": "LS", "lr": "LR", "ly": "LY", "li": "LI", "lt": "LT", "lu": "LU", "mg": "MG", "mw": "MW", "my": "MY", "mv": "MV", "ml": "ML", "mt": "MT", "mh": "MH", "mr": "MR", "mu": "MU", "mx": "MX", "fm": "FM", "md": "MD", "mc": "MC", "mn": "MN", "me": "ME", "ma": "MA", "mz": "MZ", "mm": "MM", "na": "NA", "nr": "NR", "np": "NP", "nl": "NL", "nz": "NZ", "ni": "NI", "ne": "NE", "ng": "NG", "kp": "KP", "mk": "MK", "no": "NO", "om": "OM", "pk": "PK", "pw": "PW", "ps": "PS", "pa": "PA", "pg": "PG", "py": "PY", "pe": "PE", "ph": "PH", "pl": "PL", "pt": "PT", "qa": "QA", "ro": "RO", "ru": "RU", "rw": "RW", "kn": "KN", "lc": "LC", "vc": "VC", "ws": "WS", "sm": "SM", "st": "ST", "sa": "SA", "sn": "SN", "rs": "RS", "sc": "SC", "sl": "SL", "sg": "SG", "sk": "SK", "si": "SI", "sb": "SB", "so": "SO", "za": "ZA", "kr": "KR", "ss": "SS", "es": "ES", "lk": "LK", "sd": "SD", "sr": "SR", "se": "SE", "ch": "CH", "sy": "SY", "tj": "TJ", "tz": "TZ", "th": "TH", "tl": "TL", "tg": "TG", "to": "TO", "tt": "TT", "tn": "TN", "tr": "TR", "tm": "TM", "tv": "TV", "ug": "UG", "ua": "UA", "ae": "AE", "gb": "GB", "us": "US", "uy": "UY", "uz": "UZ", "vu": "VU", "ve": "VE", "vn": "VN", "ye": "YE", "zm": "ZM", "zw": "ZW"
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
        "state_name": "All",
        "city_name": "All",
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
        "state_name": normalize_location_value(norm.get("state") or norm.get("state_name") or norm.get("region") or norm.get("province"), "All"),
        "city_name": normalize_location_value(norm.get("city") or norm.get("city_name"), "All"),
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


def build_review(project: Project, db: Session, sub_project_id: Optional[int] = None):
    current_subproject = resolve_subproject(project, db, sub_project_id)
    analysts_list = db.scalars(select(Analyst).where(Analyst.project_id == project.id, Analyst.sub_project_id == current_subproject.id)).all()
    analysts = {a.id: a for a in analysts_list}
    plans = db.scalars(select(CountryPlan).where(CountryPlan.project_id == project.id, CountryPlan.sub_project_id == current_subproject.id)).all()
    all_proxies = db.scalars(select(ProxyRecord).where(ProxyRecord.project_id == project.id)).all()
    all_jobs = db.scalars(select(ProvisionJob).where(ProvisionJob.project_id == project.id)).all()
    current_jobs = [job for job in all_jobs if getattr(job, "sub_project_id", None) == current_subproject.id]

    def norm_geo(country_code: Optional[str], state_name: Optional[str], city_name: Optional[str]):
        country = str(country_code or "").strip().upper()
        state = normalize_location_value(state_name)
        city = normalize_location_value(city_name)
        if state == "All":
            city = "All"
        return country, state, city

    proxy_by_id = {p.id: p for p in all_proxies}
    identity_groups = defaultdict(list)
    for proxy_obj in all_proxies:
        identity_groups[proxy_identity_key(proxy_obj.proxy_host, proxy_obj.proxy_port, proxy_obj.proxy_username)].append(proxy_obj)

    global_protected_jobs = 0
    current_completed_counts = defaultdict(int)
    current_protected_counts = defaultdict(int)
    current_pending_running_counts = defaultdict(int)
    current_existing_device_counts = defaultdict(int)
    existing_seq_max = defaultdict(int)
    existing_profile_names = set()
    existing_profile_signatures = set()
    identity_locked = set()
    current_pending = current_running = current_completed = current_failed = 0
    current_completed_durations = []

    for job in all_jobs:
        country, state, city = norm_geo(job.country_code, getattr(job, "state_name", None), getattr(job, "city_name", None))
        sequence_value = extract_profile_sequence(job.profile_name)
        seq_key = (project.id, job.analyst_name, country, state, city, job.device_type, job.os_type)
        existing_seq_max[seq_key] = max(existing_seq_max[seq_key], sequence_value)
        existing_profile_names.add(job.profile_name)
        existing_signature = job.profile_signature or build_profile_slot_signature(
            project.id,
            job.analyst_name,
            country,
            state,
            city,
            job.device_type,
            job.os_type,
            sequence_value,
        )
        existing_profile_signatures.add(existing_signature)

        if job.status in {"pending", "running", "completed"}:
            global_protected_jobs += 1
            if getattr(job, "proxy_record_id", None):
                proxy_obj = proxy_by_id.get(job.proxy_record_id)
                if proxy_obj:
                    identity_locked.add(proxy_identity_key(proxy_obj.proxy_host, proxy_obj.proxy_port, proxy_obj.proxy_username))
            else:
                payload = safe_json_loads(job.payload_json, {})
                proxy_cfg = payload.get("user_proxy_config") if isinstance(payload, dict) else {}
                if isinstance(proxy_cfg, dict) and proxy_cfg.get("proxy_host") and proxy_cfg.get("proxy_port"):
                    identity_locked.add(proxy_identity_key(proxy_cfg.get("proxy_host"), proxy_cfg.get("proxy_port"), proxy_cfg.get("proxy_user")))

        if getattr(job, "sub_project_id", None) != current_subproject.id:
            continue

        row_key = (job.analyst_name, country, state, city)
        device_key = (job.analyst_name, country, state, city, job.device_type, job.os_type)
        if job.status in {"pending", "running", "completed"}:
            current_protected_counts[row_key] += 1
            current_existing_device_counts[device_key] += 1
            if job.status in {"pending", "running"}:
                current_pending_running_counts[row_key] += 1
        if job.status == "completed":
            current_completed += 1
            current_completed_counts[row_key] += 1
            try:
                current_completed_durations.append(max((job.updated_at - job.created_at).total_seconds(), 1))
            except Exception:
                current_completed_durations.append(5)
        elif job.status == "failed":
            current_failed += 1
        elif job.status == "running":
            current_running += 1
        else:
            current_pending += 1

    for identity, group in identity_groups.items():
        if any(bool(getattr(proxy_obj, "assigned", False)) or str(getattr(proxy_obj, "assignment_status", "") or "").strip().lower() in {"reserved", "assigned"} for proxy_obj in group):
            identity_locked.add(identity)

    proxies_by_geo_kind = defaultdict(list)
    untagged_by_kind = defaultdict(list)
    duplicate_identity_rows = []
    for identity, group in sorted(identity_groups.items(), key=lambda item: item[0]):
        group_sorted = sorted(group, key=lambda proxy_obj: proxy_obj.id)
        if len(group_sorted) > 1:
            duplicate_identity_rows.append({
                "identity": identity,
                "count": len(group_sorted),
                "example": proxy_to_string(group_sorted[0]),
            })
        if identity in identity_locked:
            continue
        canonical_proxy = group_sorted[0]
        kind = normalize_proxy_kind(canonical_proxy.proxy_kind)
        country, state, city = norm_geo(canonical_proxy.country_code, canonical_proxy.state_name, canonical_proxy.city_name)
        if country:
            proxies_by_geo_kind[(country, state, city, kind)].append(canonical_proxy)
        else:
            untagged_by_kind[kind].append(canonical_proxy)

    for bucket in list(proxies_by_geo_kind.values()) + list(untagged_by_kind.values()):
        bucket.sort(key=lambda proxy_obj: proxy_obj.id)

    avg_duration = round(sum(current_completed_durations) / len(current_completed_durations), 1) if current_completed_durations else 8
    eta_seconds = int((current_pending + current_running) * avg_duration) if (current_pending + current_running) else 0

    proxy_used_identities = set()
    profile_rows = []
    summary_by_row = defaultdict(lambda: {
        "analyst": "",
        "country_code": "",
        "state_name": "All",
        "city_name": "All",
        "total_required": 0,
        "total_created": 0,
        "protected_profiles": 0,
        "pending_running": 0,
        "gap": 0,
        "create_now": 0,
        "desktop": 0,
        "mobile": 0,
        "windows": 0,
        "mac": 0,
        "android": 0,
        "iphone": 0,
        "mapped_proxies": 0,
        "extension_category": normalize_extension_category(project.extension_category),
    })
    seq_map = defaultdict(int, existing_seq_max)

    for plan in sorted(plans, key=lambda x: (x.country_code, normalize_location_value(x.state_name).lower(), normalize_location_value(x.city_name).lower())):
        assigned_ids = [int(x) for x in plan.analyst_ids_csv.split(",") if x.strip() and int(x) in analysts]
        if not assigned_ids:
            continue
        plan_country, plan_state, plan_city = norm_geo(plan.country_code, getattr(plan, "state_name", None), getattr(plan, "city_name", None))
        shares = split_even(plan.total_profiles, [str(x) for x in assigned_ids])

        for analyst_id_str, share_count in shares.items():
            analyst = analysts[int(analyst_id_str)]
            seg = allocate_segments(share_count, project)
            row_key = (analyst.name, plan_country, plan_state, plan_city)
            summary = summary_by_row[row_key]
            summary["analyst"] = analyst.name
            summary["country_code"] = plan_country
            summary["state_name"] = plan_state
            summary["city_name"] = plan_city
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
            for device_type, os_type, target_count in device_chunks:
                required_proxy_kind = "residential" if device_type == "desktop" else "mobile"
                existing_count = current_existing_device_counts[(analyst.name, plan_country, plan_state, plan_city, device_type, os_type)]
                create_count = max(target_count - existing_count, 0)
                if create_count <= 0:
                    continue
                for _ in range(create_count):
                    seq_key = (project.id, analyst.name, plan_country, plan_state, plan_city, device_type, os_type)
                    proxy_obj = None
                    proxy_reason = ""
                    risk_flags = []
                    match_level = None
                    candidate_levels = []
                    if plan_city != "All":
                        candidate_levels.append(("city", proxies_by_geo_kind.get((plan_country, plan_state, plan_city, required_proxy_kind), [])))
                    if plan_state != "All":
                        candidate_levels.append(("state", proxies_by_geo_kind.get((plan_country, plan_state, "All", required_proxy_kind), [])))
                    candidate_levels.append(("country", proxies_by_geo_kind.get((plan_country, "All", "All", required_proxy_kind), [])))
                    candidate_levels.append(("untagged", untagged_by_kind.get(required_proxy_kind, [])))

                    for level_name, bucket in candidate_levels:
                        available = []
                        for proxy_candidate in bucket:
                            identity = proxy_identity_key(proxy_candidate.proxy_host, proxy_candidate.proxy_port, proxy_candidate.proxy_username)
                            if identity in proxy_used_identities:
                                continue
                            available.append(proxy_candidate)
                        if available:
                            proxy_obj = available[0]
                            match_level = level_name
                            break

                    if proxy_obj:
                        proxy_identity = proxy_identity_key(proxy_obj.proxy_host, proxy_obj.proxy_port, proxy_obj.proxy_username)
                        proxy_used_identities.add(proxy_identity)
                        summary["mapped_proxies"] += 1
                        duplicate_count = len(identity_groups.get(proxy_identity, []))
                        if duplicate_count > 1:
                            risk_flags.append(f"Inventory contains {duplicate_count} copies of this same proxy endpoint; only the first copy is used.")
                        if match_level == "state":
                            risk_flags.append("Exact city proxy was unavailable, so a state-wide proxy was used.")
                        elif match_level == "country":
                            risk_flags.append("Exact state/city proxy was unavailable, so a country-wide proxy was used.")
                        elif match_level == "untagged":
                            risk_flags.append("A geo-untagged proxy was used because no tagged proxy matched this location.")
                    else:
                        proxy_reason = f"No {required_proxy_kind} proxy available for {location_label(plan_country, plan_state, plan_city)}"
                        risk_flags.append(proxy_reason)

                    while True:
                        seq_map[seq_key] += 1
                        sequence_value = seq_map[seq_key]
                        profile_name = build_profile_name(
                            analyst.name,
                            project.name,
                            plan_country,
                            plan_state,
                            plan_city,
                            device_type,
                            os_type,
                            sequence_value,
                        )
                        slot_signature = build_profile_slot_signature(
                            project.id,
                            analyst.name,
                            plan_country,
                            plan_state,
                            plan_city,
                            device_type,
                            os_type,
                            sequence_value,
                        )
                        if profile_name not in existing_profile_names and slot_signature not in existing_profile_signatures:
                            existing_profile_names.add(profile_name)
                            existing_profile_signatures.add(slot_signature)
                            break

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
                    location_text = location_label(plan_country, plan_state, plan_city)
                    payload = {
                        "name": profile_name,
                        "group_id": project.ads_group or "0",
                        "remark": project.remark_template or f"{project.name} | {current_subproject.name} | {analyst.name} | {location_text} | {os_type}",
                        "user_proxy_config": user_proxy_config,
                        "fingerprint_config": {
                            "automatic_timezone": "1",
                            "random_ua": {
                                "ua_browser": ["chrome"],
                                "ua_system_version": [os_type_to_system(os_type)],
                            },
                        },
                        "country": plan_country,
                    }
                    if ipchecker_value in {"ip2location", "ipapi"}:
                        payload["ipchecker"] = ipchecker_value
                    if project.extension_category:
                        payload["extension_category_name"] = project.extension_category.strip()
                        payload["remark"] = f"{payload['remark']} | extension:{project.extension_category}"

                    summary["create_now"] += 1
                    profile_rows.append({
                        "profile_name": profile_name,
                        "analyst": analyst.name,
                        "country": plan_country,
                        "state_name": plan_state,
                        "city_name": plan_city,
                        "device_type": device_type,
                        "os_type": os_type,
                        "proxy_kind_required": required_proxy_kind,
                        "proxy_kind_actual": normalize_proxy_kind(proxy_obj.proxy_kind) if proxy_obj else None,
                        "proxy_reason": proxy_reason,
                        "proxy": proxy_to_string(proxy_obj) if proxy_obj else "UNMAPPED",
                        "proxy_record_id": proxy_obj.id if proxy_obj else None,
                        "proxy_assignment_status": str(getattr(proxy_obj, "assignment_status", "") or "free") if proxy_obj else "unmapped",
                        "extension_category": normalize_extension_category(project.extension_category),
                        "risk_flags": risk_flags,
                        "profile_signature": slot_signature,
                        "payload": payload,
                    })

    analyst_grid = []
    total_required_sum = 0
    for row_key, summary in sorted(summary_by_row.items(), key=lambda kv: (kv[0][0].lower(), kv[0][1], kv[0][2].lower(), kv[0][3].lower())):
        summary["total_created"] = current_completed_counts[row_key]
        summary["protected_profiles"] = current_protected_counts[row_key]
        summary["pending_running"] = current_pending_running_counts[row_key]
        summary["gap"] = max(summary["total_required"] - summary["protected_profiles"], 0)
        total_required_sum += summary["total_required"]
        analyst_grid.append(summary)

    duplicate_proxy_rows = sum(max(len(group) - 1, 0) for group in identity_groups.values())
    assigned_proxy_rows = sum(1 for proxy_obj in all_proxies if str(getattr(proxy_obj, "assignment_status", "") or "").strip().lower() == "assigned")
    reserved_proxy_rows = sum(1 for proxy_obj in all_proxies if str(getattr(proxy_obj, "assignment_status", "") or "").strip().lower() == "reserved")
    locked_proxy_rows = sum(len(group) for identity, group in identity_groups.items() if identity in identity_locked)
    warnings = [f"Review is scoped to sub-project '{current_subproject.name}', but proxy locks and duplicate checks run across the full parent project."]
    if duplicate_proxy_rows:
        warnings.append(f"{duplicate_proxy_rows} duplicate proxy rows were detected across the parent project. Only the first copy of each endpoint is eligible for assignment.")
    if reserved_proxy_rows:
        warnings.append(f"{reserved_proxy_rows} proxies are currently reserved for pending or running jobs anywhere under the parent project.")
    if assigned_proxy_rows:
        warnings.append(f"{assigned_proxy_rows} proxies are locked to completed profiles across the parent project to prevent accidental reuse.")
    if not profile_rows and total_required_sum and sum(item["gap"] for item in analyst_grid) == 0 and current_protected_counts:
        warnings.append("No new profiles are queued for this sub-project because its current requirement is already fully covered.")

    totals = {
        "profiles_required": total_required_sum,
        "profiles_created": current_completed,
        "profiles_to_create_now": len(profile_rows),
        "proxy_count": len(all_proxies),
        "mapped_proxy_count": sum(1 for row in profile_rows if row["proxy"] != "UNMAPPED"),
        "unmapped_profiles": sum(1 for row in profile_rows if row["proxy"] == "UNMAPPED"),
    }
    job_progress = {
        "total": len(current_jobs),
        "pending": current_pending,
        "running": current_running,
        "completed": current_completed,
        "failed": current_failed,
        "eta_seconds": eta_seconds,
        "average_seconds_per_profile": avg_duration,
    }
    proxy_audit = {
        "unique_proxy_identities": len(identity_groups),
        "duplicate_proxy_rows": duplicate_proxy_rows,
        "duplicate_proxy_identities": len(duplicate_identity_rows),
        "duplicate_examples": duplicate_identity_rows[:10],
        "locked_proxy_rows": locked_proxy_rows,
        "reserved_proxy_rows": reserved_proxy_rows,
        "assigned_proxy_rows": assigned_proxy_rows,
        "eligible_proxy_rows": sum(1 for identity in identity_groups if identity not in identity_locked),
        "protected_job_count": global_protected_jobs,
        "warnings": warnings,
    }
    return {
        "subproject": subproject_to_dict(current_subproject),
        "analyst_grid": analyst_grid,
        "profile_rows": profile_rows,
        "totals": totals,
        "job_progress": job_progress,
        "proxy_audit": proxy_audit,
    }


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


@app.get("/api/master-projects")
def list_master_projects(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    projects = db.scalars(select(Project).where(Project.project_kind == "master").order_by(Project.created_at.desc())).all()
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
        project_kind="master",
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
    ensure_default_subproject(project, db)
    return project_to_dict(project)


@app.get("/api/projects/{project_id}")
def get_project(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    default_subproject = ensure_default_subproject(project, db)
    subprojects = db.scalars(select(SubProject).where(SubProject.project_id == project.id).order_by(SubProject.created_at.asc(), SubProject.id.asc())).all()
    return {
        "project": project_to_dict(project),
        "subprojects": [subproject_to_dict(s) for s in subprojects],
        "default_subproject_id": default_subproject.id,
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


@app.get("/api/projects/{project_id}/subprojects")
def list_subprojects(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    ensure_default_subproject(project, db)
    subprojects = db.scalars(select(SubProject).where(SubProject.project_id == project.id).order_by(SubProject.created_at.asc(), SubProject.id.asc())).all()
    return [subproject_to_dict(s) for s in subprojects]


@app.post("/api/projects/{project_id}/subprojects")
def create_subproject(project_id: int, data: SubProjectCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    ensure_default_subproject(project, db)
    name = str(data.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Sub-project name is required")
    existing = db.scalar(select(SubProject).where(SubProject.project_id == project.id, SubProject.name == name))
    if existing:
        raise HTTPException(status_code=400, detail="A sub-project with this name already exists in the parent project")
    subproject = SubProject(project_id=project.id, name=name, notes=(str(data.notes or "").strip() or None))
    db.add(subproject)
    db.commit()
    db.refresh(subproject)
    return subproject_to_dict(subproject)


@app.get("/api/projects/{project_id}/analysts")
def list_analysts(project_id: int, sub_project_id: Optional[int] = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    subproject = resolve_subproject(project, db, sub_project_id)
    analysts = db.scalars(select(Analyst).where(Analyst.project_id == project.id, Analyst.sub_project_id == subproject.id).order_by(Analyst.name.asc())).all()
    return [analyst_to_dict(a) for a in analysts]


@app.post("/api/projects/{project_id}/analysts")
def add_analysts(project_id: int, names_csv: str = Form(...), sub_project_id: Optional[int] = Form(None), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    subproject = resolve_subproject(project, db, sub_project_id)
    created = []
    for raw in names_csv.splitlines():
        name = raw.strip()
        if not name:
            continue
        analyst = Analyst(project_id=project_id, sub_project_id=subproject.id, name=name)
        db.add(analyst)
        created.append(name)
    db.commit()
    return {"created": created, "sub_project_id": subproject.id}


@app.delete("/api/analysts/{analyst_id}")
def delete_analyst(analyst_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    analyst = db.get(Analyst, analyst_id)
    if not analyst:
        raise HTTPException(status_code=404, detail="Analyst not found")
    db.delete(analyst)
    db.commit()
    return {"deleted": analyst_id}


@app.get("/api/projects/{project_id}/countries")
def list_countries(project_id: int, sub_project_id: Optional[int] = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    subproject = resolve_subproject(project, db, sub_project_id)
    plans = db.scalars(select(CountryPlan).where(CountryPlan.project_id == project.id, CountryPlan.sub_project_id == subproject.id).order_by(CountryPlan.country_code.asc(), CountryPlan.id.asc())).all()
    return [country_to_dict(c) for c in plans]


@app.post("/api/projects/{project_id}/countries")
def add_country_plan(project_id: int, data: CountryPlanIn, sub_project_id: Optional[int] = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    subproject = resolve_subproject(project, db, sub_project_id)
    if data.total_profiles <= 0:
        raise HTTPException(status_code=400, detail="Total profiles must be greater than 0")
    if not str(data.country_code or '').strip():
        raise HTTPException(status_code=400, detail="Country is required")
    analyst_ids_csv = ",".join(str(x) for x in data.analyst_ids)
    country_code = str(data.country_code or '').strip().upper()
    state_name = normalize_location_value(data.state_name)
    city_name = normalize_location_value(data.city_name)
    if state_name == "All":
        city_name = "All"
    existing = db.scalar(select(CountryPlan).where(
        CountryPlan.project_id == project_id,
        CountryPlan.sub_project_id == subproject.id,
        CountryPlan.country_code == country_code,
        CountryPlan.state_name == state_name,
        CountryPlan.city_name == city_name,
    ))
    if existing:
        existing.total_profiles = data.total_profiles
        existing.analyst_ids_csv = analyst_ids_csv
        db.commit()
        return country_to_dict(existing)
    plan = CountryPlan(
        project_id=project_id,
        sub_project_id=subproject.id,
        country_code=country_code,
        state_name=state_name,
        city_name=city_name,
        total_profiles=data.total_profiles,
        analyst_ids_csv=analyst_ids_csv,
    )
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
async def upload_proxies(project_id: int, file: UploadFile = File(...), replace_existing: bool = Form(False), sub_project_id: Optional[int] = Form(None), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    subproject = resolve_subproject(project, db, sub_project_id)
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
            for proxy_obj in db.scalars(select(ProxyRecord).where(ProxyRecord.project_id == project.id, ProxyRecord.sub_project_id == subproject.id)).all():
                db.delete(proxy_obj)
            db.flush()
        created = 0
        errors = []
        if parse_mode == "raw_lines":
            for idx, line in enumerate(lines, start=1):
                try:
                    parsed = parse_proxy_line(line)
                    db.add(ProxyRecord(project_id=project_id, sub_project_id=subproject.id, **parsed))
                    created += 1
                except Exception as exc:
                    errors.append({"row": idx, "error": str(exc)})
        else:
            for idx, row in enumerate(rows, start=2):
                try:
                    parsed = parse_proxy_row(row)
                    db.add(ProxyRecord(project_id=project_id, sub_project_id=subproject.id, **parsed))
                    created += 1
                except Exception as exc:
                    errors.append({"row": idx, "error": str(exc)})
        db.commit()
        return {"created": created, "errors": errors, "headers": headers, "filename": file.filename, "parse_mode": parse_mode, "sub_project_id": subproject.id}
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Proxy upload failed on server: {exc}")


@app.get("/api/projects/{project_id}/proxies")
def list_proxies(project_id: int, sub_project_id: Optional[int] = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    subproject = resolve_subproject(project, db, sub_project_id)
    proxies = db.scalars(select(ProxyRecord).where(ProxyRecord.project_id == project.id, ProxyRecord.sub_project_id == subproject.id).order_by(ProxyRecord.id.asc())).all()
    return [{
        "id": proxy_obj.id,
        "project_id": proxy_obj.project_id,
        "sub_project_id": proxy_obj.sub_project_id,
        "provider": proxy_obj.provider,
        "country_code": proxy_obj.country_code,
        "state_name": normalize_location_value(proxy_obj.state_name),
        "city_name": normalize_location_value(proxy_obj.city_name),
        "proxy_kind": proxy_obj.proxy_kind,
        "proxy_type": proxy_obj.proxy_type,
        "proxy_soft": proxy_obj.proxy_soft,
        "ipchecker": proxy_obj.ipchecker,
        "proxy_identity": proxy_identity_key(proxy_obj.proxy_host, proxy_obj.proxy_port, proxy_obj.proxy_username),
        "assigned": bool(proxy_obj.assigned),
        "assignment_status": str(getattr(proxy_obj, "assignment_status", "") or "free"),
        "assigned_profile_name": getattr(proxy_obj, "assigned_profile_name", None),
        "assigned_job_id": getattr(proxy_obj, "assigned_job_id", None),
        "assigned_adspower_profile_id": getattr(proxy_obj, "assigned_adspower_profile_id", None),
        "proxy": proxy_to_string(proxy_obj),
    } for proxy_obj in proxies]


@app.get("/api/projects/{project_id}/review")
def get_review(project_id: int, sub_project_id: Optional[int] = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return build_review(project, db, sub_project_id)


@app.post("/api/projects/{project_id}/create-jobs")
def create_jobs(project_id: int, sub_project_id: Optional[int] = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    subproject = resolve_subproject(project, db, sub_project_id)
    review = build_review(project, db, subproject.id)
    if not review["profile_rows"]:
        raise HTTPException(status_code=400, detail="No remaining profiles need to be created for this sub-project. Its current requirement is already satisfied.")
    unmapped = [row for row in review["profile_rows"] if row["proxy"] == "UNMAPPED"]
    if unmapped:
        preview = "; ".join(f"{row['profile_name']}: {row['proxy_reason']}" for row in unmapped[:5])
        raise HTTPException(status_code=400, detail=f"Cannot create jobs until every new profile has a matching proxy. {preview}")
    for existing in db.scalars(select(ProvisionJob).where(ProvisionJob.project_id == project.id, ProvisionJob.sub_project_id == subproject.id)).all():
        if existing.status in {"pending", "running"}:
            raise HTTPException(status_code=400, detail="There are already pending or running jobs for this sub-project")

    created = 0
    for row in review["profile_rows"]:
        proxy_record_id = row.get("proxy_record_id")
        if not proxy_record_id:
            raise HTTPException(status_code=400, detail=f"Profile {row['profile_name']} is missing a proxy lock target")
        proxy_obj = db.get(ProxyRecord, proxy_record_id)
        if not proxy_obj:
            raise HTTPException(status_code=400, detail=f"Proxy record {proxy_record_id} was not found")
        current_status = str(getattr(proxy_obj, "assignment_status", "") or "free").strip().lower()
        if bool(proxy_obj.assigned) or current_status in {"reserved", "assigned"}:
            raise HTTPException(status_code=400, detail=f"Proxy {proxy_to_string(proxy_obj)} is already locked to another profile under this parent project")

        job = ProvisionJob(
            project_id=project.id,
            sub_project_id=subproject.id,
            connector_name=project.connector_name,
            profile_name=row["profile_name"],
            analyst_name=row["analyst"],
            country_code=row["country"],
            state_name=row.get("state_name"),
            city_name=row.get("city_name"),
            device_type=row["device_type"],
            os_type=row["os_type"],
            proxy_record_id=proxy_record_id,
            profile_signature=row.get("profile_signature"),
            duplicate_risk_json=json.dumps(row.get("risk_flags") or []),
            status="pending",
            payload_json=json.dumps(row["payload"]),
            updated_at=utcnow(),
        )
        db.add(job)
        db.flush()

        proxy_obj.assigned = True
        proxy_obj.assignment_status = "reserved"
        proxy_obj.assigned_profile_name = row["profile_name"]
        proxy_obj.assigned_job_id = job.id
        proxy_obj.assigned_at = utcnow()
        proxy_obj.assigned_adspower_profile_id = None
        created += 1

    db.commit()
    return {"created_jobs": created, "locked_proxies": created, "sub_project_id": subproject.id}


@app.post("/api/projects/{project_id}/proxy-locks/release-all")
def release_proxy_locks(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if any(job.status in {"pending", "running"} for job in project.jobs):
        raise HTTPException(status_code=400, detail="Cannot release proxy locks while jobs are pending or running anywhere in the parent project")

    released = 0
    for proxy_obj in project.proxies:
        current_status = str(getattr(proxy_obj, "assignment_status", "") or "free").strip().lower()
        if bool(proxy_obj.assigned) or current_status in {"reserved", "assigned"} or getattr(proxy_obj, "assigned_profile_name", None) or getattr(proxy_obj, "assigned_job_id", None) or getattr(proxy_obj, "assigned_adspower_profile_id", None):
            proxy_obj.assigned = False
            proxy_obj.assignment_status = "free"
            proxy_obj.assigned_profile_name = None
            proxy_obj.assigned_job_id = None
            proxy_obj.assigned_at = None
            proxy_obj.assigned_adspower_profile_id = None
            released += 1
    db.commit()
    return {"released_proxies": released}


@app.get("/api/projects/{project_id}/jobs")
def list_jobs(project_id: int, sub_project_id: Optional[int] = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    subproject = resolve_subproject(project, db, sub_project_id)
    jobs = db.scalars(select(ProvisionJob).where(ProvisionJob.project_id == project.id, ProvisionJob.sub_project_id == subproject.id).order_by(ProvisionJob.created_at.desc())).all()
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
            "project_id": j.project_id,
            "sub_project_id": j.sub_project_id,
            "profile_name": j.profile_name,
            "analyst_name": j.analyst_name,
            "country_code": j.country_code,
            "state_name": normalize_location_value(getattr(j, 'state_name', None)),
            "city_name": normalize_location_value(getattr(j, 'city_name', None)),
            "device_type": j.device_type,
            "os_type": j.os_type,
            "proxy_record_id": getattr(j, 'proxy_record_id', None),
            "adspower_profile_id": getattr(j, 'adspower_profile_id', None),
            "duplicate_risk": safe_json_loads(getattr(j, 'duplicate_risk_json', None), []),
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
    extracted_profile_id = extract_adspower_profile_id(data.result)
    if extracted_profile_id:
        job.adspower_profile_id = extracted_profile_id

    proxy_obj = db.get(ProxyRecord, job.proxy_record_id) if getattr(job, "proxy_record_id", None) else None
    if proxy_obj:
        if data.status == "completed":
            proxy_obj.assigned = True
            proxy_obj.assignment_status = "assigned"
            proxy_obj.assigned_profile_name = job.profile_name
            proxy_obj.assigned_job_id = job.id
            proxy_obj.assigned_at = utcnow()
            proxy_obj.assigned_adspower_profile_id = extracted_profile_id
        elif data.status == "failed":
            proxy_obj.assigned = False
            proxy_obj.assignment_status = "free"
            proxy_obj.assigned_profile_name = None
            proxy_obj.assigned_job_id = None
            proxy_obj.assigned_at = None
            proxy_obj.assigned_adspower_profile_id = None

    db.commit()
    return {"ok": True, "adspower_profile_id": extracted_profile_id}

@app.get("/api/proxy-template.csv")
def download_proxy_template(user: User = Depends(get_current_user)):
    sample = "\n".join([
        "provider,country_code,state_name,city_name,proxy_kind,proxy_type,proxy_soft,ipchecker,proxy_host,proxy_port,proxy_username,proxy_password",
        "Decodo,US,Texas,Dallas,residential,https,other,ipapi,res-us.example.com,8000,user1,pass1",
        "IPBurger,IN,All,All,mobile,http,other,ip2location,mob-in.example.com,9000,user2,pass2",
    ])
    headers = {"Content-Disposition": 'attachment; filename="proxy_template_example.csv"'}
    return Response(content=sample + "\n", media_type="text/csv", headers=headers)


@app.get("/health")
def health():
    return {"status": "ok", "time": utcnow().isoformat()}
