import csv
import io
import json
import math
import os
import secrets
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from itsdangerous import URLSafeSerializer, BadSignature

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("PORTAL_DB_PATH", os.path.join(os.path.dirname(BASE_DIR), "portal.db"))
SECRET_KEY = os.getenv("PORTAL_SECRET_KEY", "change-me-in-production")
ADMIN_USERNAME = os.getenv("PORTAL_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("PORTAL_ADMIN_PASSWORD", "ChangeMe123!")
CONNECTOR_SHARED_TOKEN = os.getenv("PORTAL_CONNECTOR_SHARED_TOKEN", "change-connector-token")

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
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
    naming_pattern: Mapped[str] = mapped_column(String(255), default="Project_Country_Analyst_Device_Sequence")
    desktop_pct: Mapped[float] = mapped_column(Float, default=50)
    mobile_pct: Mapped[float] = mapped_column(Float, default=50)
    windows_pct: Mapped[float] = mapped_column(Float, default=50)
    mac_pct: Mapped[float] = mapped_column(Float, default=50)
    android_pct: Mapped[float] = mapped_column(Float, default=50)
    iphone_pct: Mapped[float] = mapped_column(Float, default=50)
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
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(bind=engine)


app = FastAPI(title="AdsPower Profile Provisioning Portal")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


class ProjectCreate(BaseModel):
    name: str
    code: str
    ads_group: Optional[str] = None
    extension_category: Optional[str] = None
    naming_pattern: str = "Project_Country_Analyst_Device_Sequence"


class ProjectSettings(BaseModel):
    desktop_pct: float
    mobile_pct: float
    windows_pct: float
    mac_pct: float
    android_pct: float
    iphone_pct: float
    ads_group: Optional[str] = None
    extension_category: Optional[str] = None
    connector_name: Optional[str] = None
    remark_template: Optional[str] = None


class CountryPlanIn(BaseModel):
    country_code: str
    total_profiles: int
    analyst_ids: List[int]


class ConnectorIn(BaseModel):
    name: str
    host_os: str


class JobResultIn(BaseModel):
    status: str
    result: Dict


class LoginIn(BaseModel):
    username: str
    password: str


def utcnow():
    return datetime.now(timezone.utc)


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


def project_to_dict(project: Project):
    return {
        "id": project.id,
        "name": project.name,
        "code": project.code,
        "ads_group": project.ads_group,
        "extension_category": project.extension_category,
        "naming_pattern": project.naming_pattern,
        "desktop_pct": project.desktop_pct,
        "mobile_pct": project.mobile_pct,
        "windows_pct": project.windows_pct,
        "mac_pct": project.mac_pct,
        "android_pct": project.android_pct,
        "iphone_pct": project.iphone_pct,
        "remark_template": project.remark_template,
        "connector_name": project.connector_name,
    }


def analyst_to_dict(a: Analyst):
    return {"id": a.id, "name": a.name, "email": a.email}


def country_to_dict(c: CountryPlan):
    analyst_ids = [int(x) for x in c.analyst_ids_csv.split(",") if x.strip()]
    return {"id": c.id, "country_code": c.country_code, "total_profiles": c.total_profiles, "analyst_ids": analyst_ids}


def parse_proxy_row(row: Dict[str, str]) -> Dict[str, Optional[str]]:
    norm = {str(k).strip().lower(): (str(v).strip() if v is not None else "") for k, v in row.items()}
    proxy_string = norm.get("proxy") or norm.get("proxy_string") or norm.get("raw_proxy") or ""
    host = norm.get("proxy_host") or norm.get("host") or ""
    port = norm.get("proxy_port") or norm.get("port") or ""
    username = norm.get("proxy_username") or norm.get("username") or ""
    password = norm.get("proxy_password") or norm.get("password") or ""
    if proxy_string and not host and ":" in proxy_string:
        parts = proxy_string.split(":")
        if len(parts) >= 4:
            host, port, username, password = parts[0], parts[1], parts[2], ":".join(parts[3:])
        elif len(parts) >= 2:
            host, port = parts[0], parts[1]
    if not host or not port:
        raise ValueError("Proxy row missing host or port")
    return {
        "provider": norm.get("provider") or norm.get("proxy_provider") or None,
        "country_code": (norm.get("country") or norm.get("country_code") or "").upper() or None,
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
    proxies_by_country = defaultdict(list)
    untagged_proxies = []
    for p in all_proxies:
        if p.country_code:
            proxies_by_country[p.country_code.upper()].append(p)
        else:
            untagged_proxies.append(p)

    proxy_used_ids = set()
    profile_rows = []
    analyst_summary = defaultdict(lambda: {
        "analyst": "",
        "countries": set(),
        "total_profiles": 0,
        "desktop": 0,
        "mobile": 0,
        "windows": 0,
        "mac": 0,
        "android": 0,
        "iphone": 0,
        "proxy_rows_mapped": 0,
        "extension_category": project.extension_category or "",
    })
    seq_map = defaultdict(int)

    for plan in sorted(plans, key=lambda x: x.country_code):
        assigned_ids = [int(x) for x in plan.analyst_ids_csv.split(",") if x.strip() and int(x) in analysts]
        if not assigned_ids:
            continue
        shares = split_even(plan.total_profiles, [str(x) for x in assigned_ids])
        country_proxy_pool = [p for p in proxies_by_country.get(plan.country_code.upper(), []) if p.id not in proxy_used_ids]
        fallback_pool = [p for p in untagged_proxies if p.id not in proxy_used_ids]
        pooled = country_proxy_pool + fallback_pool
        proxy_index = 0

        for analyst_id_str, share_count in shares.items():
            analyst = analysts[int(analyst_id_str)]
            seg = allocate_segments(share_count, project)
            analyst_key = analyst.name
            summary = analyst_summary[analyst_key]
            summary["analyst"] = analyst.name
            summary["countries"].add(plan.country_code.upper())
            summary["total_profiles"] += share_count
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
                for _ in range(count):
                    seq_key = (project.code, plan.country_code.upper(), analyst.name, os_type.upper())
                    seq_map[seq_key] += 1
                    proxy_obj = pooled[proxy_index] if proxy_index < len(pooled) else None
                    if proxy_obj:
                        proxy_used_ids.add(proxy_obj.id)
                        proxy_index += 1
                        summary["proxy_rows_mapped"] += 1
                    profile_name = f"{normalize_name(project.code)}_{normalize_name(plan.country_code.upper())}_{normalize_name(analyst.name)}_{os_type.upper()}_{seq_map[seq_key]:03d}"
                    payload = {
                        "name": profile_name,
                        "group_id": project.ads_group or "0",
                        "remark": project.remark_template or f"{project.name} | {analyst.name} | {plan.country_code.upper()} | {os_type}",
                        "user_proxy_config": {
                            "proxy_type": "http",
                            "proxy_host": proxy_obj.proxy_host if proxy_obj else "",
                            "proxy_port": proxy_obj.proxy_port if proxy_obj else "",
                            "proxy_user": (proxy_obj.proxy_username if proxy_obj else "") or "",
                            "proxy_password": (proxy_obj.proxy_password if proxy_obj else "") or "",
                        },
                        "fingerprint_config": {
                            "automatic_timezone": "1",
                            "random_ua": {
                                "ua_browser": "chrome",
                                "ua_system_version": os_type_to_system(os_type),
                            },
                        },
                        "country": plan.country_code.upper(),
                    }
                    if project.extension_category:
                        payload["remark"] = f"{payload['remark']} | extension:{project.extension_category}"
                    profile_rows.append({
                        "profile_name": profile_name,
                        "analyst": analyst.name,
                        "country": plan.country_code.upper(),
                        "device_type": device_type,
                        "os_type": os_type,
                        "proxy": proxy_to_string(proxy_obj) if proxy_obj else "UNMAPPED",
                        "extension_category": project.extension_category or "",
                        "payload": payload,
                    })

    analyst_grid = []
    for summary in sorted(analyst_summary.values(), key=lambda x: x["analyst"]):
        summary["countries"] = ", ".join(sorted(summary["countries"]))
        analyst_grid.append(summary)

    totals = {
        "projects_profiles": len(profile_rows),
        "proxy_count": len(all_proxies),
        "mapped_proxy_count": len(proxy_used_ids),
        "unmapped_profiles": sum(1 for r in profile_rows if r["proxy"] == "UNMAPPED"),
    }
    return {"analyst_grid": analyst_grid, "profile_rows": profile_rows, "totals": totals}


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
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", "")).strip()
    user = db.scalar(select(User).where(User.username == username))
    if not user or not pwd_context.verify(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"}, status_code=400)
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
    return templates.TemplateResponse("app.html", {"request": request, "username": user.username})


@app.get("/api/me")
def api_me(user: User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role}


@app.get("/api/projects")
def list_projects(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    projects = db.scalars(select(Project).order_by(Project.created_at.desc())).all()
    return [project_to_dict(p) for p in projects]


@app.post("/api/projects")
def create_project(data: ProjectCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    existing = db.scalar(select(Project).where(Project.code == data.code.strip()))
    if existing:
        raise HTTPException(status_code=400, detail="Project code already exists")
    project = Project(
        name=data.name.strip(),
        code=data.code.strip().upper(),
        ads_group=data.ads_group,
        extension_category=data.extension_category,
        naming_pattern=data.naming_pattern,
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
    for field in ["desktop_pct", "mobile_pct", "windows_pct", "mac_pct", "android_pct", "iphone_pct", "ads_group", "extension_category", "connector_name", "remark_template"]:
        setattr(project, field, getattr(data, field))
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
    raw = await file.read()
    decoded = raw.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(decoded))
    rows = list(reader)
    if not rows:
        raise HTTPException(status_code=400, detail="No CSV rows found")
    if replace_existing:
        for p in list(project.proxies):
            db.delete(p)
        db.flush()
    created = 0
    errors = []
    for idx, row in enumerate(rows, start=2):
        try:
            parsed = parse_proxy_row(row)
            db.add(ProxyRecord(project_id=project_id, **parsed))
            created += 1
        except Exception as exc:
            errors.append({"row": idx, "error": str(exc)})
    db.commit()
    return {"created": created, "errors": errors}


@app.get("/api/projects/{project_id}/proxies")
def list_proxies(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return [{
        "id": p.id,
        "provider": p.provider,
        "country_code": p.country_code,
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
    return [{
        "id": j.id,
        "profile_name": j.profile_name,
        "analyst_name": j.analyst_name,
        "country_code": j.country_code,
        "device_type": j.device_type,
        "os_type": j.os_type,
        "status": j.status,
        "result_json": json.loads(j.result_json) if j.result_json else None,
    } for j in jobs]


@app.get("/api/connectors")
def list_connectors(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    connectors = db.scalars(select(ConnectorHeartbeat).order_by(ConnectorHeartbeat.name.asc())).all()
    return [{"name": c.name, "host_os": c.host_os, "last_seen": c.last_seen.isoformat()} for c in connectors]


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
    db.commit()
    return {"ok": True}


@app.post("/api/connector/fetch-job")
def connector_fetch_job(data: ConnectorIn, request: Request, db: Session = Depends(get_db)):
    require_connector_token(request)
    connector = db.scalar(select(ConnectorHeartbeat).where(ConnectorHeartbeat.name == data.name))
    if not connector:
        connector = ConnectorHeartbeat(name=data.name, host_os=data.host_os, last_seen=utcnow())
        db.add(connector)
        db.commit()
    else:
        connector.last_seen = utcnow()
        db.commit()
    job = db.scalar(select(ProvisionJob).where(
        ProvisionJob.status == "pending",
        (ProvisionJob.connector_name == data.name) | (ProvisionJob.connector_name.is_(None))
    ).order_by(ProvisionJob.created_at.asc()))
    if not job:
        return {"job": None}
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


@app.get("/health")
def health():
    return {"status": "ok", "time": utcnow().isoformat()}
