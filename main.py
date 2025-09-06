"""
Mini Fingerprint — FastAPI + Postgres
- POST /fp    : compute component hashes + master hash; log to DB
- GET  /      : serve index.html
- GET  /recent: last N rows (default 10)
- GET  /stats : { total_hits, unique_fps }  (by master hash)
- GET  /health: { status, salt_configured, db }

Env:
  - FP_SALT       : long random string (required in prod)
  - DATABASE_URL  : postgres://USER:PASS@HOST:PORT/DBNAME (Render Postgres External Connection String)
"""
import os, json, hashlib, logging, datetime
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlmodel import SQLModel, Field, Session, create_engine, select
from sqlalchemy import func, distinct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mini-fingerprint")

app = FastAPI(title="Mini Fingerprint", version="1.3.0")

# ---------- Config ----------
FP_SALT = os.getenv("FP_SALT", "dev-only-salt-change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")  # local fallback for quick testing
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

if FP_SALT == "dev-only-salt-change-me":
    logger.warning("⚠ Using default salt! Set FP_SALT in production.")

# ---------- DB Model ----------
class Fingerprint(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

    # component hashes
    fp_master: str = Field(index=True)
    fp_browser: Optional[str] = Field(default=None, index=True)
    fp_platform: Optional[str] = Field(default=None, index=True)
    fp_graphics: Optional[str] = Field(default=None, index=True)

    # light metadata (remove if you want stricter privacy)
    ip: Optional[str] = Field(default=None, index=True)
    user_agent: Optional[str] = Field(default=None)

    created_at: datetime.datetime = Field(
        default_factory=datetime.datetime.utcnow, index=True
    )

# ---------- Schemas ----------
class TraitsEnvelope(BaseModel):
    # we expect { "data": {...traits...} } from the client
    data: Dict[str, Any]

# ---------- Utils ----------
def stable_json_dumps(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

# ---------- Startup ----------
@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)

# ---------- Routes ----------
@app.get("/")
def serve_frontend():
    return FileResponse("index.html")

@app.post("/fp")
def generate_fingerprint(payload: TraitsEnvelope, request: Request):
    """
    Calculates three component hashes + a master hash (hash of those parts),
    logs a row, and returns { fp, parts } where:
      - parts.browser   : hash of UA + UA-CH + languages
      - parts.platform  : hash of platform + hw + screen (bucketed client-side) + timezone bucket
      - parts.graphics  : hash of canvas + webgl vendor/renderer/api
      - fp              : master hash over the three parts
    """
    try:
        data = payload.data or {}

        browser_obj  = {
            "userAgent": data.get("userAgent"),
            "uaCh": data.get("uaCh"),
            "languages": data.get("languages"),
        }
        platform_obj = {
            "platform": data.get("platform"),
            "hw": data.get("hw"),
            "screen": data.get("screen"),
            "timezoneMinutesBucket": data.get("timezoneMinutesBucket"),
        }
        graphics_obj = {
            "canvas": data.get("canvas"),
            "webgl": data.get("webgl"),
        }

        fp_browser  = sha256_hex(FP_SALT + "|" + stable_json_dumps(browser_obj))
        fp_platform = sha256_hex(FP_SALT + "|" + stable_json_dumps(platform_obj))
        fp_graphics = sha256_hex(FP_SALT + "|" + stable_json_dumps(graphics_obj))

        master_payload = stable_json_dumps({"b": fp_browser, "p": fp_platform, "g": fp_graphics})
        fp_master = sha256_hex(FP_SALT + "|" + master_payload)

        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent")

        with Session(engine) as s:
            s.add(Fingerprint(
                fp_master=fp_master,
                fp_browser=fp_browser,
                fp_platform=fp_platform,
                fp_graphics=fp_graphics,
                ip=ip,
                user_agent=ua
            ))
            s.commit()

        return {"fp": fp_master, "parts": {
            "browser": fp_browser, "platform": fp_platform, "graphics": fp_graphics
        }}
    except Exception:
        logger.exception("Error generating fingerprint")
        return {"error": "Failed to generate fingerprint"}

@app.get("/recent")
def recent(limit: int = 10):
    with Session(engine) as s:
        rows: List[Fingerprint] = s.exec(
            select(Fingerprint).order_by(Fingerprint.id.desc()).limit(limit)
        ).all()
        return [
            {
                "id": r.id,
                "fp": r.fp_master,
                "browser": r.fp_browser,
                "platform": r.fp_platform,
                "graphics": r.fp_graphics,
                "ip": r.ip,
                "user_agent": r.user_agent,
                "created_at": r.created_at.isoformat() + "Z",
            }
            for r in rows
        ]

@app.get("/stats")
def stats():
    with Session(engine) as s:
        total_val = s.exec(select(func.count(Fingerprint.id))).one()
        unique_val = s.exec(select(func.count(distinct(Fingerprint.fp_master)))).one()
        def to_int(v): return int(v[0]) if isinstance(v, tuple) else int(v)
        return {"total_hits": to_int(total_val), "unique_fps": to_int(unique_val)}

@app.get("/health")
def health_check():
    try:
        with Session(engine) as s:
            s.exec(select(Fingerprint).limit(1)).all()
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "status": "healthy",
        "salt_configured": FP_SALT != "dev-only-salt-change-me",
        "db": db_ok
    }

# Local dev runner
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
