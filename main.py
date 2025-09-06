"""
Mini Fingerprint FastAPI Backend with Postgres logging + stats
- POST /fp : hash traits (salted) and log to DB
- GET  /recent : last N rows
- GET  /stats  : total hits, unique fingerprints
- GET  /health : simple health + DB check
- GET  /       : serve index.html
"""
import os, json, hashlib, logging, datetime
from typing import Any, Dict, Optional, List, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlmodel import SQLModel, Field, Session, create_engine, select
from sqlalchemy import func, distinct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mini-fingerprint")

app = FastAPI(title="Mini Fingerprint", version="1.2.0")

# --- Config ---
FP_SALT = os.getenv("FP_SALT", "dev-only-salt-change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")  # local fallback
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

if FP_SALT == "dev-only-salt-change-me":
    logger.warning("⚠ Using default salt! Set FP_SALT in production.")

# --- DB models ---
class Fingerprint(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    fp: str = Field(index=True)
    ip: Optional[str] = Field(default=None, index=True)
    user_agent: Optional[str] = Field(default=None)
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, index=True)

# --- Schemas ---
class TraitsInput(BaseModel):
    # we accept any traits payload under "data"
    data: Dict[str, Any]

# --- Utils ---
def stable_json_dumps(obj: Dict[str, Any]) -> str:
    # sorted keys + compact separators → stable string to hash
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

# --- Startup ---
@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)

# --- Routes ---
@app.get("/")
def serve_frontend():
    return FileResponse("index.html")

@app.post("/fp")
def generate_fingerprint(traits: TraitsInput, request: Request):
    """
    Body: { "data": { ...traits... } }
    Returns: { "fp": "<sha256 hex>" }
    Also logs a row to the DB (fp, ip, user_agent, created_at).
    """
    try:
        normalized = stable_json_dumps(traits.data)
        fingerprint = sha256_hex(FP_SALT + "|" + normalized)

        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent")

        with Session(engine) as s:
            s.add(Fingerprint(fp=fingerprint, ip=ip, user_agent=ua))
            s.commit()

        return {"fp": fingerprint}
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
                "fp": r.fp,
                "ip": r.ip,
                "user_agent": r.user_agent,
                "created_at": r.created_at.isoformat() + "Z",
            }
            for r in rows
        ]

@app.get("/stats")
def stats():
    """
    Returns simple metrics:
    {
      "total_hits": <count of rows>,
      "unique_fps": <count of distinct fp>
    }
    """
    with Session(engine) as s:
        total_val = s.exec(select(func.count(Fingerprint.id))).one()
        unique_val = s.exec(select(func.count(distinct(Fingerprint.fp)))).one()

        # .one() can return a scalar or a tuple depending on versions; normalize to int
        def to_int(v: Any) -> int:
            if isinstance(v, tuple):
                return int(v[0])
            return int(v)

        return {
            "total_hits": to_int(total_val),
            "unique_fps": to_int(unique_val),
        }

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

# Enable local run: `python main.py`
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
