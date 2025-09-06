"""
Mini Fingerprint FastAPI Backend with PostgreSQL Database
Collects browser traits, generates SHA-256 fingerprints, and stores data persistently
"""
import os
import json
import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Try alternative environment variables that might be available
    host = os.getenv("PGHOST", "localhost")
    port = os.getenv("PGPORT", "5432")
    database = os.getenv("PGDATABASE", "postgres")
    user = os.getenv("PGUSER", "postgres")
    password = os.getenv("PGPASSWORD", "")
    
    if host and port and database and user:
        DATABASE_URL = f"postgresql://{user}:{password}@{host}:{port}/{database}"
        logger.info("Constructed DATABASE_URL from individual environment variables")
    else:
        logger.error("No database connection information found!")
        raise RuntimeError("Database connection required")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class FingerprintRecord(Base):
    __tablename__ = "fingerprints"
    
    id = Column(Integer, primary_key=True, index=True)
    fingerprint = Column(String(64), unique=True, index=True, nullable=False)
    traits = Column(JSON, nullable=False)
    user_agent = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    visit_count = Column(Integer, default=1)

# Create tables
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(title="Mini Fingerprint", version="1.0.0", description="Browser fingerprinting with database persistence")

# Get salt from environment variable or use dev default
FP_SALT = os.getenv("FP_SALT", "dev-only-salt-change-me")
if FP_SALT == "dev-only-salt-change-me":
    logger.warning("Using default salt! Set FP_SALT environment variable in production.")

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic models
class TraitsInput(BaseModel):
    """Pydantic model for incoming traits data"""
    data: Dict[str, Any]

class FingerprintResponse(BaseModel):
    """Response model for fingerprint generation"""
    fp: str
    is_new: bool
    visit_count: int
    first_seen: datetime
    last_seen: datetime

class FingerprintStats(BaseModel):
    """Statistics about stored fingerprints"""
    total_fingerprints: int
    total_visits: int
    unique_user_agents: int
    recent_fingerprints: List[Dict[str, Any]]

def stable_json_dumps(obj: Dict[str, Any]) -> str:
    """
    Convert object to stable JSON string with sorted keys and compact format
    This ensures the same traits always produce the same JSON representation
    """
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))

def sha256_hex(s: str) -> str:
    """
    Generate SHA-256 hash of string and return as hex
    """
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def extract_client_info(traits_data: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """
    Extract useful client information from traits
    """
    return {
        "user_agent": traits_data.get("userAgent"),
        "platform": traits_data.get("platform"),
        "language": traits_data.get("language"),
        "timezone": traits_data.get("timezone")
    }

@app.get("/")
async def serve_frontend():
    """Serve the index.html frontend"""
    return FileResponse("index.html")

@app.post("/fp", response_model=FingerprintResponse)
async def generate_fingerprint(traits: TraitsInput, db: Session = Depends(get_db)):
    """
    Generate fingerprint from browser traits and store in database
    
    1. Normalize traits to stable JSON format
    2. Prepend with salt and generate SHA-256 hash
    3. Check if fingerprint exists in database
    4. Update or create record with visit tracking
    5. Return fingerprint with metadata
    """
    try:
        # Normalize traits to stable JSON string
        normalized_traits = stable_json_dumps(traits.data)
        logger.info(f"Processing traits for fingerprint generation")
        
        # Generate fingerprint
        salted_data = FP_SALT + normalized_traits
        fingerprint = sha256_hex(salted_data)
        
        # Extract client info
        client_info = extract_client_info(traits.data)
        
        # Check if fingerprint already exists
        existing_record = db.query(FingerprintRecord).filter(
            FingerprintRecord.fingerprint == fingerprint
        ).first()
        
        if existing_record:
            # Update existing record
            existing_record.visit_count += 1
            existing_record.last_seen = datetime.utcnow()
            existing_record.traits = traits.data  # Update with latest traits
            if client_info["user_agent"]:
                existing_record.user_agent = client_info["user_agent"]
            
            db.commit()
            db.refresh(existing_record)
            
            logger.info(f"Updated existing fingerprint: {fingerprint} (visit #{existing_record.visit_count})")
            
            return FingerprintResponse(
                fp=fingerprint,
                is_new=False,
                visit_count=existing_record.visit_count,
                first_seen=existing_record.created_at,
                last_seen=existing_record.last_seen
            )
        else:
            # Create new record
            new_record = FingerprintRecord(
                fingerprint=fingerprint,
                traits=traits.data,
                user_agent=client_info["user_agent"],
                created_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                visit_count=1
            )
            
            db.add(new_record)
            db.commit()
            db.refresh(new_record)
            
            logger.info(f"Created new fingerprint: {fingerprint}")
            
            return FingerprintResponse(
                fp=fingerprint,
                is_new=True,
                visit_count=1,
                first_seen=new_record.created_at,
                last_seen=new_record.last_seen
            )
            
    except Exception as e:
        logger.error(f"Error generating fingerprint: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate fingerprint")

@app.get("/stats", response_model=FingerprintStats)
async def get_fingerprint_stats(db: Session = Depends(get_db)):
    """
    Get statistics about stored fingerprints
    """
    try:
        # Get total counts
        total_fingerprints = db.query(FingerprintRecord).count()
        from sqlalchemy import func
        total_visits = db.query(func.sum(FingerprintRecord.visit_count)).scalar() or 0
        
        # Get unique user agents count
        unique_user_agents = db.query(FingerprintRecord.user_agent).distinct().count()
        
        # Get recent fingerprints (last 10)
        recent_records = db.query(FingerprintRecord).order_by(
            FingerprintRecord.last_seen.desc()
        ).limit(10).all()
        
        recent_fingerprints = [
            {
                "fingerprint": record.fingerprint[:16] + "...",  # Truncate for display
                "visit_count": record.visit_count,
                "platform": record.traits.get("platform", "Unknown") if record.traits else "Unknown",
                "last_seen": record.last_seen.isoformat(),
                "is_recent": (datetime.utcnow() - record.last_seen).days < 1
            }
            for record in recent_records
        ]
        
        return FingerprintStats(
            total_fingerprints=total_fingerprints,
            total_visits=total_visits,
            unique_user_agents=unique_user_agents,
            recent_fingerprints=recent_fingerprints
        )
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get statistics")

@app.get("/fingerprints")
async def get_all_fingerprints(limit: int = 50, offset: int = 0, db: Session = Depends(get_db)):
    """
    Get all stored fingerprints with pagination
    """
    try:
        fingerprints = db.query(FingerprintRecord).order_by(
            FingerprintRecord.last_seen.desc()
        ).offset(offset).limit(limit).all()
        
        return {
            "fingerprints": [
                {
                    "id": fp.id,
                    "fingerprint": fp.fingerprint,
                    "visit_count": fp.visit_count,
                    "user_agent": fp.user_agent,
                    "platform": fp.traits.get("platform") if fp.traits else None,
                    "screen_resolution": f"{fp.traits.get('screen', {}).get('width', '?')}x{fp.traits.get('screen', {}).get('height', '?')}" if fp.traits else None,
                    "created_at": fp.created_at.isoformat(),
                    "last_seen": fp.last_seen.isoformat()
                }
                for fp in fingerprints
            ],
            "total": db.query(FingerprintRecord).count()
        }
        
    except Exception as e:
        logger.error(f"Error getting fingerprints: {e}")
        raise HTTPException(status_code=500, detail="Failed to get fingerprints")

@app.get("/fingerprint/{fingerprint_hash}")
async def get_fingerprint_details(fingerprint_hash: str, db: Session = Depends(get_db)):
    """
    Get detailed information about a specific fingerprint
    """
    try:
        record = db.query(FingerprintRecord).filter(
            FingerprintRecord.fingerprint == fingerprint_hash
        ).first()
        
        if not record:
            raise HTTPException(status_code=404, detail="Fingerprint not found")
        
        return {
            "fingerprint": record.fingerprint,
            "traits": record.traits,
            "visit_count": record.visit_count,
            "user_agent": record.user_agent,
            "created_at": record.created_at.isoformat(),
            "last_seen": record.last_seen.isoformat(),
            "days_since_first_seen": (datetime.utcnow() - record.created_at).days
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting fingerprint details: {e}")
        raise HTTPException(status_code=500, detail="Failed to get fingerprint details")

@app.delete("/fingerprint/{fingerprint_hash}")
async def delete_fingerprint(fingerprint_hash: str, db: Session = Depends(get_db)):
    """
    Delete a specific fingerprint record
    """
    try:
        record = db.query(FingerprintRecord).filter(
            FingerprintRecord.fingerprint == fingerprint_hash
        ).first()
        
        if not record:
            raise HTTPException(status_code=404, detail="Fingerprint not found")
        
        db.delete(record)
        db.commit()
        
        logger.info(f"Deleted fingerprint: {fingerprint_hash}")
        return {"message": "Fingerprint deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting fingerprint: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete fingerprint")

@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint with database connectivity test
    """
    try:
        # Test database connectivity
        db.execute("SELECT 1")
        db_status = "connected"
    except Exception as e:
        logger.error(f"Database connectivity error: {e}")
        db_status = "error"
    
    return {
        "status": "healthy",
        "database": db_status,
        "salt_configured": FP_SALT != "dev-only-salt-change-me",
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
