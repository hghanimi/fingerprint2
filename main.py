"""
Mini Fingerprint FastAPI Backend
Collects browser traits and generates SHA-256 fingerprints with salt
"""
import os
import json
import hashlib
import logging
from typing import Any, Dict

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="Mini Fingerprint", version="1.0.0")

# Get salt from environment variable or use dev default
FP_SALT = os.getenv("FP_SALT", "dev-only-salt-change-me")
if FP_SALT == "dev-only-salt-change-me":
    logger.warning("Using default salt! Set FP_SALT environment variable in production.")


class TraitsInput(BaseModel):
    """Pydantic model for incoming traits data"""
    data: Dict[str, Any]


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


@app.get("/")
async def serve_frontend():
    """Serve the index.html frontend"""
    return FileResponse("index.html")


@app.post("/fp")
async def generate_fingerprint(traits: TraitsInput):
    """
    Generate fingerprint from browser traits
    
    1. Normalize traits to stable JSON format
    2. Prepend with salt
    3. Generate SHA-256 hash
    4. Return hex fingerprint
    """
    try:
        # Normalize traits to stable JSON string
        normalized_traits = stable_json_dumps(traits.data)
        logger.info(f"Normalized traits: {normalized_traits}")
        
        # Prepend salt and generate hash
        salted_data = FP_SALT + normalized_traits
        fingerprint = sha256_hex(salted_data)
        
        logger.info(f"Generated fingerprint: {fingerprint}")
        
        return {"fp": fingerprint}
        
    except Exception as e:
        logger.error(f"Error generating fingerprint: {e}")
        return {"error": "Failed to generate fingerprint"}


@app.get("/health")
async def health_check():
    """Simple health check endpoint"""
    return {"status": "healthy", "salt_configured": FP_SALT != "dev-only-salt-change-me"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)