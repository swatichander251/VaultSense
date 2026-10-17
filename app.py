import os
import json
import time
import hmac
import hashlib
import secrets
import threading
from collections import deque
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, ConfigDict
from core import Model

API_KEY = os.environ.get("VAULTSENSE_API_KEY", "")
AUDIT_KEY = os.environ.get("VAULTSENSE_AUDIT_KEY", "")
if len(API_KEY) < 32 or len(AUDIT_KEY) < 32:
    raise RuntimeError("Set separate VAULTSENSE_API_KEY and VAULTSENSE_AUDIT_KEY secrets of at least 32 characters")
app = FastAPI(title="VaultSense", version="0.1.0")
model = Model()
auth = HTTPBearer()
lock = threading.Lock()
audit = deque(maxlen=1000)
head = "0"*64

def authorize(credentials: HTTPAuthorizationCredentials = Depends(auth)):
    if not secrets.compare_digest(credentials.credentials, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid token")

class Transaction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount: float = Field(ge=0, le=100000000)
    hour: int = Field(ge=0, le=23)
    international: int = Field(ge=0, le=1)
    new_payee: int = Field(ge=0, le=1)
    velocity_10m: int = Field(ge=0, le=100000)

@app.get("/")
def index():
    return FileResponse("index.html")

@app.get("/health")
def health():
    return {"status":"ok", "model_version":model.data["version"], "confidential_computing_verified":False,
            "mode":"synthetic-only demo; no hardware attestation implemented"}

@app.post("/score", dependencies=[Depends(authorize)])
def score(t: Transaction):
    global head
    start = time.perf_counter()
    result = model.predict(t.model_dump())
    elapsed = (time.perf_counter()-start)*1000
    with lock:
        record = {"event_id": secrets.token_hex(12), "time_ns":time.time_ns(),
                  "model_version":model.data["version"], "flagged":result["flagged"], "previous_mac":head}
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        head = hmac.new(AUDIT_KEY.encode(), payload, hashlib.sha256).hexdigest()
        record["mac"] = head
        audit.append(record)
        event_id = record["event_id"]
    return {**result, "event_id":event_id, "inference_ms":round(elapsed,3),
            "confidential_computing_verified":False}

@app.get("/audit", dependencies=[Depends(authorize)])
def get_audit():
    with lock:
        return {"records":list(audit), "head":head,
                "limitations":"Volatile single-process HMAC chain; not immutable, not externally anchored, not proof of non-exposure. Contains alert metadata, not transaction features."}
