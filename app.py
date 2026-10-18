import os
import re
import json
import time
import hmac
import hashlib
import secrets
import threading
from collections import deque
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, ConfigDict

from typing import List, Literal, Optional

import guard
import chatbot
from core import Model, BASE_DIR, FEATURES
from supa import Supabase, SupabaseError

# ---------------------------------------------------------------- settings
API_KEY = os.environ.get("VAULTSENSE_API_KEY", "")
AUDIT_KEY = os.environ.get("VAULTSENSE_AUDIT_KEY", "")
if len(API_KEY) < 32 or len(AUDIT_KEY) < 32:
    raise RuntimeError("Set separate VAULTSENSE_API_KEY and VAULTSENSE_AUDIT_KEY secrets of at least 32 characters")

# Supabase login (optional). When both are set, a signed-in Supabase user's
# access token is accepted on /score, so the frontend never holds the API key.
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")  # anon / publishable key, NOT service_role
SUPABASE_ENABLED = bool(SUPABASE_URL and SUPABASE_ANON_KEY)

# CORS: which websites may call this API from a browser.
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
ALLOWED_ORIGIN_REGEX = os.environ.get(
    "ALLOWED_ORIGIN_REGEX",
    r"https://([a-z0-9-]+\.)*(lovable\.app|lovableproject\.com|lovable\.dev)",
)

# ---------------------------------------------------------------- app state
model = Model()
bearer = HTTPBearer(auto_error=False)
lock = threading.Lock()
audit = deque(maxlen=1000)
head = "0" * 64
_token_cache = {}  # sha256(token) -> (user_id, expires_at)
TOKEN_CACHE_SECONDS = 60
sessions = guard.SessionTracker()
ALLOWED_LINK_DOMAINS = [d.strip() for d in os.environ.get("ALLOWED_LINK_DOMAINS", "").split(",") if d.strip()]
CHATBOT_AUTO_LIMIT = float(os.environ.get("CHATBOT_AUTO_LIMIT", "1000"))


DEMO_ALLOW_GUARD_OFF = os.environ.get("DEMO_ALLOW_GUARD_OFF", "false").lower() == "true"


@asynccontextmanager
async def lifespan(app):
    app.state.http = httpx.AsyncClient(timeout=10.0)
    app.state.supa = Supabase(app.state.http)
    app.state.bot = chatbot.ChatBot(chatbot.make_llm(app.state.http), app.state.supa, sessions, model, _audit,
                                    auto_limit=CHATBOT_AUTO_LIMIT, link_domains=ALLOWED_LINK_DOMAINS)
    yield
    await app.state.http.aclose()


app = FastAPI(title="VaultSense", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX or None,
    allow_credentials=False,  # we use Authorization headers, not cookies
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # Don't echo submitted values back (they could be sensitive); just say which fields are wrong.
    fields = sorted({".".join(str(p) for p in e.get("loc", [])[1:]) or "body" for e in exc.errors()})
    return JSONResponse(status_code=422, content={"detail": "Invalid request", "invalid_fields": fields})


# ---------------------------------------------------------------- auth
async def _verify_supabase_token(request: Request, token: str):
    """Ask Supabase Auth who owns this access token. Returns user id or None."""
    key = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    cached = _token_cache.get(key)
    if cached and cached[1] > now:
        return cached[0]
    try:
        r = await request.app.state.http.get(
            f"{SUPABASE_URL}/auth/v1/user",
            headers={"apikey": SUPABASE_ANON_KEY, "Authorization": f"Bearer {token}"},
        )
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Could not reach Supabase to verify login")
    if r.status_code != 200:
        return None
    user_id = r.json().get("id")
    if not user_id:
        return None
    if len(_token_cache) > 5000:
        _token_cache.clear()
    _token_cache[key] = (user_id, now + TOKEN_CACHE_SECONDS)
    return user_id


async def authorize(request: Request, credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    """Accept either the server API key (curl / demo page / server-to-server)
    or a logged-in Supabase user's access token (Lovable frontend)."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = credentials.credentials
    if secrets.compare_digest(token.encode(), API_KEY.encode()):
        return {"kind": "api_key", "user_id": None, "token": None}
    if SUPABASE_ENABLED:
        user_id = await _verify_supabase_token(request, token)
        if user_id:
            return {"kind": "supabase_user", "user_id": user_id, "token": token}
    raise HTTPException(status_code=401, detail="Invalid or expired token")


async def authorize_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    """Audit log is admin-only: API key required, Supabase users can't read it."""
    if credentials is None or not secrets.compare_digest(credentials.credentials.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="Admin API key required")


# ---------------------------------------------------------------- schema
class Transaction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount: float = Field(ge=0, le=100000000)
    hour: int = Field(ge=0, le=23)
    international: int = Field(ge=0, le=1)
    new_payee: int = Field(ge=0, le=1)
    velocity_10m: int = Field(ge=0, le=100000)


def _audit(event_type, caller, **fields):
    """Append metadata (never message text or transaction values) to the HMAC chain."""
    global head
    with lock:
        record = {"event_id": secrets.token_hex(12), "time_ns": time.time_ns(), "type": event_type,
                  "caller": caller["kind"], **fields, "previous_mac": head}
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        head = hmac.new(AUDIT_KEY.encode(), payload, hashlib.sha256).hexdigest()
        record["mac"] = head
        audit.append(record)
        return record["event_id"]


def _session_key(caller, session_id):
    # Namespaced by user so one customer can't lock or read another's session.
    return f"{caller['user_id'] or 'server'}:{session_id}"


class GuardInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=1, max_length=128)
    text: str = Field(max_length=20000)
    source: Literal["user", "retrieved"] = "user"


class GuardOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=1, max_length=128)
    text: str = Field(max_length=50000)
    canary: Optional[str] = Field(default=None, max_length=200)
    protected_phrases: List[str] = Field(default_factory=list, max_length=50)


class GuardAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=64)
    amount: float = Field(default=0, ge=0, le=100000000)
    initiated_by: Literal["user", "model", "retrieved"] = "user"
    user_confirmed_out_of_band: bool = False
    last_input_decision: Literal["allow", "review", "block"] = "allow"
    transaction: Optional[Transaction] = None  # if given, the fraud model also scores it


class SessionRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=1, max_length=128)


# ---------------------------------------------------------------- routes
@app.get("/")
def index():
    return FileResponse(BASE_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "model_version": model.data["version"],
            "supabase_auth_enabled": SUPABASE_ENABLED,
            "guard_version": guard.GUARD_VERSION,
            "confidential_computing_verified": False,
            "mode": "synthetic-only demo; no hardware attestation implemented"}


@app.post("/score")
def score(t: Transaction, caller: dict = Depends(authorize)):
    start = time.perf_counter()
    result = model.predict(t.model_dump())
    elapsed = (time.perf_counter() - start) * 1000
    event_id = _audit("fraud_score", caller, model_version=model.data["version"], flagged=result["flagged"])
    return {**result, "event_id": event_id, "model_version": model.data["version"],
            "inference_ms": round(elapsed, 3), "confidential_computing_verified": False}


@app.get("/audit", dependencies=[Depends(authorize_admin)])
def get_audit():
    with lock:
        return {"records": list(audit), "head": head,
                "limitations": "Volatile single-process HMAC chain; not immutable, not externally anchored, not proof of non-exposure. Contains alert metadata, not transaction features."}


# ---------------------------------------------------------------- chatbot guard
async def _supa_log(request, caller, key, layer, source, decision, risk, rules, event_id):
    await request.app.state.supa.log_guard_event({
        "user_id": caller.get("user_id"), "session_hash": hashlib.sha256(key.encode()).hexdigest()[:16],
        "layer": layer, "source": source, "decision": decision, "risk_score": risk,
        "rules": list(rules), "event_id": event_id})


@app.post("/guard/input")
async def guard_input(req: GuardInput, request: Request, caller: dict = Depends(authorize)):
    """Screen a customer message (source=user) or a document/web/email/tool result that is
    about to go into the chatbot's context (source=retrieved)."""
    key = _session_key(caller, req.session_id)
    result = guard.screen_input(req.text, req.source)
    session = None
    if req.source == "user":
        session = sessions.record(key, req.text, result["decision"])
        if session["locked"]:
            result["decision"] = "block"
            result["findings"].insert(0, {"rule": "session_locked", "weight": 1.0,
                                          "why": "too many attack attempts in this session; hand off to a human"})
    event_id = _audit("guard_input", caller, source=req.source, decision=result["decision"],
                      risk=result["risk_score"], rules=[f["rule"] for f in result["findings"]],
                      session_signals=(session or {}).get("signals", []))
    await _supa_log(request, caller, key, "input", req.source, result["decision"], result["risk_score"],
                    [f["rule"] for f in result["findings"]], event_id)
    return {**result, "session": session, "event_id": event_id}


@app.post("/guard/output")
async def guard_output(req: GuardOutput, request: Request, caller: dict = Depends(authorize)):
    """Screen the chatbot's reply before the customer sees it."""
    result = guard.screen_output(req.text, canary=req.canary, protected_phrases=req.protected_phrases,
                                 allowed_link_domains=ALLOWED_LINK_DOMAINS)
    event_id = _audit("guard_output", caller, decision=result["decision"],
                      rules=[f["rule"] for f in result["findings"]])
    await _supa_log(request, caller, _session_key(caller, req.session_id), "output", "model", result["decision"],
                    None, [f["rule"] for f in result["findings"]], event_id)
    return {**result, "event_id": event_id}


@app.post("/guard/action")
async def guard_action(req: GuardAction, request: Request, caller: dict = Depends(authorize)):
    """Policy gate: call this BEFORE the chatbot executes any tool/action."""
    fraud = None
    if req.transaction is not None:
        fraud = model.predict(req.transaction.model_dump())
    result = guard.check_action(
        req.action, amount=req.amount, user_confirmed_out_of_band=req.user_confirmed_out_of_band,
        initiated_by=req.initiated_by, session_state=sessions.state(_session_key(caller, req.session_id)),
        last_input_decision=req.last_input_decision, auto_limit=CHATBOT_AUTO_LIMIT,
        fraud_flagged=bool(fraud and fraud["flagged"]))
    event_id = _audit("guard_action", caller, action=req.action, decision=result["decision"],
                      initiated_by=req.initiated_by, fraud_flagged=bool(fraud and fraud["flagged"]))
    await _supa_log(request, caller, _session_key(caller, req.session_id), "action", req.initiated_by,
                    result["decision"], fraud and fraud["fraud_score"], [req.action], event_id)
    return {**result, "fraud": fraud, "event_id": event_id}


@app.post("/guard/unlock", dependencies=[Depends(authorize_admin)])
def guard_unlock(req: SessionRef, user_id: Optional[str] = None):
    """Admin: unlock a session after a human has reviewed it."""
    sessions.unlock(f"{user_id or 'server'}:{req.session_id}")
    _audit("guard_unlock", {"kind": "api_key"}, session_hash=hashlib.sha256(req.session_id.encode()).hexdigest()[:16])
    return {"unlocked": True}


# ---------------------------------------------------------------- demo chatbot
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=4000)
    guard_enabled: bool = True


class ConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str = Field(min_length=1, max_length=128)
    pending_id: str = Field(min_length=1, max_length=64)


@app.post("/chat")
async def chat(req: ChatRequest, request: Request, caller: dict = Depends(authorize)):
    """Demo bank chatbot. Every message, document, tool call and reply goes through the guard."""
    if not req.guard_enabled:
        # Turning the guard off is only for showing the attack succeeding, on synthetic demo data.
        if not DEMO_ALLOW_GUARD_OFF or caller["kind"] == "supabase_user":
            raise HTTPException(status_code=403, detail="Guard can only be disabled in demo mode on synthetic data")
    return await request.app.state.bot.handle(caller, req.session_id, req.message, caller.get("token"), req.guard_enabled)


@app.post("/chat/confirm")
async def chat_confirm(req: ConfirmRequest, request: Request, caller: dict = Depends(authorize)):
    """The app's Confirm button. The LLM has no way to call this."""
    return await request.app.state.bot.confirm(caller, req.session_id, req.pending_id, caller.get("token"))


@app.post("/transactions/{transaction_id}/score")
async def score_saved_transaction(transaction_id: str, request: Request, caller: dict = Depends(authorize)):
    """Score a transaction row the customer saved in Supabase, and write the result with the
    service role so customers can't edit their own fraud score."""
    if caller["kind"] != "supabase_user":
        raise HTTPException(status_code=400, detail="Requires a signed-in Supabase user")
    supa = request.app.state.supa
    if not supa.can_write:
        raise HTTPException(status_code=503, detail="Server is missing SUPABASE_SERVICE_ROLE_KEY")
    if not UUID_RE.fullmatch(transaction_id):
        raise HTTPException(status_code=400, detail="Invalid id")
    try:
        rows = await supa.select("transactions", {"select": "id,amount,created_at,international,new_payee",
                                                  "id": f"eq.{transaction_id}"}, caller["token"])
        if not rows:  # RLS hides other people's rows, so this also covers "not yours"
            raise HTTPException(status_code=404, detail="Transaction not found")
        t = rows[0]
        created = chatbot.datetime.fromisoformat(t["created_at"].replace("Z", "+00:00"))
        since = (created - chatbot.timedelta(minutes=10)).isoformat()
        earlier = await supa.select("transactions", {"select": "id", "and": f"(created_at.gte.{since},created_at.lt.{t['created_at']})"},
                                    caller["token"])
        hour = created.astimezone(chatbot.ZoneInfo(chatbot.BANK_TZ)).hour if chatbot.ZoneInfo else created.hour
        features = {"amount": float(t["amount"]), "hour": hour, "international": int(bool(t.get("international"))),
                    "new_payee": int(bool(t.get("new_payee"))), "velocity_10m": len(earlier)}
        result = model.predict(features)
        event_id = _audit("fraud_score", caller, model_version=model.data["version"], flagged=result["flagged"])
        await supa.update_service("transactions", {"id": transaction_id, "user_id": caller["user_id"]},
                                  {"fraud_score": result["fraud_score"], "flagged": result["flagged"],
                                   "explanations": result["explanations"], "event_id": event_id,
                                   "model_version": model.data["version"]})
    except SupabaseError:
        raise HTTPException(status_code=502, detail="Supabase request failed")
    return {**result, "event_id": event_id, "features_used": features}


# ---------------------------------------------------------------- model & research results (for the website)
RESULT_FILES = {"tabformer_live_model": "evaluation.json", "ulb": "results/ulb.json", "paysim": "results/paysim.json",
                "baf_fairness": "results/baf.json", "simulated_banks": "results/federated.json"}


@app.get("/model")
def model_info(caller: dict = Depends(authorize)):
    """Which data the live model was trained on and how well it did (no customer data)."""
    keep = ("version", "trained_on", "trained_at", "split", "threshold", "high_threshold", "test_summary", "threshold_note")
    return {**{k: model.data[k] for k in keep if k in model.data}, "features": list(FEATURES)}


@app.get("/results")
def research_results(caller: dict = Depends(authorize)):
    """Benchmark, fairness and simulated-bank results produced by train.py, benchmarks.py and federated.py."""
    out = {}
    for name, rel in RESULT_FILES.items():
        path = BASE_DIR / rel
        if path.exists():
            try:
                out[name] = json.loads(path.read_text())
            except ValueError:
                out[name] = {"error": "unreadable"}
    return out
