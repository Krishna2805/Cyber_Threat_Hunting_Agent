from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from backend.db import init_db
from backend.logger import log_event


# ---------------------------------------------------------------------------
# Lifespan – runs init_db() once when the server starts
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()          # ensure schema exists before the first request
    yield              # app is running
    # (shutdown logic, if any, goes here)


app = FastAPI(lifespan=lifespan)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "Cyber Threat Detection Victim API Running"}


@app.post("/login")
async def login(request: Request):

    try:
        data = await request.json()
        username = data.get("username", "unknown")
    except:
        username = "unknown"

    ip = request.client.host

    log_event(
        event_type="login_attempt",
        method="POST",
        endpoint="/login",
        username=username,
        ip=ip,
        status_code=401,
        status="fail"
    )

    return {"message": "Invalid credentials"}


@app.get("/admin")
async def admin(request: Request):

    ip = request.client.host

    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/admin",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked"
    )

    return {"message": "Admin access denied"}


@app.get("/config")
async def config(request: Request):

    ip = request.client.host

    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/config",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked"
    )

    return {"message": "Forbidden"}


@app.get("/internal")
async def internal(request: Request):

    ip = request.client.host

    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/internal",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked"
    )

    return {"message": "Forbidden"}