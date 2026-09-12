import os
import sys
import asyncio

# On Windows, enforce ProactorEventLoopPolicy for subprocess support
if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        pass

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse

from routers.audit import router as audit_router
from routers.remediation import router as remediation_router

app = FastAPI(
    title="SentinelX Desktop Backend API",
    description="Automated Security Audit, Triage, and Blue Team Remediation Engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(audit_router)
app.include_router(remediation_router)

@app.get("/")
def serve_testing_page():
    frontend_html = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "src", "pages", "index.html"))
    if os.path.exists(frontend_html):
        return FileResponse(frontend_html)

    backend_html = os.path.abspath(os.path.join(os.path.dirname(__file__), "index.html"))
    if os.path.exists(backend_html):
        return FileResponse(backend_html)

    return RedirectResponse(url="/docs")

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "SentinelX Desktop Backend"}
