"""
Main entrypoint for PhishGuard AI FastAPI Backend.
Integrates endpoints, mounts static directories, and serves the dashboard UI.
"""

import os
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request

from backend.core.config import settings
from backend.database.db import init_db
from backend.api.v1.endpoints import router as api_router

# Create database tables on launch
init_db()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="AI-Powered Email Security & Phishing Detector REST API",
    version="1.0.0"
)

# CORS middleware config
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production security scope
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
app.include_router(api_router, prefix=settings.API_V1_STR)

# Ensure static directories exist
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "css"), exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "js"), exist_ok=True)

# Templates setup
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
os.makedirs(TEMPLATES_DIR, exist_ok=True)
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Mount static files (CSS, JS, Assets)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
def read_root():
    """Serves the main application landing page and SPA dashboard."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    return HTMLResponse(
        content="<h2>PhishGuard AI Frontend index.html is still generating... Please refresh in a moment.</h2>",
        status_code=200
    )

@app.get("/admin", response_class=HTMLResponse)
def read_admin():
    """Serves the admin panel."""
    admin_path = os.path.join(TEMPLATES_DIR, "admin.html")
    if os.path.exists(admin_path):
        with open(admin_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    return HTMLResponse(
        content="<h2>PhishGuard AI Admin admin.html is generating...</h2>",
        status_code=200
    )

if __name__ == "__main__":
    import uvicorn
    # In production, run with uvicorn programmatically or via CLI
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
