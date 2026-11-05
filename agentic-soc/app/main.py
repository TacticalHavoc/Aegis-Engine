import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.api.alerts import router as alerts_router
from app.api.incidents import router as incidents_router

load_dotenv()

app = FastAPI(
    title="Agentic SOC - Investigation Platform",
    description="Autonomous Agentic Security Operations Center Investigation API",
    version="1.0.0",
)

app.include_router(alerts_router)
app.include_router(incidents_router)

DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint to verify API readiness."""
    return {"status": "healthy"}


@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
async def serve_dashboard():
    """Serve the interactive Multi-Agent SOC Incident Dashboard."""
    if os.path.exists(DASHBOARD_PATH):
        with open(DASHBOARD_PATH, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)
