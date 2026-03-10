from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.routers import (
    auth, malware, phishing, device, antitheft, notifications, settings, realtime, threats, admin
)
from app.ai.background_monitor import monitor_service
from app.models.init_db import create_all_tables

app = FastAPI(title="TraceX Guard Backend")

# Static + templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Register routers
app.include_router(auth.router)
app.include_router(malware.router)
app.include_router(phishing.router)
app.include_router(device.router)
app.include_router(antitheft.router)
app.include_router(notifications.router)
app.include_router(settings.router)
app.include_router(realtime.router)
app.include_router(threats.router)
app.include_router(admin.router)


@app.on_event("startup")
def startup_event():
    # Ensure the database schema exists (useful for SQLite/dev mode)
    create_all_tables()

    # Start background monitoring service
    monitor_service.start()


@app.on_event("shutdown")
def shutdown_event():
    monitor_service.stop()


@app.get("/")
def root():
    return {"status": "TraceX Guard backend running"}
