import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.deps import get_current_admin
from app.models.db import SessionLocal
from app.models.user import User
from app.models.device import Device
from app.models.threat_event import ThreatEvent
from sqlalchemy import func

router = APIRouter(prefix="/admin", tags=["admin"])

templates = Jinja2Templates(directory="app/templates")

@router.get("/", response_class=HTMLResponse)
def admin_dashboard(request: Request, current_user=Depends(get_current_admin)):
    db = SessionLocal()
    user_count = db.query(User).count()
    device_count = db.query(Device).count()
    threat_count = db.query(ThreatEvent).count()

    # threat breakdown
    threat_by_type = (
        db.query(ThreatEvent.event_type, func.count(ThreatEvent.id))
        .group_by(ThreatEvent.event_type)
        .all()
    )

    return templates.TemplateResponse(
        "admin_dashboard.html",
        {
            "request": request,
            "user_count": user_count,
            "device_count": device_count,
            "threat_count": threat_count,
            "threat_by_type": threat_by_type,
        },
    )

@router.get("/users")
def list_users(current_user=Depends(get_current_admin)):
    db = SessionLocal()
    users = db.query(User).all()
    return {
        "count": len(users),
        "users": [
            {"id": u.id, "username": u.username, "email": u.email, "is_admin": u.is_admin}
            for u in users
        ],
    }

@router.get("/devices")
def list_devices(current_user=Depends(get_current_admin)):
    db = SessionLocal()
    devices = db.query(Device).all()
    return {
        "count": len(devices),
        "devices": [
            {
                "id": d.id,
                "device_id": d.device_id,
                "user_id": d.user_id,
                "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                "last_location": d.last_location,
                "is_active": d.is_active,
            }
            for d in devices
        ],
    }

@router.get("/threats")
def list_threats(current_user=Depends(get_current_admin)):
    db = SessionLocal()
    events = db.query(ThreatEvent).order_by(ThreatEvent.detected_at.desc()).limit(200).all()
    return {
        "count": len(events),
        "threats": [
            {
                "id": e.id,
                "type": e.event_type,
                "user_id": e.user_id,
                "device_id": e.device_id,
                "details": e.details,
                "detected_at": e.detected_at.isoformat(),
                "resolved": e.resolved,
            }
            for e in events
        ],
    }


@router.get("/reports/threats")
def download_threat_report(format: str = "csv", current_user=Depends(get_current_admin)):
    """Generate a threat report for admins. Supports CSV and JSON."""
    db = SessionLocal()
    events = db.query(ThreatEvent).order_by(ThreatEvent.detected_at.desc()).all()

    if format.lower() == "json":
        return {
            "count": len(events),
            "threats": [
                {
                    "id": e.id,
                    "type": e.event_type,
                    "user_id": e.user_id,
                    "device_id": e.device_id,
                    "details": e.details,
                    "detected_at": e.detected_at.isoformat(),
                    "resolved": e.resolved,
                }
                for e in events
            ],
        }

    # default to CSV
    from fastapi.responses import StreamingResponse
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "type", "user_id", "device_id", "detected_at", "resolved", "details"])
    for e in events:
        writer.writerow([
            e.id,
            e.event_type,
            e.user_id,
            e.device_id,
            e.detected_at.isoformat(),
            e.resolved,
            json.dumps(e.details) if e.details else "",
        ])
    output.seek(0)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threat_report.csv"},
    )
