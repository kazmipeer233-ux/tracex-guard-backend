from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.deps import get_current_user
from app.cache import cache_get, cache_set
from app.models.db import SessionLocal
from app.models.device import Device
from app.models.threat_event import ThreatEvent
from app.ai.threat_detection import detect_threat
from app.services.notification_service import send_alert

router = APIRouter(prefix="/device", tags=["device"])


# =========================
# Request Models
# =========================

class ScanDeviceRequest(BaseModel):
    device_id: str
    scan_type: str = "full"


class ReportThreatRequest(BaseModel):
    device_id: str
    threat_type: str
    details: dict = {}


class TelemetryUpdateRequest(BaseModel):
    device_id: str
    fingerprint: str
    installed_apps: list = []
    network_activity: list = []
    permissions: list = []
    behavior: dict = {}


# =========================
# Scan Device
# =========================

@router.post("/scan-device")
def scan_device(request: ScanDeviceRequest, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()

    device = db.query(Device).filter(
        Device.device_id == request.device_id,
        Device.user_id == current_user["sub"]
    ).first()

    if not device:
        db.close()
        raise HTTPException(status_code=404, detail="Device not found")

    features = {
        "permissions": device.installed_apps or [],
        "behavior": {},
        "network": device.network_activity or [],
        "signatures": [],
    }

    result = detect_threat(features)

    if result.get("threat"):
        event = ThreatEvent(
            user_id=current_user["sub"],
            device_id=device.id,
            event_type=result.get("type"),
            details=result
        )
        db.add(event)
        db.commit()

        send_alert(
            current_user["sub"],
            f"Threat detected: {result.get('type')}",
            {"device_id": device.device_id}
        )

    db.close()

    return {
        "status": "scan completed",
        "device_id": request.device_id,
        "scan_type": request.scan_type,
        "result": result
    }


# =========================
# Security Score
# =========================

@router.get("/security-score")
def get_security_score(current_user=Depends(get_current_user)):

    db: Session = SessionLocal()

    unresolved = db.query(ThreatEvent).filter(
        ThreatEvent.user_id == current_user["sub"],
        ThreatEvent.resolved == False
    ).count()

    score = max(0, 100 - unresolved * 10)

    db.close()

    return {
        "security_score": score,
        "status": "secure" if score > 70 else "warning"
    }


# =========================
# Report Threat
# =========================

@router.post("/report-threat")
def report_threat(request: ReportThreatRequest, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()

    device = db.query(Device).filter(
        Device.device_id == request.device_id,
        Device.user_id == current_user["sub"]
    ).first()

    if not device:
        db.close()
        raise HTTPException(status_code=404, detail="Device not found")

    event = ThreatEvent(
        user_id=current_user["sub"],
        device_id=device.id,
        event_type=request.threat_type,
        details=request.details
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    db.close()

    return {
        "status": "threat reported",
        "event_id": event.id
    }


# =========================
# Telemetry
# =========================

@router.post("/telemetry")
def submit_telemetry(data: TelemetryUpdateRequest, current_user=Depends(get_current_user)):

    db: Session = SessionLocal()

    device = db.query(Device).filter(
        Device.device_id == data.device_id,
        Device.user_id == current_user["sub"]
    ).first()

    if not device:
        db.close()
        raise HTTPException(status_code=404, detail="Device not found")

    if device.fingerprint != data.fingerprint:
        db.close()
        raise HTTPException(status_code=401, detail="Fingerprint mismatch")

    device.installed_apps = data.installed_apps
    device.network_activity = data.network_activity

    db.commit()

    features = {
        "permissions": data.permissions,
        "behavior": data.behavior,
        "network": data.network_activity,
        "signatures": [],
    }

    result = detect_threat(features)

    if result.get("threat"):
        event = ThreatEvent(
            user_id=current_user["sub"],
            device_id=device.id,
            event_type=result.get("type"),
            details=result
        )
        db.add(event)
        db.commit()

        send_alert(
            current_user["sub"],
            f"Threat detected: {result.get('type')}",
            {"device_id": device.device_id}
        )

    db.close()

    return {
        "status": "telemetry received",
        "threat_result": result
    }


# =========================
# Device Status
# =========================

@router.get("/device-status")
def get_device_status(current_user=Depends(get_current_user)):

    db: Session = SessionLocal()

    device = db.query(Device).filter(
        Device.user_id == current_user["sub"]
    ).order_by(Device.last_seen.desc()).first()

    if not device:
        db.close()
        raise HTTPException(status_code=404, detail="No device found")

    db.close()

    return {
        "device_status": "active" if device.is_active else "inactive",
        "last_seen": str(device.last_seen)
    }


# =========================
# Lock Device
# =========================

@router.post("/lock-device")
def lock_device(current_user=Depends(get_current_user)):

    db: Session = SessionLocal()

    device = db.query(Device).filter(
        Device.user_id == current_user["sub"]
    ).order_by(Device.last_seen.desc()).first()

    if not device:
        db.close()
        raise HTTPException(status_code=404, detail="No device found")

    device.is_active = False
    db.commit()

    db.close()

    return {"status": "device locked"}


# =========================
# Trigger Alarm
# =========================

@router.post("/trigger-alarm")
def trigger_alarm(current_user=Depends(get_current_user)):
    return {"status": "alarm triggered"}