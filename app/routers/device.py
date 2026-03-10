from fastapi import APIRouter, Depends, HTTPException
from app.deps import get_current_user
from app.cache import cache_get, cache_set
from pydantic import BaseModel
from app.models.db import SessionLocal
from app.models.device import Device
from app.models.threat_event import ThreatEvent
from app.ai.threat_detection import detect_threat
from app.services.notification_service import send_alert
from sqlalchemy.orm import Session

router = APIRouter(prefix="/device", tags=["device"])

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

@router.post("/scan-device")
def scan_device(request: ScanDeviceRequest, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    device = db.query(Device).filter(Device.device_id == request.device_id, Device.user_id == current_user["sub"]).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Touch last_seen
    device.last_seen = device.last_seen
    db.commit()

    # Trigger a real-time scan via the threat engine
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
            details={"model": "tflite", "confidence": result.get("confidence"), "result": result},
        )
        db.add(event)
        db.commit()
        send_alert(current_user["sub"], f"Threat detected: {result.get('type')}", {"device_id": device.device_id, "result": result})

    return {"status": "scan completed", "device_id": request.device_id, "scan_type": request.scan_type, "result": result}

@router.get("/security-score")
def get_security_score(current_user=Depends(get_current_user)):
    cache_key = f"security_score:{current_user['sub']}"
    cached = cache_get(cache_key)

    db: Session = SessionLocal()
    unresolved = db.query(ThreatEvent).filter(ThreatEvent.user_id == current_user["sub"], ThreatEvent.resolved == False).count()
    score = max(0, 100 - unresolved * 10)

    if cached is not None:
        previous_score = int(cached)
        # Send alert if security score drops significantly
        if score + 10 <= previous_score:
            send_alert(
                current_user["sub"],
                "Security score dropped",
                {"old_score": previous_score, "new_score": score},
            )
        cache_set(cache_key, str(score), expire_seconds=60)
        return {"security_score": score, "cached": True}

    cache_set(cache_key, str(score), expire_seconds=60)
    return {"security_score": score, "cached": False}

@router.post("/report-threat")
def report_threat(request: ReportThreatRequest, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    device = db.query(Device).filter(Device.device_id == request.device_id, Device.user_id == current_user["sub"]).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    event = ThreatEvent(user_id=current_user["sub"], device_id=device.id, event_type=request.threat_type, details=request.details)
    db.add(event)
    db.commit()
    db.refresh(event)
    return {"status": "threat reported", "event_id": event.id, "device_id": request.device_id, "threat_type": request.threat_type}


@router.post("/telemetry")
def submit_telemetry(data: TelemetryUpdateRequest, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    device = db.query(Device).filter(Device.device_id == data.device_id, Device.user_id == current_user["sub"]).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # update fingerprint validation
    if device.fingerprint != data.fingerprint:
        raise HTTPException(status_code=401, detail="Device fingerprint mismatch")

    device.installed_apps = data.installed_apps
    device.network_activity = data.network_activity
    device.last_seen = device.last_seen
    db.commit()

    # Run threat detection immediately on incoming telemetry
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
            details={"confidence": result.get("confidence"), "result": result},
        )
        db.add(event)
        db.commit()
        send_alert(current_user["sub"], f"Threat detected: {result.get('type')}", {"device_id": device.device_id, "result": result})

    return {"status": "telemetry received", "device_id": device.device_id, "threat_result": result}

@router.get("/device-status")
def get_device_status(current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    device = db.query(Device).filter(Device.user_id == current_user["sub"]).order_by(Device.last_seen.desc()).first()
    if not device:
        raise HTTPException(status_code=404, detail="No device found")
    return {"device_status": "active" if device.is_active else "inactive", "last_seen": str(device.last_seen)}

@router.post("/lock-device")
def lock_device(current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    device = db.query(Device).filter(Device.user_id == current_user["sub"]).order_by(Device.last_seen.desc()).first()
    if not device:
        raise HTTPException(status_code=404, detail="No device found")
    device.is_active = False
    db.commit()
    return {"status": "device locked"}

@router.post("/trigger-alarm")
def trigger_alarm(current_user=Depends(get_current_user)):
    # In a real app, trigger a push notification or similar
    return {"status": "alarm triggered"}
