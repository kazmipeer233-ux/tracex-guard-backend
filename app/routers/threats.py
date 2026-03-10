from fastapi import APIRouter, Depends, HTTPException
from typing import Optional
from app.deps import get_current_user
from app.models.db import SessionLocal
from app.models.threat_event import ThreatEvent
from sqlalchemy.orm import Session
from sqlalchemy import func

router = APIRouter(prefix="/threats", tags=["threats"])

@router.get("")
def list_threats(skip: int = 0, limit: int = 50, threat_type: Optional[str] = None, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    query = db.query(ThreatEvent).filter(ThreatEvent.user_id == current_user["sub"])
    if threat_type:
        query = query.filter(ThreatEvent.event_type == threat_type)
    events = query.order_by(ThreatEvent.detected_at.desc()).offset(skip).limit(limit).all()
    return {"count": len(events), "events": [
        {
            "id": e.id,
            "type": e.event_type,
            "details": e.details,
            "detected_at": e.detected_at.isoformat(),
            "resolved": e.resolved,
        }
        for e in events
    ]}

@router.get("/summary")
def summary(current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    total = db.query(ThreatEvent).filter(ThreatEvent.user_id == current_user["sub"]).count()
    unresolved = db.query(ThreatEvent).filter(ThreatEvent.user_id == current_user["sub"], ThreatEvent.resolved == False).count()
    by_type = (
        db.query(ThreatEvent.event_type, func.count(ThreatEvent.id))
        .filter(ThreatEvent.user_id == current_user["sub"])
        .group_by(ThreatEvent.event_type)
        .all()
    )
    return {"total": total, "unresolved": unresolved, "by_type": {t: c for t, c in by_type}}

@router.get("/{threat_id}")
def get_threat(threat_id: int, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    event = db.query(ThreatEvent).filter(ThreatEvent.id == threat_id, ThreatEvent.user_id == current_user["sub"]).first()
    if not event:
        raise HTTPException(status_code=404, detail="Threat event not found")
    return {
        "id": event.id,
        "type": event.event_type,
        "details": event.details,
        "detected_at": event.detected_at.isoformat(),
        "resolved": event.resolved,
    }
