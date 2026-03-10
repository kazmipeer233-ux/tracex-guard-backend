from fastapi import APIRouter, Depends, HTTPException
from app.deps import get_current_user
from app.models.db import SessionLocal
from app.models.user_settings import UserSettings
from pydantic import BaseModel
from sqlalchemy.orm import Session

router = APIRouter(prefix="/settings", tags=["settings"])

class SettingsUpdateRequest(BaseModel):
    auto_scan: bool = True
    real_time_protection: bool = True
    permission_monitor: bool = True
    tracker_blocking: bool = True
    threat_alerts: bool = True
    security_reports: bool = False
    dark_mode: bool = False
    theme_color: str = "blue"

@router.get("/")
def get_settings(current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    settings = db.query(UserSettings).filter(UserSettings.user_id == current_user["sub"]).first()
    if not settings:
        # Return defaults if not set
        return SettingsUpdateRequest().dict()
    return {
        "auto_scan": settings.auto_scan,
        "real_time_protection": settings.real_time_protection,
        "permission_monitor": settings.permission_monitor,
        "tracker_blocking": settings.tracker_blocking,
        "threat_alerts": settings.threat_alerts,
        "security_reports": settings.security_reports,
        "dark_mode": settings.dark_mode,
        "theme_color": settings.theme_color
    }

@router.post("/")
def update_settings(settings: SettingsUpdateRequest, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    user_id = current_user["sub"]
    user_settings = db.query(UserSettings).filter(UserSettings.user_id == user_id).first()
    if not user_settings:
        user_settings = UserSettings(user_id=user_id, **settings.dict())
        db.add(user_settings)
    else:
        for k, v in settings.dict().items():
            setattr(user_settings, k, v)
    db.commit()
    db.refresh(user_settings)
    return settings.dict()
