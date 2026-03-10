from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.deps import get_current_user
from app.models.db import SessionLocal
from app.models.device import Device
from app.models.anti_theft import AntiTheftCommand
from sqlalchemy.orm import Session
import datetime

router = APIRouter(prefix="/antitheft", tags=["antitheft"])

class LocationUpdateRequest(BaseModel):
    device_id: str
    latitude: float
    longitude: float
    timestamp: float = None

class DeviceCommandRequest(BaseModel):
    device_id: str


@router.post("/location")
def update_location(data: LocationUpdateRequest, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    device = db.query(Device).filter(Device.device_id == data.device_id, Device.user_id == current_user["sub"]).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.last_location = {
        "lat": data.latitude,
        "lon": data.longitude,
        "timestamp": data.timestamp or datetime.datetime.utcnow().timestamp(),
    }
    db.commit()
    return {"status": "location updated", "device_id": data.device_id}


@router.post("/lock")
def remote_lock(data: DeviceCommandRequest, current_user=Depends(get_current_user)):
    return _create_command(db=None, current_user=current_user, device_id=data.device_id, command_type="lock")


@router.post("/alarm")
def remote_alarm(data: DeviceCommandRequest, current_user=Depends(get_current_user)):
    return _create_command(db=None, current_user=current_user, device_id=data.device_id, command_type="alarm")


@router.post("/wipe")
def remote_wipe(data: DeviceCommandRequest, current_user=Depends(get_current_user)):
    return _create_command(db=None, current_user=current_user, device_id=data.device_id, command_type="wipe")


@router.get("/commands")
def get_pending_commands(device_id: str, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    device = db.query(Device).filter(Device.device_id == device_id, Device.user_id == current_user["sub"]).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    commands = (
        db.query(AntiTheftCommand)
        .filter(AntiTheftCommand.device_id == device.id, AntiTheftCommand.status == "pending")
        .all()
    )
    return {"commands": [
        {
            "id": c.id,
            "type": c.command_type,
            "payload": c.payload,
            "created_at": c.created_at.isoformat(),
        }
        for c in commands
    ]}


def _create_command(db: Session, current_user, device_id: str, command_type: str):
    if db is None:
        db = SessionLocal()

    device = db.query(Device).filter(Device.device_id == device_id, Device.user_id == current_user["sub"]).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    command = AntiTheftCommand(
        user_id=current_user["sub"],
        device_id=device.id,
        command_type=command_type,
        payload={},
    )
    db.add(command)
    db.commit()
    db.refresh(command)

    return {"status": "queued", "command_id": command.id, "type": command_type}


@router.post("/commands/execute")
def mark_command_executed(command_id: int, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    command = db.query(AntiTheftCommand).filter(AntiTheftCommand.id == command_id).first()
    if not command:
        raise HTTPException(status_code=404, detail="Command not found")

    # Only user can mark their own commands as executed
    if command.user_id != current_user["sub"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    command.status = "executed"
    command.executed_at = datetime.datetime.utcnow()
    db.commit()
    return {"status": "executed", "command_id": command_id}
