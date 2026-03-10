from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.deps import get_current_user
from app.services.notification_service import send_alert, get_alerts, mark_alert_read

router = APIRouter(prefix="/notifications", tags=["notifications"])

class SendNotificationRequest(BaseModel):
    user_id: int
    message: str
    metadata: dict = {}
    severity: str = "info"


class MarkReadRequest(BaseModel):
    alert_id: str


@router.post("/send")
def send_notification(data: SendNotificationRequest, current_user=Depends(get_current_user)):
    # Only system users can send notifications to other users in production.
    alert = send_alert(data.user_id, data.message, data.metadata, severity=data.severity)
    return {"status": "sent", "alert": alert}


@router.get("")
def list_notifications(current_user=Depends(get_current_user), unread: bool = False, limit: int = 50):
    user_id = current_user.get("sub")
    alerts = get_alerts(user_id, only_unread=unread, limit=limit)
    return {"alerts": alerts}


@router.post("/read")
def mark_notification_read(data: MarkReadRequest, current_user=Depends(get_current_user)):
    user_id = current_user.get("sub")
    success = mark_alert_read(user_id, data.alert_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to mark notification read")
    return {"status": "marked_read", "alert_id": data.alert_id}
