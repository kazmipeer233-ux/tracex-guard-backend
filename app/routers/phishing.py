from fastapi import APIRouter, Depends
from app.deps import get_current_user
from app.ai.threat_detection import detect_threat
from app.services.notification_service import send_alert
from pydantic import BaseModel

router = APIRouter(prefix="/phishing", tags=["phishing"])

class PhishingDetectionRequest(BaseModel):
    url: str
    network: dict = {}
    behavior: dict = {}
    signatures: list = []

@router.post("/detect")
def detect_phishing(request: PhishingDetectionRequest, current_user=Depends(get_current_user)):
    features = {
        "permissions": [],
        "network": request.network,
        "behavior": request.behavior,
        "signatures": request.signatures,
        "url": request.url
    }
    result = detect_threat(features)
    if result.get("threat"):
        send_alert(
            current_user["sub"],
            f"Phishing detected: {request.url}",
            {"result": result, "type": "phishing_detection"},
        )
    return result
