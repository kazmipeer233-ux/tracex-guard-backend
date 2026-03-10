import threading
import time
from typing import Dict, Any

from app.models.db import SessionLocal
from app.models.device import Device
from app.models.threat_event import ThreatEvent
from app.ai.threat_detection import detect_threat
from app.services.notification_service import send_alert


class BackgroundMonitorService:
    def __init__(self, interval: int = 60):
        self.interval = interval  # seconds
        self.running = False
        self.thread = None

    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()

    def run(self):
        while self.running:
            self.scan_all_devices()
            time.sleep(self.interval)

    def scan_all_devices(self):
        db = SessionLocal()
        devices = db.query(Device).filter(Device.is_active == True).all()
        for device in devices:
            self.scan_device(device, db)
        db.close()

    def scan_device(self, device: Device, db):
        # Gather data for analysis
        features = self._build_feature_set(device)

        # AI threat detection
        result = detect_threat(features)
        if result.get("threat"):
            self._record_threat(db, device, result)
            self._alert_user(device.user_id, device.id, result)

    def _build_feature_set(self, device: Device) -> Dict[str, Any]:
        # In a real implementation, these would come from a mobile agent.
        return {
            "permissions": device.installed_apps or [],
            "behavior": {},
            "network": device.network_activity or [],
            "signatures": [],
            "url": None,
        }

    def _record_threat(self, db, device: Device, result: Dict[str, Any]):
        event = ThreatEvent(
            user_id=device.user_id,
            device_id=device.id,
            event_type=result.get("type", "suspicious_activity"),
            details={
                "model": "tflite" if result.get("confidence") else "fallback",
                "confidence": result.get("confidence"),
                "raw": result,
            },
        )
        db.add(event)
        db.commit()

    def _alert_user(self, user_id: int, device_id: int, result: Dict[str, Any]):
        message = f"Threat detected on device {device_id}: {result.get('type')} (confidence={result.get('confidence')})"
        send_alert(user_id, message, {"device_id": device_id, "result": result})


monitor_service = BackgroundMonitorService()
