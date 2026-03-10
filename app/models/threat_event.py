from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, JSON
from app.models.base import Base
import datetime

class ThreatEvent(Base):
    __tablename__ = 'threat_events'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    device_id = Column(Integer, ForeignKey('devices.id'))
    event_type = Column(String, nullable=False)  # malware, phishing, etc.
    details = Column(JSON, nullable=True)
    detected_at = Column(DateTime, default=datetime.datetime.utcnow)
    resolved = Column(Boolean, default=False)
