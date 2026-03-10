from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, JSON
from app.models.base import Base
import datetime

class Device(Base):
    __tablename__ = 'devices'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    device_id = Column(String, unique=True, index=True, nullable=False)
    fingerprint = Column(String, nullable=False)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    is_active = Column(Boolean, default=True)
    installed_apps = Column(JSON, default=list)
    network_activity = Column(JSON, default=list)
    last_location = Column(JSON, nullable=True)  # {lat, lon, timestamp}
