from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from app.models.base import Base
import datetime

class AntiTheftCommand(Base):
    __tablename__ = 'anti_theft_commands'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    device_id = Column(Integer, ForeignKey('devices.id'))
    command_type = Column(String, nullable=False)  # lock, alarm, wipe, etc.
    payload = Column(JSON, nullable=True)
    status = Column(String, default='pending')  # pending, executed, failed
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    executed_at = Column(DateTime, nullable=True)
