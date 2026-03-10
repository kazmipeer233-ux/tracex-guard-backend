from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.models.base import Base
import datetime

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    device_fingerprint = Column(String, nullable=True)
    public_key = Column(String, nullable=True)  # For end-to-end encrypted payloads
    is_admin = Column(Boolean, default=False)
