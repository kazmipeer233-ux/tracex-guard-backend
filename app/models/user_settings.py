from sqlalchemy import Column, Integer, Boolean, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class UserSettings(Base):
    __tablename__ = 'user_settings'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True)
    auto_scan = Column(Boolean, default=True)
    real_time_protection = Column(Boolean, default=True)
    permission_monitor = Column(Boolean, default=True)
    tracker_blocking = Column(Boolean, default=True)
    threat_alerts = Column(Boolean, default=True)
    security_reports = Column(Boolean, default=False)
    dark_mode = Column(Boolean, default=False)
    theme_color = Column(String, default='blue')
