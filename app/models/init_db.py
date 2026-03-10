from app.models.base import Base
from app.models.db import engine

# Explicitly import model modules so they are registered on Base.metadata.
# This is required for SQLAlchemy to know about all tables prior to create_all().
import app.models.user  # noqa: F401
import app.models.device  # noqa: F401
import app.models.threat_event  # noqa: F401
import app.models.anti_theft  # noqa: F401


def create_all_tables():
    # Create all tables in the metadata in the proper order.
    Base.metadata.create_all(bind=engine)
