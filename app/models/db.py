from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_DB = os.getenv('POSTGRES_DB')
POSTGRES_HOST = os.getenv('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = os.getenv('POSTGRES_PORT', '5432')

# Default SQLite path (project root) for easy local development.
# We locate the project root by walking up from this file: app/models/db.py -> app/models -> app -> backend -> project root
PROJECT_ROOT = Path(__file__).resolve().parents[3]
SQLITE_PATH = PROJECT_ROOT / "tracex_guard.db"

# If Postgres env vars are provided, use Postgres, otherwise fall back to SQLite.
if POSTGRES_USER and POSTGRES_PASSWORD and POSTGRES_DB:
    DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
    engine = create_engine(DATABASE_URL)
else:
    DATABASE_URL = f"sqlite:///{SQLITE_PATH}"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
