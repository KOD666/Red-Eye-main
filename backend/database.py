import os
from dotenv import load_dotenv
load_dotenv()
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database configuration string - typical for PostgreSQL containers or localhost
DATABASE_URL = os.environ.get("DATABASE_URL")

try:
    if DATABASE_URL.startswith("sqlite"):
        engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    else:
        engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20, pool_pre_ping=True)
        # Test connection immediately
        with engine.connect() as conn:
            pass
except Exception as e:
    print(f"\033[1;31m[!] PostgreSQL connection failed ({e}). Falling back to local SQLite database (test.db)...\033[0m")
    DATABASE_URL = "sqlite:///./test.db"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """FastAPI dependency to inject database sessions safely into request life-cycles."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
