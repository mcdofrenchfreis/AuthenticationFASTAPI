from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import text
from sqlalchemy import inspect as sa_inspect

from .core.settings import settings

if not settings.DATABASE_URL.startswith("postgresql"):
    raise ValueError("Only PostgreSQL is supported. Set DATABASE_URL to a postgresql+psycopg2:// URL.")

# Create engine for the configured PostgreSQL database
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def run_migrations():
    """Lightweight migrations: add new user columns if missing (DB-agnostic)."""
    insp = sa_inspect(engine)
    try:
        columns = {col['name'] for col in insp.get_columns('users')}
    except Exception:
        # Table may not exist yet; skip
        return

    additions = []
    # Use a generic VARCHAR(255) for new columns
    if "first_name" not in columns:
        additions.append("ALTER TABLE users ADD COLUMN first_name VARCHAR(255)")
    if "middle_name" not in columns:
        additions.append("ALTER TABLE users ADD COLUMN middle_name VARCHAR(255)")
    if "last_name" not in columns:
        additions.append("ALTER TABLE users ADD COLUMN last_name VARCHAR(255)")
    if "mobile" not in columns:
        additions.append("ALTER TABLE users ADD COLUMN mobile VARCHAR(255)")
    if "is_verified" not in columns:
        additions.append("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE")
    if "mfa_enabled" not in columns:
        additions.append("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE")
    if "mfa_secret" not in columns:
        additions.append("ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(255)")

    if not additions:
        return

    with engine.begin() as conn:
        for stmt in additions:
            conn.execute(text(stmt))
