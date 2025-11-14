from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import text
from sqlalchemy import inspect as sa_inspect

from .core.settings import settings

# Create engine for the configured database (MySQL recommended)
is_sqlite = settings.DATABASE_URL.startswith("sqlite")
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if is_sqlite else {},
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
    dialect = engine.dialect.name
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
        # BOOLEAN works across sqlite and others; sqlite stores as integer 0/1
        additions.append("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0")

    if not additions:
        return

    with engine.begin() as conn:
        for stmt in additions:
            conn.execute(text(stmt))
