from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.config import DATABASE_URL

is_sqlite = DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from backend import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_v11_columns()


def _ensure_sqlite_v11_columns() -> None:
    if not is_sqlite:
        return
    additions = {
        "users": [
            ("organization_id", "INTEGER"),
            ("status", "VARCHAR(24) DEFAULT 'ACTIVE' NOT NULL"),
            ("updated_at", "DATETIME"),
            ("last_login", "DATETIME"),
            ("last_seen", "DATETIME"),
        ],
        "devices": [
            ("organization_id", "INTEGER"),
            ("device_name", "VARCHAR(120)"),
            ("hostname", "VARCHAR(120)"),
            ("platform", "VARCHAR(64)"),
            ("platform_version", "VARCHAR(120)"),
            ("agent_version", "VARCHAR(40)"),
            ("device_fingerprint", "VARCHAR(128)"),
            ("status", "VARCHAR(24) DEFAULT 'ONLINE' NOT NULL"),
            ("posture_status", "VARCHAR(24) DEFAULT 'HEALTHY' NOT NULL"),
            ("registered_at", "DATETIME"),
            ("ip_context", "JSON"),
            ("location_context", "JSON"),
            ("credential_hash", "VARCHAR(64)"),
            ("credential_issued_at", "DATETIME"),
        ],
        "applications": [("organization_id", "INTEGER"), ("upstream_host", "VARCHAR(255)")],
        "security_events": [
            ("organization_id", "INTEGER"),
            ("source", "VARCHAR(32) DEFAULT 'SYSTEM' NOT NULL"),
        ],
        "telemetry": [
            ("organization_id", "INTEGER"),
            ("event_type", "VARCHAR(80) DEFAULT 'APPLICATION_ACTIVITY' NOT NULL"),
            ("source", "VARCHAR(32) DEFAULT 'SIMULATION' NOT NULL"),
            ("metadata", "JSON"),
        ],
        "risk_scores": [("organization_id", "INTEGER")],
        "access_requests": [("organization_id", "INTEGER")],
        "security_tags": [("organization_id", "INTEGER")],
    }
    with engine.begin() as connection:
        for table, columns in additions.items():
            existing = {row[1] for row in connection.execute(text(f"PRAGMA table_info({table})"))}
            for name, definition in columns:
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))
