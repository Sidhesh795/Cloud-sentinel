from __future__ import annotations

from contextlib import suppress
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from backend.config import MONGODB_DATABASE, MONGODB_URI

try:
    from pymongo import ASCENDING, MongoClient
    from pymongo.errors import PyMongoError, ServerSelectionTimeoutError
except Exception:  # pragma: no cover - exercised when pymongo is not installed
    ASCENDING = 1
    MongoClient = None
    PyMongoError = Exception
    ServerSelectionTimeoutError = Exception


_client: Any | None = None
_database: Any | None = None
_last_error: str | None = None


def _sanitize_error(exc: Exception) -> str:
    message = str(exc)
    if MONGODB_URI:
        message = message.replace(MONGODB_URI, "[mongodb-uri-redacted]")
        with suppress(Exception):
            parsed = urlsplit(MONGODB_URI)
            if parsed.username:
                message = message.replace(parsed.username, "[username-redacted]")
            if parsed.password:
                message = message.replace(parsed.password, "[password-redacted]")
    return message


def init_mongodb() -> None:
    global _client, _database, _last_error
    if not MONGODB_URI or MongoClient is None:
        _last_error = "MongoDB is not configured" if not MONGODB_URI else "pymongo is not installed"
        return
    try:
        _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=2500)
        _client.admin.command("ping")
        _database = _client[MONGODB_DATABASE]
        ensure_indexes()
        _last_error = None
    except (PyMongoError, ServerSelectionTimeoutError) as exc:
        _client = None
        _database = None
        _last_error = _sanitize_error(exc)


def close_mongodb() -> None:
    global _client, _database
    if _client is not None:
        with suppress(Exception):
            _client.close()
    _client = None
    _database = None


def get_mongo_database():
    return _database


def ensure_indexes() -> None:
    if _database is None:
        return
    _database.organizations.create_index([("slug", ASCENDING)], unique=True)
    _database.users.create_index([("organization_id", ASCENDING), ("username", ASCENDING)], unique=True)
    _database.users.create_index([("organization_id", ASCENDING), ("email", ASCENDING)], unique=True)
    _database.devices.create_index([("organization_id", ASCENDING), ("device_id", ASCENDING)], unique=True)
    _database.devices.create_index([("device_fingerprint", ASCENDING)], unique=True)
    _database.telemetry.create_index([("organization_id", ASCENDING), ("timestamp", ASCENDING)])
    _database.security_events.create_index([("organization_id", ASCENDING), ("timestamp", ASCENDING)])


def health() -> dict[str, str]:
    if _database is None:
        return {
            "status": "unavailable",
            "database": MONGODB_DATABASE,
            "detail": _last_error or "MongoDB is not initialized",
        }
    try:
        _client.admin.command("ping")
        return {"status": "healthy", "database": MONGODB_DATABASE}
    except (PyMongoError, ServerSelectionTimeoutError) as exc:
        return {"status": "unavailable", "database": MONGODB_DATABASE, "detail": _sanitize_error(exc)}


def stamp(document: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    document.setdefault("created_at", now)
    document["updated_at"] = now
    return document
