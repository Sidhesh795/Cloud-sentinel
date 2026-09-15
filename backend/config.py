import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - app can still use real environment variables
    load_dotenv = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = PROJECT_ROOT / ".env"

if load_dotenv is not None:
    load_dotenv(ENV_FILE, override=False)


DATA_STORE = os.getenv("DATA_STORE", "sqlite").strip().lower() or "sqlite"
MONGODB_URI = os.getenv("MONGODB_URI", "").strip()
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "cloudsentinel").strip() or "cloudsentinel"
JWT_SECRET = os.getenv("JWT_SECRET") or os.getenv("CLOUDSENTINEL_SECRET_KEY", "cloudsentinel-dev-secret-change-me")
AUTO_SEED = os.getenv("AUTO_SEED", "true").strip().lower() in ("true", "1", "yes")

# Database URL configuration (translates Render's postgres:// to postgresql:// for SQLAlchemy)
raw_db_url = os.getenv("DATABASE_URL", "").strip()
if raw_db_url.startswith("postgres://"):
    DATABASE_URL = raw_db_url.replace("postgres://", "postgresql://", 1)
elif raw_db_url:
    DATABASE_URL = raw_db_url
elif os.getenv("VERCEL"):
    DATABASE_URL = "sqlite:////tmp/cloudsentinel.db"
else:
    DATABASE_URL = f"sqlite:///{Path(__file__).resolve().parent / 'cloudsentinel.db'}"

# Host and Port configuration
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "0.0.0.0")


def get_allowed_origins() -> list[str]:
    default_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
    ]
    env_origins = os.getenv("ALLOWED_ORIGINS") or os.getenv("CORS_ORIGINS", "")
    if env_origins:
        for origin in env_origins.split(","):
            cleaned = origin.strip()
            if cleaned and cleaned not in default_origins:
                default_origins.append(cleaned)
    return default_origins


def using_mongodb() -> bool:
    return DATA_STORE == "mongodb"

