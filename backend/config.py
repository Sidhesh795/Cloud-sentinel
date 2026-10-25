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
def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("true", "1", "yes")


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"
DEMO_MODE = _flag("DEMO_MODE", not IS_PRODUCTION)
AUTO_SEED = _flag("AUTO_SEED", DEMO_MODE) and DEMO_MODE
SENTRY_DSN = os.getenv("SENTRY_DSN", "").strip()
REQUIRE_AGENT_DEVICE = _flag("REQUIRE_AGENT_DEVICE", IS_PRODUCTION)
DEVICE_STALE_SECONDS = int(os.getenv("DEVICE_STALE_SECONDS", "900"))
ENFORCE_CACHE_SECONDS = int(os.getenv("ENFORCE_CACHE_SECONDS", "15"))
LIVE_BEHAVIOR = _flag("LIVE_BEHAVIOR", not DEMO_MODE)
SESSION_MINUTES = int(os.getenv("SESSION_MINUTES", "480"))
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", "").strip() or None

_DEV_SECRET = "cloudsentinel-dev-secret-change-me"
JWT_SECRET = os.getenv("JWT_SECRET") or os.getenv("CLOUDSENTINEL_SECRET_KEY") or _DEV_SECRET
if IS_PRODUCTION and (JWT_SECRET == _DEV_SECRET or len(JWT_SECRET) < 32):
    raise RuntimeError("JWT_SECRET must be set to a random value of at least 32 characters when APP_ENV=production")

# Database URL configuration (translates Render's postgres:// to postgresql:// for SQLAlchemy)
raw_db_url = os.getenv("DATABASE_URL", "").strip()
if raw_db_url.startswith(("postgres://", "postgresql://")):
    # requirements ship psycopg v3, so force that driver (bare postgresql:// would load psycopg2)
    DATABASE_URL = "postgresql+psycopg://" + raw_db_url.split("://", 1)[1]
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

