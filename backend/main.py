from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api import (
    access,
    admin,
    applications,
    auth,
    devices,
    events,
    health,
    organization,
    risk,
    simulation,
    telemetry,
    users,
)
from backend.config import AUTO_SEED, DATA_STORE, get_allowed_origins
from backend.database import init_db
from backend.db.mongodb import close_mongodb, init_mongodb

logger = logging.getLogger("uvicorn.error")


def _auto_seed_if_needed() -> None:
    if not AUTO_SEED:
        return
    try:
        from backend import models
        from backend.data.seed import seed
        from backend.database import SessionLocal

        with SessionLocal() as db:
            user_count = db.query(models.User).count()
            telemetry_count = db.query(models.Telemetry).count()
            if user_count == 0 or telemetry_count == 0:
                logger.info("Seeding initial demo data and baseline telemetry...")
                seed()
                logger.info("Demo data seed completed successfully.")
    except Exception as exc:
        logger.warning("Auto-seed check encountered an issue: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db()
    _auto_seed_if_needed()
    if DATA_STORE == "mongodb":
        init_mongodb()
    yield
    close_mongodb()


def create_app() -> FastAPI:
    app = FastAPI(
        title="CloudSentinel Backend",
        description="Backend foundation for the CloudSentinel Adaptive Zero Trust control plane.",
        version="1.1.0",
        lifespan=lifespan,
    )

    origins = get_allowed_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_origin_regex=r"^https?://.*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Cloud hosting health check and root endpoints
    @app.get("/", tags=["root"])
    def root():
        return {
            "service": "CloudSentinel Adaptive Zero Trust Control Plane",
            "status": "online",
            "version": "1.1.0",
            "health": "/api/health",
            "docs": "/docs",
        }

    @app.get("/health", tags=["health"])
    def health_alias():
        return {"status": "healthy", "service": "cloudsentinel-backend"}

    app.include_router(health.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(organization.router, prefix="/api")
    app.include_router(admin.router, prefix="/api")
    app.include_router(users.router, prefix="/api")
    app.include_router(devices.router, prefix="/api")
    app.include_router(applications.router, prefix="/api")
    app.include_router(events.router, prefix="/api")
    app.include_router(telemetry.router, prefix="/api")
    app.include_router(risk.router, prefix="/api")
    app.include_router(access.router, prefix="/api")
    app.include_router(simulation.router, prefix="/api")

    return app


app = create_app()
