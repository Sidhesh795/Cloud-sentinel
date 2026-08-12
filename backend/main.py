from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api import access, applications, auth, events, health, risk, simulation, telemetry, users
from backend.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="CloudSentinel Backend",
        description="Backend foundation for the CloudSentinel Adaptive Zero Trust demo.",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(users.router, prefix="/api")
    app.include_router(applications.router, prefix="/api")
    app.include_router(events.router, prefix="/api")
    app.include_router(telemetry.router, prefix="/api")
    app.include_router(risk.router, prefix="/api")
    app.include_router(access.router, prefix="/api")
    app.include_router(simulation.router, prefix="/api")

    return app


app = create_app()
