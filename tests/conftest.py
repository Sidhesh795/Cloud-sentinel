import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend import models
from backend.auth.auth import hash_password
from backend.database import Base, get_db
from backend.main import app


SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=__import__("sqlalchemy.pool").pool.StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture()
def client():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        user = models.User(
            username="developer01",
            password_hash=hash_password("CloudDemo123!"),
            display_name="Nina Patel",
            role="developer",
            email="nina.patel@cloudsentinel.demo",
            device_id="DEV-DEV-001",
            is_active=True,
        )
        db.add(user)
        db.flush()
        device = models.Device(
            device_id="DEV-DEV-001",
            user_id=user.id,
            os="Windows",
            os_version="Windows 11 Enterprise 23H2",
            trusted_device=True,
            os_compliant=True,
            av_active=True,
            location="Pune",
        )
        db.add(device)
        db.flush()
        db.add(
            models.SecurityTag(
                user_id=user.id,
                device_id=device.id,
                tag="TRUSTED_DEVICE",
                severity="GREEN",
                source="test",
                is_active=True,
            )
        )
        for app_data in [
            ("Email", "AZURE", "Collaboration", 20),
            ("HR Portal", "AZURE", "Business Application", 40),
            ("Customer Database", "AWS", "Database", 90),
            ("Admin Console", "AWS", "Administration", 100),
            ("Cloud Storage", "GCP", "Storage", 70),
            ("Analytics Service", "GCP", "Analytics", 60),
        ]:
            db.add(
                models.Application(
                    name=app_data[0],
                    description=f"{app_data[0]} demo resource.",
                    cloud_provider=app_data[1],
                    category=app_data[2],
                    sensitivity=app_data[3],
                    is_active=True,
                )
            )
        db.commit()
    finally:
        db.close()

    def override_get_db():
        test_db = TestingSessionLocal()
        try:
            yield test_db
        finally:
            test_db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
