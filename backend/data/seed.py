from datetime import datetime, timezone

from backend import models
from backend.auth.auth import hash_password
from backend.database import SessionLocal, init_db


DEMO_PASSWORD = "CloudDemo123!"

USERS = [
    {
        "username": "admin01",
        "display_name": "Avery Shah",
        "role": "admin",
        "email": "avery.shah@cloudsentinel.demo",
        "device_id": "DEV-ADMIN-001",
    },
    {
        "username": "developer01",
        "display_name": "Nina Patel",
        "role": "developer",
        "email": "nina.patel@cloudsentinel.demo",
        "device_id": "DEV-DEV-001",
    },
    {
        "username": "employee01",
        "display_name": "Marcus Lee",
        "role": "employee",
        "email": "marcus.lee@cloudsentinel.demo",
        "device_id": "DEV-EMP-001",
    },
    {
        "username": "analyst01",
        "display_name": "Sara Iyer",
        "role": "analyst",
        "email": "sara.iyer@cloudsentinel.demo",
        "device_id": "DEV-ANALYST-001",
    },
]

APPLICATIONS = [
    {
        "name": "Email",
        "description": "Corporate messaging and collaboration mailbox.",
        "cloud_provider": "AZURE",
        "category": "Collaboration",
        "sensitivity": 20,
    },
    {
        "name": "HR Portal",
        "description": "Employee records, payroll workflows, and benefits access.",
        "cloud_provider": "AZURE",
        "category": "Business Application",
        "sensitivity": 40,
    },
    {
        "name": "Customer Database",
        "description": "Production customer records and transaction history.",
        "cloud_provider": "AWS",
        "category": "Database",
        "sensitivity": 90,
    },
    {
        "name": "Admin Console",
        "description": "Privileged control plane for infrastructure administration.",
        "cloud_provider": "AWS",
        "category": "Administration",
        "sensitivity": 100,
    },
    {
        "name": "Cloud Storage",
        "description": "Shared project files and data exports.",
        "cloud_provider": "GCP",
        "category": "Storage",
        "sensitivity": 70,
    },
    {
        "name": "Analytics Service",
        "description": "Operational dashboards and aggregate business metrics.",
        "cloud_provider": "GCP",
        "category": "Analytics",
        "sensitivity": 60,
    },
]

BASELINE_TAGS = [
    ("TRUSTED_DEVICE", "GREEN", "seed"),
    ("MFA_VERIFIED", "GREEN", "seed"),
    ("OS_COMPLIANT", "GREEN", "seed"),
    ("AV_ACTIVE", "GREEN", "seed"),
]


def upsert_user(db, user_data: dict) -> models.User:
    user = db.query(models.User).filter_by(username=user_data["username"]).first()
    if user is None:
        user = models.User(
            username=user_data["username"],
            password_hash=hash_password(DEMO_PASSWORD),
            display_name=user_data["display_name"],
            role=user_data["role"],
            email=user_data["email"],
            device_id=user_data["device_id"],
            is_active=True,
        )
        db.add(user)
        db.flush()
    else:
        user.display_name = user_data["display_name"]
        user.role = user_data["role"]
        user.email = user_data["email"]
        user.device_id = user_data["device_id"]
        user.is_active = True
    return user


def upsert_device(db, user: models.User) -> models.Device:
    device = db.query(models.Device).filter_by(device_id=user.device_id).first()
    now = datetime.now(timezone.utc)
    if device is None:
        device = models.Device(
            device_id=user.device_id,
            user_id=user.id,
            os="Windows",
            os_version="Windows 11 Enterprise 23H2",
            trusted_device=True,
            os_compliant=True,
            av_active=True,
            location="Pune",
            last_seen=now,
        )
        db.add(device)
        db.flush()
    else:
        device.user_id = user.id
        device.os = "Windows"
        device.os_version = "Windows 11 Enterprise 23H2"
        device.trusted_device = True
        device.os_compliant = True
        device.av_active = True
        device.location = "Pune"
        device.last_seen = now
    return device


def upsert_security_tags(db, user: models.User, device: models.Device) -> None:
    for tag_name, severity, source in BASELINE_TAGS:
        tag = (
            db.query(models.SecurityTag)
            .filter_by(user_id=user.id, device_id=device.id, tag=tag_name)
            .first()
        )
        if tag is None:
            db.add(
                models.SecurityTag(
                    user_id=user.id,
                    device_id=device.id,
                    tag=tag_name,
                    severity=severity,
                    source=source,
                    is_active=True,
                )
            )
        else:
            tag.severity = severity
            tag.source = source
            tag.is_active = True


def upsert_baseline_telemetry(db, user: models.User, device: models.Device) -> None:
    latest = (
        db.query(models.Telemetry)
        .filter_by(user_id=user.id)
        .order_by(models.Telemetry.timestamp.desc())
        .first()
    )
    normal = {
        "requests_per_minute": 20,
        "data_download_mb": 50,
        "failed_logins": 0,
        "unique_applications": 2,
        "access_frequency": 5,
        "login_hour": 10,
        "location": device.location,
    }
    if latest and all(getattr(latest, key) == value for key, value in normal.items()):
        return
    db.add(models.Telemetry(user_id=user.id, device_id=device.id, **normal))


def reset_simulation_state(db, user: models.User) -> None:
    state = db.query(models.SimulationState).filter_by(user_id=user.id).first()
    if state is None:
        db.add(models.SimulationState(user_id=user.id, simulation_active=False, state="NORMAL"))
    else:
        state.simulation_active = False
        state.state = "NORMAL"
        state.started_at = None
        state.updated_at = datetime.now(timezone.utc)


def upsert_applications(db) -> None:
    for app_data in APPLICATIONS:
        application = db.query(models.Application).filter_by(name=app_data["name"]).first()
        if application is None:
            db.add(models.Application(**app_data, is_active=True))
        else:
            application.description = app_data["description"]
            application.cloud_provider = app_data["cloud_provider"]
            application.category = app_data["category"]
            application.sensitivity = app_data["sensitivity"]
            application.is_active = True


def seed() -> None:
    init_db()
    db = SessionLocal()
    try:
        for user_data in USERS:
            user = upsert_user(db, user_data)
            device = upsert_device(db, user)
            upsert_security_tags(db, user, device)
            upsert_baseline_telemetry(db, user, device)
            reset_simulation_state(db, user)
        upsert_applications(db)
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    seed()
    print("Seeded CloudSentinel demo data.")
