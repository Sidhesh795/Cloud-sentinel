from datetime import datetime, timezone

from sqlalchemy import Boolean, false, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="ACTIVE", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped["Organization | None"] = relationship(back_populates="users")
    devices: Mapped[list["Device"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    security_events: Mapped[list["SecurityEvent"]] = relationship(back_populates="user")
    telemetry: Mapped[list["Telemetry"]] = relationship(back_populates="user")
    risk_scores: Mapped[list["RiskScore"]] = relationship(back_populates="user")
    security_tags: Mapped[list["SecurityTag"]] = relationship(back_populates="user")
    access_requests: Mapped[list["AccessRequest"]] = relationship(back_populates="user")


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="ACTIVE", nullable=False)
    environment: Mapped[str] = mapped_column(String(24), default="DEMO", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="organization")
    devices: Mapped[list["Device"]] = relationship(back_populates="organization")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    device_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    device_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(120), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True)
    platform_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    device_fingerprint: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="ONLINE", nullable=False)
    posture_status: Mapped[str] = mapped_column(String(24), default="HEALTHY", nullable=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    ip_context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    location_context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    os: Mapped[str] = mapped_column(String(64), nullable=False)
    os_version: Mapped[str] = mapped_column(String(64), nullable=False)
    trusted_device: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    os_compliant: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    av_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    location: Mapped[str] = mapped_column(String(120), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    credential_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, nullable=True)
    credential_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization | None] = relationship(back_populates="devices")
    user: Mapped[User] = relationship(back_populates="devices")
    security_events: Mapped[list["SecurityEvent"]] = relationship(back_populates="device")
    telemetry: Mapped[list["Telemetry"]] = relationship(back_populates="device")
    security_tags: Mapped[list["SecurityTag"]] = relationship(back_populates="device")


class Application(Base):
    __tablename__ = "applications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cloud_provider: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    sensitivity: Mapped[int] = mapped_column(Integer, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    upstream_host: Mapped[str | None] = mapped_column(String(255), unique=True, index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    access_requests: Mapped[list["AccessRequest"]] = relationship(back_populates="application")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(32), default="SYSTEM", nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)

    user: Mapped[User | None] = relationship(back_populates="security_events")
    device: Mapped[Device | None] = relationship(back_populates="security_events")


class Telemetry(Base):
    __tablename__ = "telemetry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    requests_per_minute: Mapped[int] = mapped_column(Integer, nullable=False)
    data_download_mb: Mapped[float] = mapped_column(Float, nullable=False)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False)
    unique_applications: Mapped[int] = mapped_column(Integer, nullable=False)
    access_frequency: Mapped[int] = mapped_column(Integer, nullable=False)
    login_hour: Mapped[int] = mapped_column(Integer, nullable=False)
    location: Mapped[str] = mapped_column(String(120), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), default="APPLICATION_ACTIVITY", nullable=False)
    source: Mapped[str] = mapped_column(String(32), default="SIMULATION", nullable=False)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    anomaly_flag: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)

    user: Mapped[User] = relationship(back_populates="telemetry")
    device: Mapped[Device | None] = relationship(back_populates="telemetry")


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    identity_risk: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    posture_risk: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    behavior_risk: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    context_risk: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    resource_risk: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)

    user: Mapped[User] = relationship(back_populates="risk_scores")


class AccessRequest(Base):
    __tablename__ = "access_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    application_id: Mapped[int] = mapped_column(ForeignKey("applications.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)

    user: Mapped[User] = relationship(back_populates="access_requests")
    application: Mapped[Application] = relationship(back_populates="access_requests")


class SecurityTag(Base):
    __tablename__ = "security_tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    tag: Mapped[str] = mapped_column(String(80), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    user: Mapped[User] = relationship(back_populates="security_tags")
    device: Mapped[Device | None] = relationship(back_populates="security_tags")


class SimulationState(Base):
    __tablename__ = "simulation_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True, nullable=False)
    simulation_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="NORMAL", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(150), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True, nullable=False)


class AnomalyFeedback(Base):
    __tablename__ = "anomaly_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), nullable=True, index=True)
    telemetry_id: Mapped[int] = mapped_column(ForeignKey("telemetry.id"), unique=True, nullable=False)
    verdict: Mapped[str] = mapped_column(String(24), nullable=False)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
