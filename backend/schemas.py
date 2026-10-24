from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


USER_ROLES = "^(ADMIN|SECURITY_ANALYST|EMPLOYEE|DEVELOPER|admin|analyst|employee|developer)$"
USER_STATUSES = "^(ACTIVE|SUSPENDED|DISABLED)$"


class UserBase(BaseModel):
    id: int
    organization_id: int | None = None
    username: str
    display_name: str
    role: str
    email: EmailStr
    device_id: str | None
    status: str = "ACTIVE"
    is_active: bool
    created_at: datetime
    updated_at: datetime | None = None
    last_login: datetime | None = None
    last_seen: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class UserSummary(BaseModel):
    id: int
    username: str
    role: str

    model_config = ConfigDict(from_attributes=True)


class OrganizationRead(BaseModel):
    id: int
    name: str
    slug: str
    status: str
    environment: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AdminUserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=120)
    role: str = Field(pattern=USER_ROLES)
    status: str = Field(default="ACTIVE", pattern=USER_STATUSES)


class AdminUserUpdate(BaseModel):
    email: EmailStr | None = None
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: str | None = Field(default=None, pattern=USER_ROLES)
    status: str | None = Field(default=None, pattern=USER_STATUSES)


class DeviceRead(BaseModel):
    id: int
    organization_id: int | None = None
    device_id: str
    user_id: int
    device_name: str | None = None
    hostname: str | None = None
    platform: str | None = None
    platform_version: str | None = None
    agent_version: str | None = None
    status: str = "ONLINE"
    posture_status: str = "HEALTHY"
    registered_at: datetime | None = None
    os: str
    os_version: str
    trusted_device: bool
    os_compliant: bool
    av_active: bool
    location: str
    last_seen: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DeviceInventoryItem(DeviceRead):
    username: str | None = None
    user_email: EmailStr | None = None
    user_display_name: str | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)


class DeviceRegisterRequest(BaseModel):
    user_id: int | None = None
    device_name: str = Field(min_length=1, max_length=120)
    hostname: str = Field(min_length=1, max_length=120)
    platform: str = Field(min_length=1, max_length=64)
    platform_version: str = Field(min_length=1, max_length=120)
    agent_version: str = Field(min_length=1, max_length=40)


class DeviceRegisterResponse(BaseModel):
    device_id: str
    agent_registration_token: str
    status: str


class DeviceHeartbeatRequest(BaseModel):
    agent_version: str | None = Field(default=None, max_length=40)
    posture_metadata: dict | None = None


class DeviceHeartbeatResponse(BaseModel):
    device_id: str
    status: str
    server_time: datetime
    next_heartbeat_seconds: int


class DevicePostureRequest(BaseModel):
    os: str = Field(min_length=1, max_length=64)
    os_version: str = Field(min_length=1, max_length=120)
    firewall_enabled: bool | None = None
    encryption_enabled: bool | None = None
    security_product_active: bool | None = None
    patch_state: str | None = Field(default=None, max_length=40)
    screen_lock_enabled: bool | None = None
    security_product_name: str | None = Field(default=None, max_length=80)
    last_update_days: int | None = Field(default=None, ge=0, le=36500)
    metadata: dict | None = None


class DevicePostureResponse(BaseModel):
    device_id: str
    posture_status: str
    reasons: list[str]
    server_time: datetime


class ApplicationRead(BaseModel):
    id: int
    organization_id: int | None = None
    name: str
    description: str
    cloud_provider: str
    category: str
    sensitivity: int = Field(ge=0, le=100)
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityTagRead(BaseModel):
    id: int
    user_id: int
    device_id: int | None
    tag: str
    severity: str
    source: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityTagSummary(BaseModel):
    tag: str
    severity: str
    source: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class SecurityEventRead(BaseModel):
    id: int
    organization_id: int | None = None
    user_id: int | None
    device_id: int | None
    event_type: str
    severity: str
    source: str = "SYSTEM"
    description: str
    metadata: dict | None = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_model(cls, event) -> "SecurityEventRead":
        return cls(
            id=event.id,
            user_id=event.user_id,
            device_id=event.device_id,
            event_type=event.event_type,
            severity=event.severity,
            source=event.source,
            description=event.description,
            metadata=event.metadata_json,
            timestamp=event.timestamp,
        )


class UserPostureRead(BaseModel):
    user: UserBase
    devices: list[DeviceRead]
    security_tags: list[SecurityTagRead]
    posture_status: str = "STATIC"
    posture_risk: int = 0
    last_evaluated_at: datetime | None = None
    reasons: list[str] = []


class TelemetryCreate(BaseModel):
    user_id: int
    device_id: str
    requests_per_minute: int = Field(ge=0, le=1000)
    data_download_mb: float = Field(ge=0, le=100000)
    failed_logins: int = Field(ge=0, le=100)
    unique_applications: int = Field(ge=0, le=100)
    access_frequency: int = Field(ge=0, le=1000)
    login_hour: int = Field(ge=0, le=23)
    location: str = Field(min_length=1, max_length=120)
    event_type: str = "APPLICATION_ACTIVITY"
    source: str = "SIMULATION"
    metadata: dict | None = None


class TelemetryRead(BaseModel):
    id: int
    organization_id: int | None = None
    user_id: int
    device_id: int | None
    requests_per_minute: int
    data_download_mb: float
    failed_logins: int
    unique_applications: int
    access_frequency: int
    login_hour: int
    location: str
    event_type: str = "APPLICATION_ACTIVITY"
    source: str = "SIMULATION"
    metadata: dict | None = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_model(cls, telemetry) -> "TelemetryRead":
        return cls(
            id=telemetry.id,
            organization_id=telemetry.organization_id,
            user_id=telemetry.user_id,
            device_id=telemetry.device_id,
            requests_per_minute=telemetry.requests_per_minute,
            data_download_mb=telemetry.data_download_mb,
            failed_logins=telemetry.failed_logins,
            unique_applications=telemetry.unique_applications,
            access_frequency=telemetry.access_frequency,
            login_hour=telemetry.login_hour,
            location=telemetry.location,
            event_type=telemetry.event_type,
            source=telemetry.source,
            metadata=telemetry.metadata_json,
            timestamp=telemetry.timestamp,
        )


class RiskAssessmentRead(BaseModel):
    user_id: int
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    components: dict[str, int]
    anomaly: dict
    tags: list[SecurityTagSummary]
    reasons: list[str]


class RiskScoreRead(BaseModel):
    id: int
    user_id: int
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    identity_risk: int
    posture_risk: int
    behavior_risk: int
    context_risk: int
    resource_risk: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class AccessCheckRequest(BaseModel):
    user_id: int
    application_id: int
    action: str = Field(pattern="^(READ|WRITE|DELETE|ADMIN)$")


class AccessDecisionRead(BaseModel):
    user_id: int
    application: dict
    action: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    decision: str
    reason: str
    policy_rule: str
    resource_sensitivity: int = Field(ge=0, le=100)
    resource_level: str
    factors: list[str]


class AccessMatrixItem(BaseModel):
    application_id: int
    application: str
    cloud: str
    sensitivity: int = Field(ge=0, le=100)
    resource_level: str
    action: str
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    decision: str
    reason: str
    policy_rule: str
    factors: list[str]


class SimulationRequest(BaseModel):
    user_id: int


class SimulationStatusRead(BaseModel):
    user_id: int
    simulation_active: bool
    state: str
    started_at: datetime | None
    risk_score: int | None


class SimulationResultRead(BaseModel):
    user_id: int
    simulation_active: bool
    state: str
    started_at: datetime | None
    risk_score: int
    risk_level: str
    access_matrix: list[AccessMatrixItem]
    events_created: list[str]


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserSummary


class HealthResponse(BaseModel):
    status: str
    service: str


class MongoHealthResponse(BaseModel):
    status: str
    database: str
    detail: str | None = None


class EnrollmentTokenRequest(BaseModel):
    user_id: int | None = None
    ttl_minutes: int = Field(default=60, ge=5, le=1440)


class EnrollmentTokenResponse(BaseModel):
    token: str
    expires_at: datetime
    user_id: int


class AgentEnrollRequest(BaseModel):
    token: str = Field(min_length=10, max_length=128)
    device_name: str = Field(min_length=1, max_length=120)
    hostname: str = Field(min_length=1, max_length=120)
    platform: str = Field(min_length=1, max_length=64)
    platform_version: str = Field(min_length=1, max_length=120)
    agent_version: str = Field(min_length=1, max_length=40)


class AgentEnrollResponse(BaseModel):
    device_id: str
    device_secret: str
    heartbeat_seconds: int
