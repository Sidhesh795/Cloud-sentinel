from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserBase(BaseModel):
    id: int
    username: str
    display_name: str
    role: str
    email: EmailStr
    device_id: str | None
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserSummary(BaseModel):
    id: int
    username: str
    role: str

    model_config = ConfigDict(from_attributes=True)


class DeviceRead(BaseModel):
    id: int
    device_id: str
    user_id: int
    os: str
    os_version: str
    trusted_device: bool
    os_compliant: bool
    av_active: bool
    location: str
    last_seen: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApplicationRead(BaseModel):
    id: int
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
    user_id: int | None
    device_id: int | None
    event_type: str
    severity: str
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


class TelemetryRead(BaseModel):
    id: int
    user_id: int
    device_id: int | None
    requests_per_minute: int
    data_download_mb: float
    failed_logins: int
    unique_applications: int
    access_frequency: int
    login_hour: int
    location: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


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
