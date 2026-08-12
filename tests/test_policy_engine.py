from backend import models
from backend.security.policy_engine import evaluate_policy
from backend.security.risk_engine import RiskAssessment


def risk(level: str, score: int):
    return RiskAssessment(
        user_id=1,
        risk_score=score,
        risk_level=level,
        identity_risk=0,
        posture_risk=0,
        behavior_risk=0,
        context_risk=0,
        reasons=[],
    )


def user():
    return models.User(
        id=1,
        username="developer01",
        password_hash="hash",
        display_name="Nina Patel",
        role="developer",
        email="nina.patel@cloudsentinel.demo",
        device_id="DEV-DEV-001",
        is_active=True,
    )


def admin_user():
    return models.User(
        id=2,
        username="admin01",
        password_hash="hash",
        display_name="Avery Shah",
        role="admin",
        email="avery.shah@cloudsentinel.demo",
        device_id="DEV-ADMIN-001",
        is_active=True,
    )


def device(**overrides):
    values = {
        "id": 1,
        "device_id": "DEV-DEV-001",
        "user_id": 1,
        "os": "Windows",
        "os_version": "Windows 11 Enterprise 23H2",
        "trusted_device": True,
        "os_compliant": True,
        "av_active": True,
        "location": "Pune",
    }
    values.update(overrides)
    return models.Device(**values)


def app(name: str, sensitivity: int, cloud="AWS"):
    return models.Application(
        id=1,
        name=name,
        description=f"{name} test app",
        cloud_provider=cloud,
        category="Test",
        sensitivity=sensitivity,
        is_active=True,
    )


def tag(name: str):
    return models.SecurityTag(
        user_id=1,
        tag=name,
        severity="CRITICAL",
        source="test",
        is_active=True,
    )


def decision(risk_level, score, sensitivity, action="READ", tags=None, dev=None, cloud="AWS"):
    return evaluate_policy(
        user=user(),
        risk=risk(risk_level, score),
        security_tags=tags or [],
        device=dev or device(),
        application=app("Resource", sensitivity, cloud),
        action=action,
    ).decision


def admin_decision(risk_level, score, sensitivity, action="READ", tags=None, cloud="AWS"):
    result = evaluate_policy(
        user=admin_user(),
        risk=risk(risk_level, score),
        security_tags=tags or [],
        device=device(),
        application=app("Resource", sensitivity, cloud),
        action=action,
    )
    return result


def test_low_risk_policy_matrix():
    assert decision("LOW", 12, 20) == "ALLOW"
    assert decision("LOW", 12, 40) == "ALLOW"
    assert decision("LOW", 12, 90) == "MFA_REQUIRED"


def test_medium_risk_policy_matrix():
    assert decision("MEDIUM", 45, 20) == "ALLOW"
    assert decision("MEDIUM", 45, 70) == "MFA_REQUIRED"
    assert decision("MEDIUM", 45, 90) == "MFA_REQUIRED"


def test_high_risk_policy_matrix():
    assert decision("HIGH", 65, 20) == "ALLOW"
    assert decision("HIGH", 65, 40) == "MFA_REQUIRED"
    assert decision("HIGH", 65, 70) == "READ_ONLY"
    assert decision("HIGH", 65, 90) == "DENY"


def test_critical_risk_policy_matrix():
    assert decision("CRITICAL", 91, 20) == "MFA_REQUIRED"
    assert decision("CRITICAL", 91, 70) == "READ_ONLY"
    assert decision("CRITICAL", 91, 90) == "DENY"


def test_critical_tags_deny_critical_resources():
    for tag_name in ["MALICIOUS_PROCESS", "DATA_EXFILTRATION", "COMPROMISED_DEVICE"]:
        assert decision("MEDIUM", 45, 90, tags=[tag(tag_name)]) == "DENY"


def test_dangerous_actions_become_more_restricted():
    assert decision("HIGH", 65, 70, action="READ") == "READ_ONLY"
    assert decision("HIGH", 65, 70, action="WRITE") == "MFA_REQUIRED"
    assert decision("HIGH", 65, 70, action="DELETE") == "DENY"
    assert decision("HIGH", 65, 40, action="ADMIN") == "DENY"


def test_untrusted_device_restricts_sensitive_resources():
    assert decision("MEDIUM", 45, 70, dev=device(trusted_device=False)) == "DENY"
    assert decision("MEDIUM", 45, 40, dev=device(trusted_device=False)) == "MFA_REQUIRED"


def test_multi_cloud_uses_same_policy():
    results = {
        decision("HIGH", 65, 90, cloud="AWS"),
        decision("HIGH", 65, 90, cloud="AZURE"),
        decision("HIGH", 65, 90, cloud="GCP"),
    }
    assert results == {"DENY"}


def test_admin_normal_access_all_clouds_and_sensitivities():
    for cloud in ["AWS", "AZURE", "GCP"]:
        for sensitivity in [20, 40, 70, 90, 100]:
            result = admin_decision("LOW", 7, sensitivity, cloud=cloud)
            assert result.decision == "ALLOW"
            assert result.policy_rule == "ADMIN_PRIVILEGED_ACCESS"


def test_admin_compromised_sensitive_resources_require_mfa_not_deny():
    for tag_name in ["DATA_EXFILTRATION", "THREAT_DETECTED", "COMPROMISED_DEVICE"]:
        result = admin_decision("CRITICAL", 100, 100, tags=[tag(tag_name)])
        assert result.decision == "MFA_REQUIRED"
        assert result.policy_rule == "ADMIN_PRIVILEGED_STEP_UP_REQUIRED"
        assert tag_name in result.factors


def test_admin_high_risk_low_resources_remain_authorized():
    result = admin_decision("CRITICAL", 100, 20, tags=[tag("DATA_EXFILTRATION")])
    assert result.decision == "ALLOW"
    assert result.risk_level == "CRITICAL"
