from backend import models
from backend.security.anomaly import assess_behavior
from backend.security.posture import evaluate_posture
from backend.security.risk_engine import calculate_risk


def telemetry(**overrides):
    values = {
        "requests_per_minute": 20,
        "data_download_mb": 50,
        "failed_logins": 0,
        "unique_applications": 2,
        "access_frequency": 5,
        "login_hour": 10,
        "location": "Pune",
    }
    values.update(overrides)
    return models.Telemetry(user_id=1, device_id=1, **values)


def user_with_telemetry(sample):
    user = models.User(
        id=1,
        username="developer01",
        password_hash="hash",
        display_name="Nina Patel",
        role="developer",
        email="nina.patel@cloudsentinel.demo",
        device_id="DEV-DEV-001",
        is_active=True,
    )
    user.telemetry = [sample]
    return user


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


def test_anomaly_normal_behavior_low_risk():
    result = assess_behavior(telemetry())
    assert result.is_anomaly is False
    assert result.behavior_risk < 30


def test_anomaly_attack_like_behavior_high_risk():
    result = assess_behavior(
        telemetry(
            requests_per_minute=180,
            data_download_mb=850,
            failed_logins=4,
            unique_applications=5,
            access_frequency=30,
            login_hour=2,
        )
    )
    assert result.is_anomaly is True
    assert result.behavior_risk >= 70


def test_healthy_device_produces_healthy_tags():
    sample = telemetry()
    user = user_with_telemetry(sample)
    result = evaluate_posture(user, device(), assess_behavior(sample))
    tags = {tag.tag for tag in result.tags}
    assert {"TRUSTED_DEVICE", "OS_COMPLIANT", "AV_ACTIVE", "NORMAL_BEHAVIOR"} <= tags
    assert result.posture_risk == 0


def test_changed_device_state_produces_warning_and_critical_tags():
    sample = telemetry(
        requests_per_minute=180,
        data_download_mb=850,
        failed_logins=4,
        unique_applications=5,
        access_frequency=30,
        location="Singapore",
    )
    user = user_with_telemetry(sample)
    result = evaluate_posture(
        user,
        device(trusted_device=False, os_compliant=False, av_active=False),
        assess_behavior(sample),
    )
    tags = {tag.tag for tag in result.tags}
    assert {"NEW_DEVICE", "OUTDATED_SOFTWARE", "COMPROMISED_DEVICE", "DATA_EXFILTRATION"} <= tags
    assert result.posture_risk >= 30


def test_normal_state_calculates_low_risk():
    sample = telemetry()
    user = user_with_telemetry(sample)
    anomaly = assess_behavior(sample)
    posture = evaluate_posture(user, device(), anomaly)
    risk = calculate_risk(user, device(), sample, posture, anomaly)
    assert risk.risk_level == "LOW"
    assert 0 <= risk.risk_score <= 100


def test_attack_like_state_calculates_high_or_critical_risk():
    sample = telemetry(
        requests_per_minute=180,
        data_download_mb=850,
        failed_logins=4,
        unique_applications=5,
        access_frequency=30,
        login_hour=2,
        location="Singapore",
    )
    user = user_with_telemetry(sample)
    bad_device = device(trusted_device=False)
    anomaly = assess_behavior(sample)
    posture = evaluate_posture(user, bad_device, anomaly)
    risk = calculate_risk(user, bad_device, sample, posture, anomaly)
    assert risk.risk_level in {"HIGH", "CRITICAL"}
    assert risk.risk_score >= 60
    assert risk.reasons
