from dataclasses import dataclass

from backend import models
from backend.security.risk_engine import RiskAssessment


DECISION_ALLOW = "ALLOW"
DECISION_MFA = "MFA_REQUIRED"
DECISION_READ_ONLY = "READ_ONLY"
DECISION_DENY = "DENY"
DECISION_ISOLATE = "ISOLATE"

READ_ACTIONS = {"READ"}
WRITE_ACTIONS = {"WRITE", "DELETE", "ADMIN"}
CRITICAL_TAGS = {
    "MALICIOUS_PROCESS",
    "DATA_EXFILTRATION",
    "COMPROMISED_DEVICE",
    "CRITICAL_VULNERABILITY",
    "THREAT_DETECTED",
    "PRIVILEGE_ABUSE",
}

POLICY_MATRIX = {
    "LOW": {
        "LOW": DECISION_ALLOW,
        "MEDIUM": DECISION_ALLOW,
        "HIGH": DECISION_ALLOW,
        "CRITICAL": DECISION_MFA,
    },
    "MEDIUM": {
        "LOW": DECISION_ALLOW,
        "MEDIUM": DECISION_ALLOW,
        "HIGH": DECISION_MFA,
        "CRITICAL": DECISION_MFA,
    },
    "HIGH": {
        "LOW": DECISION_ALLOW,
        "MEDIUM": DECISION_MFA,
        "HIGH": DECISION_READ_ONLY,
        "CRITICAL": DECISION_DENY,
    },
    "CRITICAL": {
        "LOW": DECISION_MFA,
        "MEDIUM": DECISION_MFA,
        "HIGH": DECISION_READ_ONLY,
        "CRITICAL": DECISION_DENY,
    },
}

DECISION_RANK = {
    DECISION_ALLOW: 0,
    DECISION_MFA: 1,
    DECISION_READ_ONLY: 2,
    DECISION_DENY: 3,
    DECISION_ISOLATE: 4,
}


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason: str
    risk_score: int
    risk_level: str
    resource_sensitivity: int
    resource_level: str
    policy_rule: str
    factors: list[str]


def sensitivity_level(sensitivity: int) -> str:
    if sensitivity >= 80:
        return "CRITICAL"
    if sensitivity >= 60:
        return "HIGH"
    if sensitivity >= 30:
        return "MEDIUM"
    return "LOW"


def _more_restrictive(current: str, candidate: str) -> str:
    return candidate if DECISION_RANK[candidate] > DECISION_RANK[current] else current


def _action_restriction(decision: str, action: str, risk_level: str, resource_level: str) -> tuple[str, str | None]:
    action = action.upper()
    if action == "READ":
        return decision, None
    if action == "WRITE":
        if decision == DECISION_ALLOW and risk_level in {"MEDIUM", "HIGH", "CRITICAL"}:
            return DECISION_MFA, "WRITE_ELEVATED_AUTH"
        if decision == DECISION_READ_ONLY:
            return DECISION_MFA, "WRITE_ON_READ_ONLY_CONTEXT"
    if action in {"DELETE", "ADMIN"}:
        if risk_level in {"HIGH", "CRITICAL"} or resource_level in {"HIGH", "CRITICAL"}:
            return DECISION_DENY, f"{action}_SENSITIVE_RESOURCE"
        if decision == DECISION_ALLOW:
            return DECISION_MFA, f"{action}_REQUIRES_MFA"
    return decision, None


def _device_restriction(
    decision: str,
    device: models.Device | None,
    resource_level: str,
) -> tuple[str, str | None]:
    if device is None and resource_level in {"HIGH", "CRITICAL"}:
        return _more_restrictive(decision, DECISION_DENY), "NO_DEVICE_SENSITIVE_RESOURCE"
    if device is None:
        return _more_restrictive(decision, DECISION_MFA), "NO_REGISTERED_DEVICE"

    rule = None
    if not device.trusted_device and resource_level in {"HIGH", "CRITICAL"}:
        decision = _more_restrictive(decision, DECISION_DENY)
        rule = "UNTRUSTED_DEVICE_SENSITIVE_RESOURCE"
    elif not device.trusted_device:
        decision = _more_restrictive(decision, DECISION_MFA)
        rule = "UNTRUSTED_DEVICE"

    if (not device.av_active or not device.os_compliant) and resource_level == "CRITICAL":
        decision = _more_restrictive(decision, DECISION_DENY)
        rule = "WEAK_DEVICE_POSTURE_CRITICAL_RESOURCE"
    elif (not device.av_active or not device.os_compliant) and resource_level == "HIGH":
        decision = _more_restrictive(decision, DECISION_MFA)
        rule = "WEAK_DEVICE_POSTURE_HIGH_RESOURCE"

    return decision, rule


def evaluate_policy(
    *,
    user: models.User,
    risk: RiskAssessment,
    security_tags: list[models.SecurityTag],
    device: models.Device | None,
    application: models.Application,
    action: str,
) -> PolicyDecision:
    resource_level = sensitivity_level(application.sensitivity)
    action = action.upper()
    active_tag_names = sorted({tag.tag for tag in security_tags if tag.is_active})
    critical_active_tags = sorted(CRITICAL_TAGS.intersection(active_tag_names))

    if user.role.lower() == "admin":
        return _evaluate_admin_policy(
            risk=risk,
            active_tag_names=active_tag_names,
            application=application,
            action=action,
            resource_level=resource_level,
        )

    decision = POLICY_MATRIX[risk.risk_level][resource_level]
    policy_rule = f"{risk.risk_level}_RISK_{resource_level}_RESOURCE"

    if critical_active_tags and resource_level == "CRITICAL":
        decision = DECISION_DENY
        policy_rule = "CRITICAL_TAG_CRITICAL_RESOURCE"
    elif critical_active_tags and resource_level == "HIGH":
        decision = _more_restrictive(decision, DECISION_READ_ONLY)
        policy_rule = "CRITICAL_TAG_HIGH_RESOURCE"

    decision, device_rule = _device_restriction(decision, device, resource_level)
    if device_rule:
        policy_rule = device_rule

    decision, action_rule = _action_restriction(decision, action, risk.risk_level, resource_level)
    if action_rule:
        policy_rule = action_rule

    if risk.risk_level == "CRITICAL" and resource_level == "CRITICAL" and critical_active_tags:
        decision = DECISION_DENY
        policy_rule = "CRITICAL_RISK_CRITICAL_RESOURCE"

    reason = _reason_for(decision, risk.risk_level, resource_level, application.name)
    return PolicyDecision(
        decision=decision,
        reason=reason,
        risk_score=risk.risk_score,
        risk_level=risk.risk_level,
        resource_sensitivity=application.sensitivity,
        resource_level=resource_level,
        policy_rule=policy_rule,
        factors=active_tag_names,
    )


def _evaluate_admin_policy(
    *,
    risk: RiskAssessment,
    active_tag_names: list[str],
    application: models.Application,
    action: str,
    resource_level: str,
) -> PolicyDecision:
    action = action.upper()
    elevated_context = risk.risk_level in {"HIGH", "CRITICAL"}
    sensitive_resource = resource_level in {"HIGH", "CRITICAL"}
    elevated_action = action in {"WRITE", "DELETE", "ADMIN"}

    if elevated_context and (sensitive_resource or elevated_action):
        decision = DECISION_MFA
        policy_rule = "ADMIN_PRIVILEGED_STEP_UP_REQUIRED"
        reason = "Privileged administrator remains authorized, but step-up verification is required due to elevated risk."
    elif sensitive_resource and elevated_action:
        decision = DECISION_MFA
        policy_rule = "ADMIN_PRIVILEGED_SENSITIVE_ACTION"
        reason = "Privileged administrator access requires step-up verification for sensitive actions."
    else:
        decision = DECISION_ALLOW
        policy_rule = "ADMIN_PRIVILEGED_ACCESS"
        reason = f"{application.name} is authorized for the administrator role across simulated cloud resources."

    return PolicyDecision(
        decision=decision,
        reason=reason,
        risk_score=risk.risk_score,
        risk_level=risk.risk_level,
        resource_sensitivity=application.sensitivity,
        resource_level=resource_level,
        policy_rule=policy_rule,
        factors=active_tag_names,
    )


def _reason_for(decision: str, risk_level: str, resource_level: str, resource_name: str) -> str:
    if decision == DECISION_ALLOW:
        return f"{resource_name} is allowed because current risk and resource sensitivity are acceptable."
    if decision == DECISION_MFA:
        return "Additional authentication required due to elevated risk or resource sensitivity."
    if decision == DECISION_READ_ONLY:
        return "Write access is restricted; read-only access reduces exposure for this security context."
    if decision == DECISION_DENY:
        return f"{resource_level.title()} resource cannot be accessed from a {risk_level.lower()}-risk security context."
    return "Resource/session should be isolated by the enforcement layer for this security context."
