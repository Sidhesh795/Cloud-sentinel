from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.auth.auth import get_current_user, normalize_role
from backend.database import get_db
from backend.models import User
from backend.schemas import AccessCheckRequest, AccessDecisionRead, AccessMatrixItem
from backend.security.zero_trust_gateway import GatewayDecision, evaluate_access, evaluate_access_matrix


router = APIRouter(tags=["access"])


def _authorize_subject(db: Session, current_user: User, user_id: int) -> None:
    if user_id == current_user.id:
        return
    privileged = normalize_role(current_user.role) in {"ADMIN", "SECURITY_ANALYST", "ANALYST"}
    target = db.query(User).filter(User.id == user_id).first()
    same_org = target is not None and target.organization_id == current_user.organization_id
    if not (privileged and same_org):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed to evaluate access for this user")


def _decision_response(decision: GatewayDecision, action: str) -> AccessDecisionRead:
    return AccessDecisionRead(
        user_id=decision.user.id,
        application={
            "id": decision.application.id,
            "name": decision.application.name,
            "cloud_provider": decision.application.cloud_provider,
            "sensitivity": decision.application.sensitivity,
        },
        action=action.upper(),
        risk_score=decision.policy.risk_score,
        risk_level=decision.policy.risk_level,
        decision=decision.policy.decision,
        reason=decision.policy.reason,
        policy_rule=decision.policy.policy_rule,
        resource_sensitivity=decision.policy.resource_sensitivity,
        resource_level=decision.policy.resource_level,
        factors=decision.policy.factors,
    )


@router.post("/access/check", response_model=AccessDecisionRead)
def check_access(
    payload: AccessCheckRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AccessDecisionRead:
    _authorize_subject(db, current_user, payload.user_id)
    decision = evaluate_access(
        db,
        user_id=payload.user_id,
        application_id=payload.application_id,
        action=payload.action,
        persist=True,
    )
    return _decision_response(decision, payload.action)


@router.get("/users/{user_id}/access-matrix", response_model=list[AccessMatrixItem])
def get_access_matrix(
    user_id: int,
    action: str = "READ",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[AccessMatrixItem]:
    _authorize_subject(db, current_user, user_id)
    decisions = evaluate_access_matrix(db, user_id=user_id, action=action)
    return [
        AccessMatrixItem(
            application_id=item.application.id,
            application=item.application.name,
            cloud=item.application.cloud_provider,
            sensitivity=item.application.sensitivity,
            resource_level=item.policy.resource_level,
            action=action.upper(),
            risk_score=item.policy.risk_score,
            risk_level=item.policy.risk_level,
            decision=item.policy.decision,
            reason=item.policy.reason,
            policy_rule=item.policy.policy_rule,
            factors=item.policy.factors,
        )
        for item in decisions
    ]
