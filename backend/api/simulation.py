from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.auth.auth import get_current_user
from backend.database import get_db
from backend.models import User
from backend.schemas import SimulationRequest, SimulationResultRead, SimulationStatusRead
from backend.security.simulation import reset_simulation, simulation_status, trigger_attack


router = APIRouter(prefix="/simulation", tags=["simulation"])


def _ensure_self_requested(requested_user_id: int, current_user: User) -> None:
    if requested_user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Simulation controls are limited to the authenticated user",
        )


@router.post("/attack", response_model=SimulationResultRead)
def simulate_attack(
    payload: SimulationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    _ensure_self_requested(payload.user_id, current_user)
    return trigger_attack(db, payload.user_id)


@router.post("/reset", response_model=SimulationResultRead)
def reset_demo(
    payload: SimulationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    _ensure_self_requested(payload.user_id, current_user)
    return reset_simulation(db, payload.user_id)


@router.get("/status/{user_id}", response_model=SimulationStatusRead)
def get_simulation_status(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    _ensure_self_requested(user_id, current_user)
    return simulation_status(db, user_id)
