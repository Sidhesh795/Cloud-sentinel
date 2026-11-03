import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend import config, models

_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
RECOVERY_CODE_COUNT = 8


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 15
    return f"{(struct.unpack('>I', mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**6:06d}"


def match_step(secret: str, code: str, at: float | None = None, window: int = 1) -> int | None:
    digits = "".join(ch for ch in code if ch.isdigit())
    if len(digits) != 6:
        return None
    step = int((time.time() if at is None else at) // 30)
    for candidate in range(step - window, step + window + 1):
        if hmac.compare_digest(_hotp(secret, candidate), digits):
            return candidate
    return None


def otpauth_uri(secret: str, account: str) -> str:
    issuer = quote(config.MFA_ISSUER)
    return f"otpauth://totp/{issuer}:{quote(account)}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def _fernet() -> Fernet:
    material = config.MFA_ENCRYPTION_KEY or f"cs-mfa|{config.JWT_SECRET}"
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(material.encode()).digest()))


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(token: str) -> str | None:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None


def _norm_recovery(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def _hash_recovery(code: str) -> str:
    return hashlib.sha256(_norm_recovery(code).encode()).hexdigest()


def issue_recovery_codes(db: Session, user: models.User) -> list[str]:
    db.query(models.MfaRecoveryCode).filter(models.MfaRecoveryCode.user_id == user.id).delete()
    codes = ["".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10)) for _ in range(RECOVERY_CODE_COUNT)]
    for code in codes:
        db.add(models.MfaRecoveryCode(user_id=user.id, code_hash=_hash_recovery(code)))
    db.flush()
    return [f"{c[:5]}-{c[5:]}" for c in codes]


def recovery_remaining(db: Session, user: models.User) -> int:
    return db.query(models.MfaRecoveryCode).filter(
        models.MfaRecoveryCode.user_id == user.id, models.MfaRecoveryCode.used_at.is_(None)
    ).count()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def check_code(db: Session, user: models.User, code: str, allow_pending: bool = False) -> bool:
    """Verify a TOTP (single use per 30s step) or recovery code. Locks the account after repeated failures."""
    now = datetime.now(timezone.utc)
    if user.mfa_locked_until and _aware(user.mfa_locked_until) > now:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many attempts. Try again later.")
    secret = decrypt_secret(user.mfa_secret_enc) if user.mfa_secret_enc else None
    if secret is None or not (user.mfa_enabled or allow_pending):
        return False
    ok = False
    step = match_step(secret, code)
    if step is not None and step > (user.mfa_last_step or 0):
        user.mfa_last_step = step
        ok = True
    elif user.mfa_enabled:
        digest = _hash_recovery(code)
        row = db.query(models.MfaRecoveryCode).filter(
            models.MfaRecoveryCode.user_id == user.id,
            models.MfaRecoveryCode.code_hash == digest,
            models.MfaRecoveryCode.used_at.is_(None),
        ).first()
        if row is not None:
            row.used_at = now
            ok = True
    if ok:
        user.mfa_failed_attempts = 0
        user.mfa_locked_until = None
    else:
        user.mfa_failed_attempts = (user.mfa_failed_attempts or 0) + 1
        if user.mfa_failed_attempts >= config.MFA_MAX_ATTEMPTS:
            user.mfa_locked_until = now + timedelta(seconds=config.MFA_LOCK_SECONDS)
            user.mfa_failed_attempts = 0
    db.commit()
    return ok
