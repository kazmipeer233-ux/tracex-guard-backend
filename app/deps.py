from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from app.auth_utils import decode_access_token
from app.models.db import SessionLocal
from app.models.user import User
from app.models.device import Device

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    db = SessionLocal()
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # If token includes device info, verify it matches stored fingerprint
    device_id = payload.get("device_id")
    fingerprint = payload.get("fingerprint")
    if device_id and fingerprint:
        device = db.query(Device).filter(Device.device_id == device_id, Device.user_id == user_id).first()
        if not device or device.fingerprint != fingerprint:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device fingerprint mismatch")

    return payload


def get_current_admin(token: str = Depends(oauth2_scheme)):
    payload = get_current_user(token)
    user_id = payload.get("sub")

    db = SessionLocal()
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return payload
