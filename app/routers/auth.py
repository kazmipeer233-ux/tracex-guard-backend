from fastapi import APIRouter, Depends, HTTPException, status
from app.models.db import SessionLocal
from app.models.user import User
from app.models.device import Device
from app.auth_utils import verify_password, get_password_hash, create_access_token
from app.deps import get_current_user
from app.crypto.e2e import encrypt_message
from app.services.notification_service import send_alert
from sqlalchemy.orm import Session
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["auth"])

class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: str = None
    device_fingerprint: str = None

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    device_id: str = None
    device_fingerprint: str = None
    public_key: str = None

class DeviceRegisterRequest(BaseModel):
    device_id: str
    fingerprint: str

@router.post("/login")
def login(data: LoginRequest):
    db: Session = SessionLocal()
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # If the client provides device info, persist it for fingerprint validation
    suspicious_login = False
    note = None

    if data.device_id and data.device_fingerprint:
        device = db.query(Device).filter(Device.device_id == data.device_id, Device.user_id == user.id).first()
        if not device:
            device = Device(user_id=user.id, device_id=data.device_id, fingerprint=data.device_fingerprint)
            db.add(device)
            suspicious_login = True
            note = "New device registered"
        else:
            if device.fingerprint != data.device_fingerprint:
                suspicious_login = True
                note = "Device fingerprint changed"
            device.fingerprint = data.device_fingerprint
        db.commit()

    token_payload = {"sub": user.id}
    if data.device_id:
        token_payload["device_id"] = data.device_id
    if data.device_fingerprint:
        token_payload["fingerprint"] = data.device_fingerprint

    token = create_access_token(token_payload)

    if suspicious_login:
        send_alert(
            user.id,
            "Suspicious login detected",
            {"note": note, "username": data.username},
        )

    return {"access_token": token, "token_type": "bearer"}

@router.post("/register")
def register(data: RegisterRequest):
    db: Session = SessionLocal()
    if db.query(User).filter((User.username == data.username) | (User.email == data.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already exists")
    user = User(
        username=data.username,
        email=data.email,
        hashed_password=get_password_hash(data.password),
        public_key=data.public_key,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # If device info was provided during registration, register the device
    if data.device_id and data.device_fingerprint:
        device = Device(user_id=user.id, device_id=data.device_id, fingerprint=data.device_fingerprint)
        db.add(device)
        db.commit()

    token_payload = {"sub": user.id}
    if data.device_id:
        token_payload["device_id"] = data.device_id
    if data.device_fingerprint:
        token_payload["fingerprint"] = data.device_fingerprint

    token = create_access_token(token_payload)
    return {"access_token": token, "token_type": "bearer"}

@router.post("/device/register")
def register_device(data: DeviceRegisterRequest, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    user_id = current_user.get("sub")
    device = db.query(Device).filter(Device.device_id == data.device_id, Device.user_id == user_id).first()
    if not device:
        device = Device(user_id=user_id, device_id=data.device_id, fingerprint=data.fingerprint)
        db.add(device)
    else:
        device.fingerprint = data.fingerprint
    db.commit()
    return {"status": "device registered", "device_id": data.device_id}


class PublicKeyUpdateRequest(BaseModel):
    public_key_pem: str


@router.post("/public-key")
def update_public_key(data: PublicKeyUpdateRequest, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    user_id = current_user.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.public_key = data.public_key_pem
    db.commit()
    return {"status": "public key updated"}


class EncryptMessageRequest(BaseModel):
    message: str


@router.post("/encrypt")
def encrypt_for_self(request: EncryptMessageRequest, current_user=Depends(get_current_user)):
    db: Session = SessionLocal()
    user_id = current_user.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.public_key:
        raise HTTPException(status_code=400, detail="No public key set")
    encrypted = encrypt_message(user.public_key, request.message)
    return {"encrypted": encrypted}

@router.get("/me")
def me(current_user=Depends(get_current_user)):
    return {"user": current_user}
