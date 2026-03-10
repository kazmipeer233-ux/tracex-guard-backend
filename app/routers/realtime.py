from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from typing import Dict
from jose import JWTError
from app.auth_utils import decode_access_token
from app.cache import redis_client

router = APIRouter(prefix="/realtime", tags=["realtime"])


def verify_token(token: str) -> Dict:
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload


@router.websocket("/alerts")
async def websocket_alerts(websocket: WebSocket, token: str):
    payload = verify_token(token)
    user_id = payload.get("sub")
    if not user_id:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    pubsub = redis_client.pubsub()
    channel = f"alerts:{user_id}:channel"
    pubsub.subscribe(channel)

    try:
        for message in pubsub.listen():
            if message is None:
                continue
            if message.get("type") != "message":
                continue
            data = message.get("data")
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            await websocket.send_text(data)
    except WebSocketDisconnect:
        pubsub.unsubscribe(channel)
        await websocket.close()
    finally:
        try:
            pubsub.unsubscribe(channel)
        except Exception:
            pass
