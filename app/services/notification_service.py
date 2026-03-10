import json
import time
import uuid
from typing import Any, Dict, List

from app.cache import redis_client

ALERT_LIST_PREFIX = "alerts:"  # each user has a list
READ_SET_SUFFIX = ":read"
CHANNEL_SUFFIX = ":channel"


def _alert_list_key(user_id: int) -> str:
    return f"{ALERT_LIST_PREFIX}{user_id}"


def _read_set_key(user_id: int) -> str:
    return f"{ALERT_LIST_PREFIX}{user_id}{READ_SET_SUFFIX}"


def _channel_key(user_id: int) -> str:
    return f"{ALERT_LIST_PREFIX}{user_id}{CHANNEL_SUFFIX}"


def send_alert(user_id: int, message: str, metadata: Dict[str, Any] = None, severity: str = "info") -> Dict[str, Any]:
    alert_id = str(uuid.uuid4())
    alert = {
        "id": alert_id,
        "message": message,
        "metadata": metadata or {},
        "severity": severity,
        "timestamp": int(time.time()),
    }

    key = _alert_list_key(user_id)
    try:
        redis_client.lpush(key, json.dumps(alert))
        # Keep list to last 100 items
        redis_client.ltrim(key, 0, 99)
    except Exception:
        pass

    # publish to websocket subscribers
    channel = _channel_key(user_id)
    try:
        redis_client.publish(channel, json.dumps(alert))
    except Exception:
        pass

    return alert


def get_alerts(user_id: int, only_unread: bool = False, limit: int = 50) -> List[Dict[str, Any]]:
    key = _alert_list_key(user_id)
    raw = []
    try:
        raw = redis_client.lrange(key, 0, limit - 1)
    except Exception:
        return []

    alerts = []
    read_set = set()
    if only_unread:
        try:
            read_set = set(redis_client.smembers(_read_set_key(user_id)) or [])
        except Exception:
            read_set = set()

    for item in raw:
        try:
            alert = json.loads(item)
        except Exception:
            continue
        if only_unread and alert.get("id") in read_set:
            continue
        alerts.append(alert)

    return alerts


def mark_alert_read(user_id: int, alert_id: str) -> bool:
    try:
        redis_client.sadd(_read_set_key(user_id), alert_id)
        return True
    except Exception:
        return False
