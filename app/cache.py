import os
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)


def cache_set(key: str, value: str, expire_seconds: int = 300):
    try:
        redis_client.set(key, value, ex=expire_seconds)
    except Exception:
        pass


def cache_get(key: str):
    try:
        return redis_client.get(key)
    except Exception:
        return None
