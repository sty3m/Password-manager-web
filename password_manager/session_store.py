import secrets
import threading
import time

_LOCK = threading.Lock()
_SESSIONS = {}
SESSION_TTL_SECONDS = 60 * 60

def create_session(user_id, username, key):
    token = secrets.token_urlsafe(32)
    with _LOCK:
        _SESSIONS[token] = {"key": key, "user_id": user_id, "username": username, "created_at": time.time()}
    return token

def get_session(token):
    if not token:
        return None
    with _LOCK:
        session = _SESSIONS.get(token)
        if session is None:
            return None
        if time.time() - session["created_at"] > SESSION_TTL_SECONDS:
            del _SESSIONS[token]
            return None
        return session

def destroy_session(token):
    with _LOCK:
        _SESSIONS.pop(token, None)

def clear_all_sessions():
    with _LOCK:
        _SESSIONS.clear()
