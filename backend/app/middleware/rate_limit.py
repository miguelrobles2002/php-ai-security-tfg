import os
import logging
from datetime import datetime, date
from collections import defaultdict

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.routes.auth import sessions

logger = logging.getLogger(__name__)

# Límites por rol
LIMITS = {
    "basic":   20,
    "premium": 50,
    "admin":   None,   # sin límite
}
IP_DAILY_LIMIT = 20

ip_counters: dict = defaultdict(lambda: {"count": 0, "date": ""})

SUPABASE_URL     = os.environ.get("SUPABASE_URL", "")
SUPABASE_API_KEY = os.environ.get("SUPABASE_API_KEY", "")


def _use_supabase():
    return bool(SUPABASE_URL and SUPABASE_API_KEY)


def _headers():
    return {
        "apikey":        SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}",
        "Content-Type":  "application/json",
    }


def _get_user_supabase(user_id: int):
    res  = httpx.get(
        f"{SUPABASE_URL}/rest/v1/users?id=eq.{user_id}"
        f"&select=id,email,is_admin,role,daily_requests,last_request_date",
        headers=_headers(), timeout=10
    )
    data = res.json()
    return data[0] if data else None


def _update_user_supabase(user_id: int, fields: dict):
    httpx.patch(
        f"{SUPABASE_URL}/rest/v1/users?id=eq.{user_id}",
        headers=_headers(), json=fields, timeout=10
    )


def _get_user_sqlite(user_id: int):
    try:
        from app.db.auth_db import SessionLocalAuth
        from app.db.auth_models import User
        db   = SessionLocalAuth()
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            db.close()
            return None
        result = {
            "id":                user.id,
            "email":             user.email,
            "is_admin":          user.is_admin,
            "role":              user.role or "basic",
            "daily_requests":    user.daily_requests,
            "last_request_date": user.last_request_date,
        }
        db.close()
        return result
    except Exception as e:
        logger.error("SQLite get_user error: %s", e)
        return None


def _update_user_sqlite(user_id: int, fields: dict):
    try:
        from app.db.auth_db import SessionLocalAuth
        from app.db.auth_models import User
        db   = SessionLocalAuth()
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            for k, v in fields.items():
                setattr(user, k, v)
            db.commit()
        db.close()
    except Exception as e:
        logger.error("SQLite update_user error: %s", e)


class RateLimitMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        if request.url.path != "/api/analyze":
            return await call_next(request)

        today      = date.today().isoformat()
        ip         = request.client.host or "unknown"
        session_id = request.cookies.get("session_id")
        user_id    = None

        if session_id and session_id in sessions:
            session = sessions[session_id]
            if session["expires"] > datetime.utcnow():
                user_id = session["user_id"]

        if user_id:
            user = _get_user_supabase(user_id) if _use_supabase() else _get_user_sqlite(user_id)

            if not user:
                return await call_next(request)

            role  = user.get("role") or ("admin" if user.get("is_admin") else "basic")
            limit = LIMITS.get(role)

            # Admin y roles sin límite pasan siempre
            if limit is None:
                return await call_next(request)

            daily_requests    = user.get("daily_requests", 0) or 0
            last_request_date = user.get("last_request_date", "")

            if last_request_date != today:
                daily_requests = 0

            if daily_requests >= limit:
                logger.warning("Usuario bloqueado [%s/%s] role=%s: %s",
                               daily_requests, limit, role, user.get("email"))
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail":     f"Límite diario de {limit} análisis alcanzado.",
                        "used":       daily_requests,
                        "limit":      limit,
                        "role":       role,
                        "reset_at":   "medianoche UTC",
                        "limit_type": "user"
                    }
                )

            new_count = daily_requests + 1
            fields    = {"daily_requests": new_count, "last_request_date": today}
            if _use_supabase():
                _update_user_supabase(user_id, fields)
            else:
                _update_user_sqlite(user_id, fields)

        else:
            # Sin sesión → límite por IP
            ip_data = ip_counters[ip]
            if ip_data["date"] != today:
                ip_data["count"] = 0
                ip_data["date"]  = today

            if ip_data["count"] >= IP_DAILY_LIMIT:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail":     f"Límite diario de {IP_DAILY_LIMIT} análisis alcanzado para esta IP.",
                        "reset_at":   "medianoche UTC",
                        "limit_type": "ip"
                    }
                )
            ip_data["count"] += 1

        return await call_next(request)