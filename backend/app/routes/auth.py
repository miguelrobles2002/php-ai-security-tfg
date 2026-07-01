import os
import logging
import secrets
from datetime import datetime, timedelta

import httpx
from fastapi import APIRouter, Response, Request, HTTPException
from passlib.hash import bcrypt

logger = logging.getLogger(__name__)
router = APIRouter()

SUPABASE_URL     = os.environ.get("SUPABASE_URL", "")
SUPABASE_API_KEY = os.environ.get("SUPABASE_API_KEY", "")

VALID_ROLES = {"basic", "premium"}  # admin no se puede asignar desde el panel

def _use_supabase():
    return bool(SUPABASE_URL and SUPABASE_API_KEY)

def _headers():
    return {
        "apikey":        SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}",
        "Content-Type":  "application/json",
    }

# ── Supabase helpers ──────────────────────────────────────
def _get_user_by_email(email: str):
    res  = httpx.get(f"{SUPABASE_URL}/rest/v1/users?email=eq.{email}&select=*",
                     headers=_headers(), timeout=10)
    data = res.json()
    return data[0] if data else None

def _get_user_by_id(user_id: int):
    res  = httpx.get(f"{SUPABASE_URL}/rest/v1/users?id=eq.{user_id}&select=*",
                     headers=_headers(), timeout=10)
    data = res.json()
    return data[0] if data else None

def _create_user(email: str, password_hash: str):
    res = httpx.post(f"{SUPABASE_URL}/rest/v1/users",
                     headers={**_headers(), "Prefer": "return=representation"},
                     json={"email": email, "password": password_hash,
                           "is_verified": True, "is_admin": False, "role": "basic"},
                     timeout=10)
    data = res.json()
    return data[0] if data else None

def _update_user(user_id: int, fields: dict):
    httpx.patch(f"{SUPABASE_URL}/rest/v1/users?id=eq.{user_id}",
                headers=_headers(), json=fields, timeout=10)

def _get_all_users():
    res = httpx.get(f"{SUPABASE_URL}/rest/v1/users?select=*&order=id",
                    headers=_headers(), timeout=10)
    return res.json()

# ── SQLite helpers ────────────────────────────────────────
def _sqlite_get_by_email(email: str):
    try:
        from app.db.auth_db import SessionLocalAuth
        from app.db.auth_models import User
        db   = SessionLocalAuth()
        user = db.query(User).filter(User.email == email).first()
        db.close()
        if not user: return None
        return {"id": user.id, "email": user.email, "password": user.password,
                "is_admin": user.is_admin, "is_verified": user.is_verified,
                "role": user.role or "basic", "daily_requests": user.daily_requests,
                "last_request_date": user.last_request_date,
                "created_at": user.created_at.isoformat() if user.created_at else None}
    except Exception as e:
        logger.error("SQLite get_by_email: %s", e); return None

def _sqlite_get_by_id(user_id: int):
    try:
        from app.db.auth_db import SessionLocalAuth
        from app.db.auth_models import User
        db   = SessionLocalAuth()
        user = db.query(User).filter(User.id == user_id).first()
        db.close()
        if not user: return None
        return {"id": user.id, "email": user.email, "password": user.password,
                "is_admin": user.is_admin, "is_verified": user.is_verified,
                "role": user.role or "basic", "daily_requests": user.daily_requests,
                "last_request_date": user.last_request_date,
                "created_at": user.created_at.isoformat() if user.created_at else None}
    except Exception as e:
        logger.error("SQLite get_by_id: %s", e); return None

def _sqlite_create(email: str, password_hash: str):
    try:
        from app.db.auth_db import SessionLocalAuth
        from app.db.auth_models import User
        db   = SessionLocalAuth()
        user = User(email=email, password=password_hash, is_verified=True, role="basic")
        db.add(user); db.commit(); db.refresh(user); db.close()
        return {"id": user.id, "email": user.email, "is_admin": user.is_admin,
                "role": user.role, "daily_requests": user.daily_requests}
    except Exception as e:
        logger.error("SQLite create: %s", e); return None

def _sqlite_update(user_id: int, fields: dict):
    try:
        from app.db.auth_db import SessionLocalAuth
        from app.db.auth_models import User
        db   = SessionLocalAuth()
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            for k, v in fields.items(): setattr(user, k, v)
            db.commit()
        db.close()
    except Exception as e:
        logger.error("SQLite update: %s", e)

def _sqlite_get_all():
    try:
        from app.db.auth_db import SessionLocalAuth
        from app.db.auth_models import User
        db    = SessionLocalAuth()
        users = db.query(User).order_by(User.id).all()
        db.close()
        return [{"id": u.id, "email": u.email, "is_admin": u.is_admin,
                 "is_verified": u.is_verified, "role": u.role or "basic",
                 "daily_requests": u.daily_requests,
                 "last_request_date": u.last_request_date,
                 "created_at": u.created_at.isoformat() if u.created_at else None}
                for u in users]
    except Exception as e:
        logger.error("SQLite get_all: %s", e); return []

# ── Wrappers ──────────────────────────────────────────────
def get_user_by_email(email):
    return _get_user_by_email(email) if _use_supabase() else _sqlite_get_by_email(email)

def get_user_by_id(uid):
    return _get_user_by_id(uid) if _use_supabase() else _sqlite_get_by_id(uid)

def create_user(email, pw):
    return _create_user(email, pw) if _use_supabase() else _sqlite_create(email, pw)

def update_user(uid, fields):
    _update_user(uid, fields) if _use_supabase() else _sqlite_update(uid, fields)

def get_all_users():
    return _get_all_users() if _use_supabase() else _sqlite_get_all()

# ── Sesiones ──────────────────────────────────────────────
sessions: dict = {}
SESSION_HOURS  = 8
MAX_SESSIONS   = 5

def _cleanup():
    now = datetime.utcnow()
    for s in [k for k, v in sessions.items() if v["expires"] < now]:
        del sessions[s]

def get_current_user(request: Request):
    sid = request.cookies.get("session_id")
    if not sid: raise HTTPException(401, "No autenticado")
    _cleanup()
    session = sessions.get(sid)
    if not session or session["expires"] < datetime.utcnow():
        if sid in sessions: del sessions[sid]
        raise HTTPException(401, "Sesión expirada")
    user = get_user_by_id(session["user_id"])
    if not user: raise HTTPException(401, "Usuario no encontrado")
    return user

# ── Endpoints ─────────────────────────────────────────────

@router.post("/register")
def register(email: str, password: str):
    if not email or "@" not in email or len(email) > 254:
        raise HTTPException(400, "Email inválido")
    if not password or len(password) < 8:
        raise HTTPException(400, "La contraseña debe tener al menos 8 caracteres")
    email = email.lower().strip()
    if get_user_by_email(email):
        raise HTTPException(400, "Email ya registrado")
    user = create_user(email, bcrypt.hash(password))
    if not user:
        raise HTTPException(500, "Error al crear el usuario")
    logger.info("Usuario registrado: %s", email)
    return {"message": "Registrado correctamente. Ya puedes iniciar sesión."}


@router.post("/login")
def login(response: Response, email: str, password: str):
    email  = (email or "").lower().strip()
    user   = get_user_by_email(email)
    dummy  = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8H.dKdxAVVz9h7uCcRu"
    stored = user["password"] if user else dummy
    if not bcrypt.verify(password, stored) or not user:
        raise HTTPException(401, "Credenciales incorrectas")

    _cleanup()
    user_sessions = [s for s, d in sessions.items() if d["user_id"] == user["id"]]
    if len(user_sessions) >= MAX_SESSIONS:
        del sessions[user_sessions[0]]

    sid = secrets.token_urlsafe(32)
    sessions[sid] = {"user_id": user["id"],
                     "expires": datetime.utcnow() + timedelta(hours=SESSION_HOURS)}

    response.set_cookie(key="session_id", value=sid, httponly=True,
                        secure=True, samesite="lax", max_age=SESSION_HOURS * 3600)
    logger.info("Login exitoso: %s", email)
    return {"message": "Login correcto", "admin": user["is_admin"]}


@router.post("/logout")
def logout(response: Response, request: Request):
    sid = request.cookies.get("session_id")
    if sid and sid in sessions: del sessions[sid]
    response.delete_cookie("session_id")
    return {"message": "Sesión cerrada"}


@router.get("/verify-session")
def verify_session(request: Request):
    user  = get_current_user(request)
    role  = user.get("role") or ("admin" if user["is_admin"] else "basic")
    limit = {"basic": 20, "premium": 50, "admin": None}.get(role)
    return {
        "authenticated":  True,
        "email":          user["email"],
        "admin":          user["is_admin"],
        "role":           role,
        "daily_requests": user.get("daily_requests", 0),
        "limit":          limit,
    }


@router.get("/admin/users")
def admin_list_users(request: Request):
    user = get_current_user(request)
    if not user["is_admin"]:
        raise HTTPException(403, "Acceso denegado")
    _cleanup()
    now             = datetime.utcnow()
    active_ids      = {d["user_id"] for d in sessions.values() if d["expires"] > now}
    users           = get_all_users()
    return [
        {
            "id":                u["id"],
            "email":             u["email"],
            "is_admin":          u["is_admin"],
            "role":              u.get("role") or ("admin" if u["is_admin"] else "basic"),
            "is_verified":       u.get("is_verified", True),
            "daily_requests":    u.get("daily_requests", 0),
            "last_request_date": u.get("last_request_date"),
            "created_at":        u.get("created_at"),
            "online":            u["id"] in active_ids,
        }
        for u in users
    ]


@router.patch("/admin/users/{user_id}/role")
def change_user_role(user_id: int, request: Request, role: str):
    admin = get_current_user(request)
    if not admin["is_admin"]:
        raise HTTPException(403, "Acceso denegado")
    if role not in VALID_ROLES:
        raise HTTPException(400, f"Rol inválido. Valores permitidos: {', '.join(VALID_ROLES)}")
    target = get_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Usuario no encontrado")
    if target["is_admin"]:
        raise HTTPException(400, "No se puede cambiar el rol de un admin")
    update_user(user_id, {"role": role})
    logger.info("Rol de usuario %s cambiado a %s por admin %s",
                target["email"], role, admin["email"])
    return {"message": f"Rol actualizado a '{role}'", "user_id": user_id, "role": role}