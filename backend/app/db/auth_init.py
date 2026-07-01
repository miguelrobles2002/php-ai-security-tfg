import os
import logging
import httpx
from passlib.hash import bcrypt

logger = logging.getLogger(__name__)

SUPABASE_URL     = os.environ.get("SUPABASE_URL", "")
SUPABASE_API_KEY = os.environ.get("SUPABASE_API_KEY", "")
ADMIN_EMAIL      = "miguelroblesmedina@gmail.com"
ADMIN_PASSWORD   = "ASO_asir.2026"


def _use_supabase():
    return bool(SUPABASE_URL and SUPABASE_API_KEY)


def _headers():
    return {
        "apikey":        SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}",
        "Content-Type":  "application/json",
    }


def _supabase_init():
    res  = httpx.get(
        f"{SUPABASE_URL}/rest/v1/users?email=eq.{ADMIN_EMAIL}&select=id,is_verified,role",
        headers=_headers(), timeout=10
    )
    data = res.json()

    if not data:
        httpx.post(
            f"{SUPABASE_URL}/rest/v1/users",
            headers={**_headers(), "Prefer": "return=minimal"},
            json={
                "email":       ADMIN_EMAIL,
                "password":    bcrypt.hash(ADMIN_PASSWORD),
                "is_admin":    True,
                "is_verified": True,
                "role":        "admin",
            },
            timeout=10
        )
        logger.info("Admin creado en Supabase.")
    else:
        # Migrar campo role si no existe
        updates = {}
        if not data[0].get("is_verified"):
            updates["is_verified"] = True
        if not data[0].get("role"):
            updates["role"] = "admin"
        if updates:
            httpx.patch(
                f"{SUPABASE_URL}/rest/v1/users?id=eq.{data[0]['id']}",
                headers=_headers(), json=updates, timeout=10
            )
            logger.info("Admin actualizado en Supabase: %s", updates)


def _sqlite_init():
    from app.db.auth_db import engine, BaseAuth, SessionLocalAuth
    from app.db.auth_models import User
    from sqlalchemy import text

    BaseAuth.metadata.create_all(bind=engine)

    # Migración: añadir columnas nuevas si no existen
    new_columns = [
        ("is_verified",       "BOOLEAN DEFAULT 1"),
        ("last_request_date", "VARCHAR"),
        ("role",              "VARCHAR DEFAULT 'basic'"),
    ]
    with engine.connect() as conn:
        for col_name, col_def in new_columns:
            try:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}"))
                conn.commit()
            except Exception:
                pass

    db    = SessionLocalAuth()
    admin = db.query(User).filter(User.email == ADMIN_EMAIL).first()
    if not admin:
        db.add(User(
            email=ADMIN_EMAIL,
            password=bcrypt.hash(ADMIN_PASSWORD),
            is_admin=True,
            is_verified=True,
            role="admin"
        ))
        db.commit()
        logger.info("Admin creado en SQLite.")
    else:
        changed = False
        if not admin.is_verified:
            admin.is_verified = True
            changed = True
        if not admin.role:
            admin.role = "admin"
            changed = True
        if changed:
            db.commit()
    db.close()


def init_auth_db():
    if _use_supabase():
        logger.info("Inicializando auth con Supabase...")
        _supabase_init()
    else:
        logger.info("Inicializando auth con SQLite...")
        _sqlite_init()
    logger.info("Base de datos de autenticación lista.")