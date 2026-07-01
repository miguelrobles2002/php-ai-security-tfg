import os
import logging
import httpx
from passlib.hash import bcrypt

logger = logging.getLogger(__name__)

SUPABASE_URL     = os.environ.get("SUPABASE_URL", "")
SUPABASE_API_KEY = os.environ.get("SUPABASE_API_KEY", "")
ADMIN_EMAIL      = os.environ.get("ADMIN_EMAIL", "")
ADMIN_PASSWORD   = os.environ.get("ADMIN_PASSWORD", "")


def _use_supabase():
    return bool(SUPABASE_URL and SUPABASE_API_KEY)


def _headers():
    return {
        "apikey":        SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}",
        "Content-Type":  "application/json",
    }


def _supabase_init():
    # Si no hay admin configurado por variables de entorno, no creamos nada.
    if not (ADMIN_EMAIL and ADMIN_PASSWORD):
        logger.info("ADMIN_EMAIL/ADMIN_PASSWORD no configurados: se omite la creación de admin.")
        return

    res = httpx.get(
        f"{SUPABASE_URL}/rest/v1/users?email=eq.{ADMIN_EMAIL}&select=id,is_verified,role",
        headers=_headers(), timeout=10
    )
    # Validar que Supabase respondió correctamente antes de parsear JSON.
    # Si está caído/pausado devuelve HTML de error (no JSON) y esto evita
    # el JSONDecodeError que tumbaba la app.
    res.raise_for_status()
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
        try:
            _supabase_init()
        except Exception as e:
            # Si Supabase falla (caído, pausado, incidencia...), la app NO debe
            # morirse: solo registramos el error y seguimos arrancando. La parte
            # de análisis de código (IA) funciona sin base de datos.
            logger.error("No se pudo inicializar Supabase (la app sigue arrancando): %s", e)
    else:
        logger.info("Inicializando auth con SQLite...")
        try:
            _sqlite_init()
        except Exception as e:
            logger.error("No se pudo inicializar SQLite (la app sigue arrancando): %s", e)
    logger.info("Base de datos de autenticación lista.")