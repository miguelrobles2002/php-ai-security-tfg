import os
import logging
import threading

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)
router = APIRouter()

SUPABASE_URL     = os.environ.get("SUPABASE_URL", "")
SUPABASE_API_KEY = os.environ.get("SUPABASE_API_KEY", "")


def _use_supabase():
    return bool(SUPABASE_URL and SUPABASE_API_KEY)


def _supabase_headers():
    return {
        "apikey":        SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}",
        "Content-Type":  "application/json",
        "Prefer":        "return=minimal"
    }


class FeedbackRequest(BaseModel):
    code:            str
    predicted_label: int
    real_label:      int
    confidence:      float

    @field_validator("real_label", "predicted_label")
    @classmethod
    def label_must_be_valid(cls, v):
        if v not in (0, 1, 2):
            raise ValueError("El label debe ser 0, 1 o 2")
        return v

    @field_validator("confidence")
    @classmethod
    def confidence_must_be_valid(cls, v):
        if not (0.0 <= v <= 1.0):
            raise ValueError("La confianza debe estar entre 0.0 y 1.0")
        return v

    @field_validator("code")
    @classmethod
    def code_must_not_be_empty(cls, v):
        if not v.strip():
            raise ValueError("El código no puede estar vacío")
        return v


def _get_user_role(request: Request) -> str:
    """Devuelve el rol del usuario actual desde la sesión."""
    from app.routes.auth import sessions, get_user_by_id
    from datetime import datetime
    sid = request.cookies.get("session_id")
    if not sid or sid not in sessions:
        return "anonymous"
    session = sessions[sid]
    if session["expires"] < datetime.utcnow():
        return "anonymous"
    user = get_user_by_id(session["user_id"])
    if not user:
        return "anonymous"
    if user.get("is_admin"):
        return "admin"
    return user.get("role") or "basic"


def _run_incremental():
    try:
        from app.models.train_incremental import train_incremental
        train_incremental()
    except Exception as e:
        logger.error("Error en entrenamiento incremental: %s", e)


def _save_supabase(data: FeedbackRequest) -> int:
    url = f"{SUPABASE_URL}/rest/v1/feedback"
    res = httpx.post(url, headers=_supabase_headers(), json={
        "code":            data.code,
        "predicted_label": data.predicted_label,
        "real_label":      data.real_label,
        "confidence":      data.confidence,
    }, timeout=10)
    if res.status_code not in (200, 201):
        raise Exception(f"Supabase insert error {res.status_code}: {res.text}")
    count_res = httpx.get(
        f"{SUPABASE_URL}/rest/v1/feedback?select=id&rotated=eq.0",
        headers={**_supabase_headers(), "Prefer": "count=exact"}, timeout=10
    )
    return int(count_res.headers.get("content-range", "0/0").split("/")[-1])


def _save_sqlite(data: FeedbackRequest) -> int:
    from app.db.database import get_connection
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO feedback (code, predicted_label, real_label, confidence)
        VALUES (?, ?, ?, ?)
    """, (data.code, data.predicted_label, data.real_label, data.confidence))
    conn.commit()
    cur.execute("""
        SELECT COUNT(*) FROM feedback
        WHERE real_label IS NOT NULL AND (rotated IS NULL OR rotated = 0)
    """)
    count = cur.fetchone()[0]
    conn.close()
    return count


@router.post("/feedback")
def save_feedback(data: FeedbackRequest, request: Request):

    # Verificar que el usuario puede enviar feedback
    role = _get_user_role(request)
    if role == "basic":
        raise HTTPException(
            status_code=403,
            detail="El feedback solo está disponible para usuarios premium. Contacta con el administrador."
        )
    if role == "anonymous":
        raise HTTPException(status_code=401, detail="No autenticado")

    try:
        count = _save_supabase(data) if _use_supabase() else _save_sqlite(data)
    except Exception as e:
        logger.error("Error al guardar feedback: %s", e)
        raise HTTPException(status_code=500, detail="Error al guardar el feedback")

    if count > 0 and count % 100 == 0:
        logger.info("100 feedbacks → lanzando entrenamiento incremental...")
        threading.Thread(target=_run_incremental, daemon=True).start()

    return {
        "status":           "ok",
        "message":          "Feedback guardado",
        "count":            count,
        "next_training_in": max(0, 100 - (count % 100))
    }