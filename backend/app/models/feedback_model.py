import os
import logging
from pydantic import BaseModel

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "")


class FeedbackRequest(BaseModel):
    code:            str
    predicted_label: int
    real_label:      int
    confidence:      float


def save_feedback(code: str, predicted_label: int, real_label: int, confidence: float):
    """Guarda un ejemplo de feedback en Supabase (PostgreSQL) o SQLite según entorno."""
    try:
        from app.db.database import get_connection
        conn   = get_connection()
        cursor = conn.cursor()

        if DATABASE_URL:
            # PostgreSQL
            cursor.execute("""
                INSERT INTO feedback (code, predicted_label, real_label, confidence)
                VALUES (%s, %s, %s, %s)
            """, (code, predicted_label, real_label, confidence))
        else:
            # SQLite
            cursor.execute("""
                INSERT INTO feedback (code, predicted_label, real_label, confidence)
                VALUES (?, ?, ?, ?)
            """, (code, predicted_label, real_label, confidence))

        conn.commit()
        conn.close()
        logger.info("Feedback guardado correctamente.")
        return True

    except Exception as e:
        logger.error("Error guardando feedback: %s", e)
        return False