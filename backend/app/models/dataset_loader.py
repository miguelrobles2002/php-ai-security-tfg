import sqlite3
import logging
from pathlib import Path

from datasets import Dataset

logger = logging.getLogger(__name__)

DB_PATH    = Path("app/data/feedback.db")
NUM_LABELS = 3 


def load_feedback_dataset(limit: int = 100) -> Dataset:
    """
    Carga los últimos `limit` ejemplos de feedback confirmado
    y los devuelve como un HuggingFace Dataset con columnas
    'text' (str) y 'labels' (int).
    """

    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"No se encontró la base de datos de feedback en '{DB_PATH}'. "
            "Asegúrate de que la ruta es correcta y de que existen registros."
        )

    if not isinstance(limit, int) or limit <= 0:
        raise ValueError(f"'limit' debe ser un entero positivo, recibido: {limit}")

    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()

        cur.execute("""
            SELECT code, real_label
            FROM feedback
            WHERE real_label IS NOT NULL
              AND code IS NOT NULL
              AND TRIM(code) != ''
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))

        rows = cur.fetchall()

    except sqlite3.Error as e:
        raise RuntimeError(f"Error al leer la base de datos de feedback: {e}") from e
    finally:
        conn.close()

    data    = []
    skipped = 0

    for code, real_label in rows:
        try:
            label = int(real_label)
        except (TypeError, ValueError):
            logger.warning("Label no convertible a int ('%s'), fila ignorada.", real_label)
            skipped += 1
            continue

        if label not in range(NUM_LABELS):
            logger.warning("Label fuera de rango (%d), fila ignorada.", label)
            skipped += 1
            continue

        text = str(code).strip()
        if not text:
            logger.warning("Texto vacío tras strip, fila ignorada.")
            skipped += 1
            continue

        data.append({"text": text, "labels": label})

    logger.info(
        "Feedback cargado: %d ejemplos válidos, %d ignorados (de %d totales).",
        len(data), skipped, len(rows)
    )

    if not data:
        logger.warning("No hay ejemplos válidos en el feedback. Dataset vacío.")

    return Dataset.from_list(data)

def _mark_feedback_as_rotated():
    """Marca los feedbacks procesados para que el contador vuelva a 0."""
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE feedback SET rotated = 1 WHERE real_label IS NOT NULL")
    conn.commit()
    conn.close()