import os
import logging

logger = logging.getLogger(__name__)

SUPABASE_URL     = os.environ.get("SUPABASE_URL", "")
SUPABASE_API_KEY = os.environ.get("SUPABASE_API_KEY", "")


def _use_supabase():
    return bool(SUPABASE_URL and SUPABASE_API_KEY)


def supabase_headers():
    return {
        "apikey":        SUPABASE_API_KEY,
        "Authorization": f"Bearer {SUPABASE_API_KEY}",
        "Content-Type":  "application/json",
        "Prefer":        "return=minimal"
    }


def init_db():
    if _use_supabase():
        logger.info("Usando Supabase REST API para feedback.")
        return

    # Fallback SQLite local
    import sqlite3
    from pathlib import Path
    BASE_DIR = Path(__file__).resolve().parent
    DATA_DIR = BASE_DIR.parent / "data"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH  = DATA_DIR / "feedback.db"

    logger.info("Inicializando base de datos SQLite en: %s", DB_PATH)
    conn   = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            code            TEXT    NOT NULL,
            predicted_label INTEGER,
            real_label      INTEGER,
            confidence      REAL,
            rotated         INTEGER DEFAULT 0,
            created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    try:
        cursor.execute("ALTER TABLE feedback ADD COLUMN rotated INTEGER DEFAULT 0")
    except Exception:
        pass
    conn.commit()
    conn.close()
    logger.info("Base de datos SQLite lista.")


def get_connection():
    """Solo para uso local con SQLite."""
    import sqlite3
    from pathlib import Path
    BASE_DIR = Path(__file__).resolve().parent
    DATA_DIR = BASE_DIR.parent / "data"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH  = DATA_DIR / "feedback.db"
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn