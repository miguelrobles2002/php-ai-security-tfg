import shutil
import sqlite3
import logging
from datetime import datetime
from pathlib import Path

import torch
import numpy as np
from torch.nn import CrossEntropyLoss

from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback,
)
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from app.models.dataset_loader import load_feedback_dataset, DB_PATH

logger = logging.getLogger(__name__)

BASE_MODEL_PATH        = Path("app/models/bert_model")
INCREMENTAL_MODEL_PATH = Path("app/models/bert_model_incremental")
BACKUP_DIR             = Path("app/models/backups")

MIN_EXAMPLES   = 10
ROTATE_EVERY   = 100  
MAX_BACKUPS    = 5
MAX_LENGTH     = 512
NUM_LABELS     = 3

def ensure_db_schema():
    """
    Añade la columna 'rotated' si no existe.
    SQLite no soporta IF NOT EXISTS en ALTER TABLE,
    así que capturamos el OperationalError si ya existe.
    """
    if not DB_PATH.exists():
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("ALTER TABLE feedback ADD COLUMN rotated INTEGER DEFAULT 0")
        conn.commit()
        logger.info("Columna 'rotated' añadida a la tabla feedback.")
    except sqlite3.OperationalError:
        pass  
    finally:
        conn.close()


def get_feedback_count() -> int:
    """Cuenta feedbacks confirmados y aún no rotados."""
    if not DB_PATH.exists():
        return 0
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM feedback
            WHERE real_label IS NOT NULL
              AND (rotated IS NULL OR rotated = 0)
        """)
        count = cur.fetchone()[0]
        conn.close()
        return count
    except sqlite3.Error as e:
        logger.error("Error al consultar feedback count: %s", e)
        return 0


def mark_feedback_as_rotated():
    """Marca todos los feedbacks procesados para resetear el contador."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            UPDATE feedback SET rotated = 1
            WHERE real_label IS NOT NULL
              AND (rotated IS NULL OR rotated = 0)
        """)
        conn.commit()
        conn.close()
        logger.info("Feedbacks marcados como rotados. Contador reseteado.")
    except sqlite3.Error as e:
        logger.error("Error al marcar feedbacks como rotados: %s", e)


def rotate_models():
    """
    Ciclo de rotación completo:

    ANTES:
        bert_model/              <- modelo base activo
        bert_model_incremental/  <- modelo reentrenado

    DESPUÉS:
        backups/bert_model_TIMESTAMP/  <- el base anterior
        bert_model/              <- lo que era incremental (nuevo base)
        bert_model_incremental/  <- vacío, listo para el próximo ciclo
    """
    weights = (
        list(INCREMENTAL_MODEL_PATH.glob("model.safetensors")) +
        list(INCREMENTAL_MODEL_PATH.glob("pytorch_model.bin"))
    )
    if not weights:
        logger.error("El modelo incremental no tiene pesos. Rotación cancelada.")
        return

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if BASE_MODEL_PATH.exists():
        backup_path = BACKUP_DIR / f"bert_model_{ts}"
        shutil.move(str(BASE_MODEL_PATH), str(backup_path))
        logger.info("Base anterior movido a backup: %s", backup_path)

    shutil.move(str(INCREMENTAL_MODEL_PATH), str(BASE_MODEL_PATH))
    logger.info("Incremental promovido a base: %s", BASE_MODEL_PATH)

    INCREMENTAL_MODEL_PATH.mkdir(parents=True, exist_ok=True)
    logger.info("Carpeta incremental recreada para el próximo ciclo.")

    backups = sorted(BACKUP_DIR.glob("bert_model_*"), key=lambda p: p.stat().st_mtime)
    for old in backups[:-MAX_BACKUPS]:
        shutil.rmtree(old)
        logger.info("Backup antiguo eliminado: %s", old)

    logger.info("=== Rotación completada ===")


class WeightedTrainer(Trainer):
    def __init__(self, class_weights: torch.Tensor, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.class_weights = class_weights

    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels  = inputs.get("labels")
        outputs = model(**inputs)
        logits  = outputs.get("logits")
        weights = self.class_weights.to(logits.device)
        loss    = CrossEntropyLoss(weight=weights)(logits, labels)
        return (loss, outputs) if return_outputs else loss


def compute_class_weights(dataset, num_labels: int = NUM_LABELS) -> torch.Tensor:
    counts = [0] * num_labels
    for item in dataset:
        counts[item["labels"]] += 1
    total = sum(counts)
    weights = [total / (num_labels * c) if c > 0 else 1.0 for c in counts]
    logger.info("Distribución labels: %s → pesos: %s", counts, [round(w, 3) for w in weights])
    return torch.tensor(weights, dtype=torch.float)


def backup_current_model() -> Path:
    if not INCREMENTAL_MODEL_PATH.exists():
        return None
    weights = (
        list(INCREMENTAL_MODEL_PATH.glob("model.safetensors")) +
        list(INCREMENTAL_MODEL_PATH.glob("pytorch_model.bin"))
    )
    if not weights:
        return None
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"bert_model_incremental_{ts}"
    shutil.copytree(INCREMENTAL_MODEL_PATH, backup_path)
    logger.info("Backup previo guardado en: %s", backup_path)
    return backup_path


def get_source_model_path() -> Path:
    if INCREMENTAL_MODEL_PATH.exists():
        weights = (
            list(INCREMENTAL_MODEL_PATH.glob("model.safetensors")) +
            list(INCREMENTAL_MODEL_PATH.glob("pytorch_model.bin"))
        )
        if weights:
            logger.info("Continuando desde modelo incremental: %s", INCREMENTAL_MODEL_PATH)
            return INCREMENTAL_MODEL_PATH

    if BASE_MODEL_PATH.exists():
        logger.info("Partiendo del modelo base: %s", BASE_MODEL_PATH)
        return BASE_MODEL_PATH

    raise RuntimeError(
        f"No se encontró ningún modelo en '{INCREMENTAL_MODEL_PATH}' ni en '{BASE_MODEL_PATH}'. "
        "Entrena el modelo base primero con run_train.py."
    )


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="weighted", zero_division=0
    )
    return {
        "accuracy":  round(accuracy_score(labels, preds), 4),
        "f1":        round(f1, 4),
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
    }


def train_incremental():
    logger.info("=== Entrenamiento incremental iniciado ===")

    ensure_db_schema()

    dataset = load_feedback_dataset(limit=ROTATE_EVERY)

    if len(dataset) < MIN_EXAMPLES:
        logger.warning(
            "Solo hay %d ejemplos de feedback (mínimo: %d). Entrenamiento cancelado.",
            len(dataset), MIN_EXAMPLES
        )
        return

    logger.info("Ejemplos de feedback cargados: %d", len(dataset))

    source_path = get_source_model_path()
    backup_path = backup_current_model()

    tokenizer = DistilBertTokenizerFast.from_pretrained(str(source_path))
    model     = DistilBertForSequenceClassification.from_pretrained(
        str(source_path),
        num_labels=NUM_LABELS
    )

    def tokenize(batch):
        return tokenizer(
            batch["text"],
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH
        )

    dataset = dataset.map(tokenize, batched=True)

    if "label" in dataset.column_names and "labels" not in dataset.column_names:
        dataset = dataset.rename_column("label", "labels")

    dataset.set_format("torch", columns=["input_ids", "attention_mask", "labels"])

    split      = dataset.train_test_split(test_size=0.1, seed=42)
    train_data = split["train"]
    val_data   = split["test"]
    logger.info("Train: %d | Val: %d", len(train_data), len(val_data))

    class_weights = compute_class_weights(train_data)

    training_args = TrainingArguments(
        output_dir                  = str(INCREMENTAL_MODEL_PATH),
        num_train_epochs            = 3,
        per_device_train_batch_size = 8,
        per_device_eval_batch_size  = 8,
        learning_rate               = 1e-5,
        weight_decay                = 0.01,
        warmup_ratio                = 0.1,
        lr_scheduler_type           = "cosine",
        eval_strategy               = "epoch",
        save_strategy               = "epoch",
        load_best_model_at_end      = True,
        metric_for_best_model       = "f1",
        greater_is_better           = True,
        logging_steps               = 10,
        seed                        = 42,
    )

    trainer = WeightedTrainer(
        class_weights   = class_weights,
        model           = model,
        args            = training_args,
        train_dataset   = train_data,
        eval_dataset    = val_data,
        compute_metrics = compute_metrics,
        callbacks       = [EarlyStoppingCallback(early_stopping_patience=2)],
    )

    try:
        trainer.train()
    except Exception as e:
        logger.error("Error durante el entrenamiento incremental: %s", e)
        if backup_path and backup_path.exists():
            if INCREMENTAL_MODEL_PATH.exists():
                shutil.rmtree(INCREMENTAL_MODEL_PATH)
            shutil.copytree(backup_path, INCREMENTAL_MODEL_PATH)
            logger.warning("Modelo restaurado desde backup: %s", backup_path)
        raise

    logger.info("=== Métricas post-incremental ===")
    results = trainer.evaluate(val_data)
    for k, v in results.items():
        logger.info("  %s: %s", k, v)

    tmp_path = INCREMENTAL_MODEL_PATH.parent / "bert_model_incremental_tmp"
    if tmp_path.exists():
        shutil.rmtree(tmp_path)

    trainer.model.save_pretrained(tmp_path)
    tokenizer.save_pretrained(tmp_path)
    logger.info("Modelo guardado en temporal: %s", tmp_path)

    if INCREMENTAL_MODEL_PATH.exists():
        shutil.rmtree(INCREMENTAL_MODEL_PATH)
    shutil.move(str(tmp_path), str(INCREMENTAL_MODEL_PATH))
    logger.info("Modelo movido a: %s", INCREMENTAL_MODEL_PATH)

    try:
        from app.services.ml_analyzer import MLAnalyzer
        MLAnalyzer.reload()
        logger.info("MLAnalyzer recargado → usando modelo incremental.")
    except Exception as e:
        logger.warning("No se pudo recargar MLAnalyzer: %s", e)

    count = get_feedback_count()
    logger.info("Feedbacks pendientes de rotar: %d / %d", count, ROTATE_EVERY)

    if count >= ROTATE_EVERY:
        logger.info("=== Umbral alcanzado → rotando modelos ===")
        rotate_models()
        mark_feedback_as_rotated()
        try:
            from app.services.ml_analyzer import MLAnalyzer
            MLAnalyzer.reload()
            logger.info("MLAnalyzer recargado tras rotación → usando nuevo base.")
        except Exception as e:
            logger.warning("No se pudo recargar MLAnalyzer tras rotación: %s", e)
        logger.info("Nuevo ciclo iniciado. Próxima rotación en %d feedbacks.", ROTATE_EVERY)
    else:
        logger.info("Rotación en %d feedbacks.", ROTATE_EVERY - count)