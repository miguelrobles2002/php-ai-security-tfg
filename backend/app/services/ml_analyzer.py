import os
from pathlib import Path
from functools import lru_cache
from typing import Dict
import logging

import torch
import torch.nn.functional as F
from transformers import AutoModelForSequenceClassification, AutoTokenizer

logger = logging.getLogger(__name__)

BASE_MODEL_PATH        = Path("app/models/bert_model")
INCREMENTAL_MODEL_PATH = Path("app/models/bert_model_incremental")

HF_MODEL_ID = os.environ.get("HF_MODEL_ID", "R0bl3s/php-vuln-detector")
HF_TOKEN    = os.environ.get("HF_TOKEN", "")

LABEL_NAMES = {0: "secure", 1: "vulnerable", 2: "not_php"}


def _has_weights(path: Path) -> bool:
    """Comprueba si una carpeta tiene pesos del modelo."""
    if not path.exists():
        return False
    weights = (
        list(path.glob("model.safetensors")) +
        list(path.glob("pytorch_model.bin"))
    )
    return bool(weights)


def _download_from_huggingface() -> Path:
    """Descarga el modelo desde Hugging Face Hub a la carpeta incremental."""
    try:
        from huggingface_hub import snapshot_download
        logger.info("Descargando modelo desde Hugging Face: %s", HF_MODEL_ID)
        INCREMENTAL_MODEL_PATH.mkdir(parents=True, exist_ok=True)
        snapshot_download(
            repo_id=HF_MODEL_ID,
            token=HF_TOKEN if HF_TOKEN else None,
            local_dir=str(INCREMENTAL_MODEL_PATH),
        )
        logger.info("Modelo descargado correctamente en %s", INCREMENTAL_MODEL_PATH)
        return INCREMENTAL_MODEL_PATH
    except Exception as e:
        raise RuntimeError(f"No se pudo descargar el modelo de Hugging Face: {e}")


def _get_active_model_path() -> Path:
    """
    Prioridad: incremental (si tiene pesos) → base → descarga de HuggingFace.
    """
    for path in (INCREMENTAL_MODEL_PATH, BASE_MODEL_PATH):
        if _has_weights(path):
            logger.info("Modelo activo encontrado localmente: %s", path)
            return path

    # No hay modelo local → descargar de Hugging Face
    logger.warning(
        "No se encontró modelo local en '%s' ni en '%s'. "
        "Descargando desde Hugging Face...",
        INCREMENTAL_MODEL_PATH, BASE_MODEL_PATH
    )
    return _download_from_huggingface()


class MLAnalyzer:

    @staticmethod
    @lru_cache(maxsize=1)
    def _load_model():
        model_path = _get_active_model_path()
        logger.info("Cargando modelo DistilBERT desde %s", model_path)
        tokenizer = AutoTokenizer.from_pretrained(str(model_path))
        model     = AutoModelForSequenceClassification.from_pretrained(str(model_path))
        model.eval()
        logger.info("Modelo cargado correctamente.")
        return model, tokenizer

    @classmethod
    def reload(cls):
        """
        Limpia la cache del modelo en memoria.
        La siguiente llamada a predict() cargará el modelo más reciente
        sin necesidad de reiniciar el servidor.
        Llamar tras train_incremental() y tras rotate_models().
        """
        cls._load_model.cache_clear()
        logger.info("Cache del modelo limpiada. Se recargará en la próxima predicción.")

    @classmethod
    def predict(cls, code: str) -> Dict:
        model, tokenizer = cls._load_model()

        inputs = tokenizer(
            code,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512
        )

        with torch.no_grad():
            outputs = model(**inputs)

        probs = F.softmax(outputs.logits, dim=1)
        confidence, predicted_class = torch.max(probs, dim=1)

        label      = int(predicted_class.item())
        probs_list = probs.squeeze().tolist()

        return {
            "label":         label,
            "label_name":    LABEL_NAMES.get(label, "unknown"),
            "confidence":    round(float(confidence.item()), 4),
            "probabilities": {
                "secure":     round(probs_list[0], 4),
                "vulnerable": round(probs_list[1], 4),
                "not_php":    round(probs_list[2], 4),
            }
        }
