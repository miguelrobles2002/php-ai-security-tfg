import logging
from .static_analyzer import StaticAnalyzer
from .ml_analyzer     import MLAnalyzer
from .decision_engine import DecisionEngine

logger = logging.getLogger(__name__)


class AnalysisService:

    @staticmethod
    def analyze(code: str) -> dict:
        if not isinstance(code, str):
            return AnalysisService._error_response("El input debe ser una cadena de texto.")

        code = code.strip()
        if not code:
            return AnalysisService._error_response("El código proporcionado está vacío.")
        if len(code) > 50_000:
            return AnalysisService._error_response("El código supera el límite de 50.000 caracteres.")

        # ── Análisis estático ──────────────────────────────────────────────
        try:
            static_results = StaticAnalyzer.run(code)
            if not isinstance(static_results, list):
                static_results = []
        except Exception as e:
            logger.error("Error en StaticAnalyzer: %s", e)
            static_results = []

        # ── Análisis ML ───────────────────────────────────────────────────
        try:
            ml_result  = MLAnalyzer.predict(code)
            label      = int(ml_result.get("label", 0))
            confidence = float(ml_result.get("confidence", 0.0))
            if label not in (0, 1, 2):
                raise ValueError(f"Label inesperado: {label}")
            if not (0.0 <= confidence <= 1.0):
                raise ValueError(f"Confianza fuera de rango: {confidence}")
        except Exception as e:
            logger.error("Error en MLAnalyzer: %s", e)
            label      = 0
            confidence = 0.0

        # ── Decisión ──────────────────────────────────────────────────────
        decision = DecisionEngine.evaluate(
            static_results=static_results,
            ml_label=label,
            ml_confidence=confidence,
        )

        is_secure = decision["is_secure"]

        # CORRECCIÓN CLAVE: si el analizador estático encontró vulnerabilidades,
        # el resultado NUNCA puede ser "seguro", independientemente del ML.
        # Esto es lo que causaba que el frontend no mostrase las vulns.
        if static_results and is_secure is not False:
            is_secure = False
            logger.info(
                "StaticAnalyzer encontró %d hallazgo(s); forzando is_secure=False.",
                len(static_results),
            )

        # Si label==2 (no es código) y no hay hallazgos estáticos → is_secure=None
        if label == 2 and not static_results:
            is_secure = None

        return {
            "is_secure":       is_secure,
            "risk_level":      decision["risk_level"],
            "confidence":      round(confidence, 4),
            "explanation":     decision["explanation"],
            "vulnerabilities": static_results,   # lista de dicts con todos los campos
        }

    @staticmethod
    def _error_response(reason: str) -> dict:
        logger.warning("AnalysisService input inválido: %s", reason)
        return {
            "is_secure":       None,
            "risk_level":      "indeterminado",
            "confidence":      0.0,
            "explanation":     [reason],
            "vulnerabilities": [],
        }