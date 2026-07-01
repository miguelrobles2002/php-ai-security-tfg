import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


class DecisionEngine:

    @staticmethod
    def evaluate(
        static_results: List[Dict],
        ml_label:       int,
        ml_confidence:  float   # confianza real del modelo, no hardcodeada
    ) -> Dict:

        explanation = []
        CONFIDENCE_THRESHOLD = 0.65

        low_confidence = ml_confidence < CONFIDENCE_THRESHOLD

        if static_results:
            explanation.append("Se detectaron vulnerabilidades mediante análisis estático.")
            if ml_label == 0:
                explanation.append(
                    "Discrepancia: el modelo de IA no detectó vulnerabilidad "
                    "pero el análisis estático sí."
                )
            return {
                "is_secure":  False,
                "risk_level": "alto",
                "confidence": ml_confidence,
                "explanation": explanation
            }

        if ml_label == 2:
            explanation.append(
                "El contenido no parece ser código PHP y no puede evaluarse."
            )
            return {
                "is_secure":  None,
                "risk_level": "indeterminado",
                "confidence": ml_confidence,
                "explanation": explanation
            }

        if ml_label == 1:
            if low_confidence:
                explanation.append(
                    f"El modelo detecta posible vulnerabilidad "
                    f"pero con baja confianza ({ml_confidence:.0%}). "
                    "Se recomienda revisión manual."
                )
                return {
                    "is_secure":  None,
                    "risk_level": "indeterminado",
                    "confidence": ml_confidence,
                    "explanation": explanation
                }
            explanation.append("El modelo de IA clasifica el código como potencialmente vulnerable.")
            return {
                "is_secure":  False,
                "risk_level": "medio",
                "confidence": ml_confidence,
                "explanation": explanation
            }

        if low_confidence:
            explanation.append(
                f"El modelo clasifica el código como seguro "
                f"pero con baja confianza ({ml_confidence:.0%}). "
                "Se recomienda revisión manual."
            )
            return {
                "is_secure":  None,
                "risk_level": "indeterminado",
                "confidence": ml_confidence,
                "explanation": explanation
            }

        explanation.append("No se detectaron patrones vulnerables.")
        return {
            "is_secure":  True,
            "risk_level": "bajo",
            "confidence": ml_confidence,
            "explanation": explanation
        }