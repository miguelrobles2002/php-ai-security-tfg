from pydantic import BaseModel
from typing import Optional, List, Any


class Vulnerabilidad(BaseModel):
    # ── Campos que renderiza mostrarVulnerabilidades() en el frontend ──
    tipo:            str
    linea:           int
    severidad:       str            # "Crítica" | "Alta" | "Media" | "Baja"
    cwe:             str            # "CWE-89"
    owasp:           str            # "A03:2021"
    confianza:       str            # "87%"
    codigo:          str            # línea PHP afectada
    descripcion:     str
    impacto:         str
    solucion:        str
    ejemplo_seguro:  str
    # ── Metadatos internos (no renderizados pero útiles) ──
    cvss_base:       float  = 0.0
    cadena_taint:    List[str] = []
    sink:            str    = ""

    class Config:
        # Permite campos extra del analyzer sin lanzar error
        extra = "ignore"


class AnalyzeResponse(BaseModel):
    is_secure:       Optional[bool]
    risk_level:      str
    confidence:      float
    explanation:     List[str]
    vulnerabilities: List[Vulnerabilidad]
