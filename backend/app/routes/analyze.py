from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from ..models.request_model import AnalyzeRequest
from ..services.analysis_service import AnalysisService

router = APIRouter()


@router.post("/analyze")
def analyze_endpoint(request: AnalyzeRequest):
    """
    Endpoint de análisis de código PHP.

    No usamos response_model=AnalyzeResponse porque Pydantic filtraría
    campos del dict de vulnerabilidades que no estén declarados en el modelo,
    lo que causaba que el frontend nunca recibiera tipo, impacto, solucion, etc.
    Devolvemos JSONResponse directamente para que el dict llegue íntegro.
    """
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="El código no puede estar vacío.")

    try:
        result = AnalysisService.analyze(request.code)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

    # Garantizamos que vulnerabilities sea siempre una lista serializable
    vulns = result.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        vulns = []

    payload = {
        "is_secure":       result.get("is_secure"),
        "risk_level":      result.get("risk_level", "indeterminado"),
        "confidence":      result.get("confidence", 0.0),
        "explanation":     result.get("explanation", []),
        "vulnerabilities": vulns,
    }

    return JSONResponse(content=payload)
