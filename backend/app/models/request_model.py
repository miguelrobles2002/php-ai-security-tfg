from pydantic import BaseModel

class AnalyzeRequest(BaseModel):
    code: str
