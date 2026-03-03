from fastapi import FastAPI, HTTPException

from app.config import get_settings
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.service import LogAnalysisService

settings = get_settings()
service = LogAnalysisService(settings=settings)

app = FastAPI(title=settings.app_name)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_logs(payload: AnalyzeRequest) -> AnalyzeResponse:
    try:
        return await service.analyze_file(
            file_path=payload.file_path,
            max_lines=payload.max_lines,
            send_telegram=payload.send_telegram,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc

