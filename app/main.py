import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException

from app.config import get_settings
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.service import LogAnalysisService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger.info(f"Dastur ishga tushdi: {settings.app_name}")
    yield
    logger.info("Dastur to'xtatilmoqda...")


app = FastAPI(
    title=get_settings().app_name,
    description="Wazuh loglarini AI yordamida tahlil qilish va Telegram xabarnoma yuborish",
    version="1.0.0",
    lifespan=lifespan,
)


def get_service() -> LogAnalysisService:
    return LogAnalysisService(settings=get_settings())


@app.get("/health", tags=["System"])
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "active"}


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_logs(
    payload: AnalyzeRequest,
    service: LogAnalysisService = Depends(get_service),
) -> AnalyzeResponse:
    try:
        return await service.analyze_file(
            file_path=payload.file_path,
            max_lines=payload.max_lines,
            send_telegram=payload.send_telegram,
        )
    except FileNotFoundError as exc:
        logger.error(f"Fayl topilmadi: {exc}")
        raise HTTPException(status_code=404, detail=f"Log fayli topilmadi: {str(exc)}")
    except Exception as exc:
        logger.error(f"Kutilmagan xatolik: {exc}")
        raise HTTPException(status_code=500, detail=f"Tahlil jarayonida xatolik: {str(exc)}")