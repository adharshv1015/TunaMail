from fastapi import APIRouter, UploadFile, File
from src.engines.analyzer import EmailAnalyzer
from src.connectors.upload_connector import UploadConnector


router = APIRouter()

@router.get("/health")
def health():

    return {
        "status": "healthy",
        "service": "TunaMail API"
    }


@router.post("/analyze")
async def analyze_email(
    file: UploadFile = File(...)
):

    connector = UploadConnector()

    email = await connector.get_email(file)

    analyzer = EmailAnalyzer()

    analysis = analyzer.analyze(email["path"])

    return {
        "status": "analyzed",
        "file_id": email["id"],
        "filename": email["filename"],
        "analysis": analysis
    }
