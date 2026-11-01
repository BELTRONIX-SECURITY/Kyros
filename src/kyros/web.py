"""FastAPI application for the Kyros SOC web interface."""
from __future__ import annotations
import os
from pathlib import Path
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from kyros.soc import MAX_FILE_SIZE, analyze_file, classify_domain, classify_ip

STATIC_DIR = Path(__file__).parent / "static"
app = FastAPI(title="Kyros SOC API", version="0.2.0",
              description="Local-first defensive triage API. External lookups are disabled.")

class IndicatorRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=253)

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Kyros SOC", "version": "0.2.0"}

@app.post("/api/analyze/ip")
async def analyze_ip(request: IndicatorRequest):
    try:
        return classify_ip(request.indicator)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/analyze/domain")
async def analyze_domain(request: IndicatorRequest):
    try:
        return classify_domain(request.indicator)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/analyze/file")
async def analyze_uploaded_file(file: UploadFile = File(...)):
    data = await file.read(MAX_FILE_SIZE + 1)
    await file.close()
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="El tamaño máximo permitido es 10 MB.")
    try:
        return analyze_file(data, file.filename)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.get("/", include_in_schema=False)
async def dashboard():
    index = STATIC_DIR / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=404, detail="Dashboard no disponible.")
    return FileResponse(index)

def run() -> None:
    import uvicorn
    uvicorn.run("kyros.web:app", host=os.getenv("KYROS_HOST", "127.0.0.1"),
                port=int(os.getenv("KYROS_PORT", "8000")), reload=False)
