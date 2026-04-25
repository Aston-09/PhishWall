from fastapi import FastAPI, Form, HTTPException

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List

from src.engines.url_engine import analyze_url
from src.engines.sms_engine import analyze_sms

app = FastAPI(
    title="PhishWall",
    description="Advanced Cyber Phishing & SMS Fraud Detection Engine",
    version="2.0.0"
)

# Enable CORS for Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

class ScanResponse(BaseModel):
    input: str
    result: str
    risk_score: int
    risk_level: str
    reasons: List[str]

@app.post("/scan", response_model=ScanResponse)
def scan(input_text: str = Form(...)):
    """
    Scans a URL or SMS content for phishing indicators.
    """
    if not input_text.strip():
        raise HTTPException(status_code=400, detail="Input text cannot be empty")

    # Basic routing based on content type
    if input_text.startswith("http") or input_text.startswith("www") or "." in input_text.split("/")[0]:
        risk_score, reasons = analyze_url(input_text)
    else:
        risk_score, reasons = analyze_sms(input_text)

    # Determine risk level
    if risk_score >= 60:
        result = "PHISHING / FRAUD"
        risk_level = "HIGH"
    elif risk_score >= 30:
        result = "SUSPICIOUS"
        risk_level = "MEDIUM"
    else:
        result = "SAFE"
        risk_level = "LOW"

    return {
        "input": input_text,
        "result": result,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons
    }

@app.get("/", response_class=HTMLResponse)
def home():
    """
    Serves the PhishWall Pro frontend.
    """
    try:
        with open("static/index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Frontend Not Found</h1>", status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
