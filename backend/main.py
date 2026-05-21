from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from analyzer import analyze_input
from qr_analyzer import extract_qr_data

from PIL import Image
import pytesseract
import io
import json
import os
from datetime import datetime


app = FastAPI(title="REDDFLAGG API")
app.mount("/static", StaticFiles(directory="../frontend"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HISTORY_FILE = "history.json"


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r") as file:
            return json.load(file)
    except:
        return []


def save_to_history(scan_input, result):
    history = load_history()

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "input": scan_input,
        "mode": result.get("mode", "UNKNOWN"),
        "score": result.get("score", 0),
        "level": result.get("level", "UNKNOWN"),
        "explanation": result.get("explanation", "")
    }

    history.insert(0, entry)
    history = history[:50]

    with open(HISTORY_FILE, "w") as file:
        json.dump(history, file, indent=2)


def clear_history_file():
    with open(HISTORY_FILE, "w") as file:
        json.dump([], file, indent=2)


def generate_stats(history):
    total_scans = len(history)

    high_risk = sum(1 for item in history if item.get("level") == "HIGH RISK")
    suspicious = sum(1 for item in history if item.get("level") == "SUSPICIOUS")
    low_risk = sum(1 for item in history if item.get("level") == "LOW RISK")

    latest_scan = history[0] if history else None

    return {
        "total_scans": total_scans,
        "high_risk": high_risk,
        "suspicious": suspicious,
        "low_risk": low_risk,
        "latest_scan": latest_scan
    }


@app.get("/")
def root():
    return FileResponse("../frontend/index.html")


@app.get("/health")
def health_check():
    return {
        "status": "connected",
        "service": "REDDFLAGG API"
    }


@app.get("/history")
def get_history():
    return load_history()


@app.delete("/history")
def clear_history():
    clear_history_file()

    return {
        "message": "Scan history cleared",
        "history": []
    }


@app.get("/stats")
def get_stats():
    history = load_history()
    return generate_stats(history)


@app.post("/analyze")
def analyze(payload: dict):
    text = payload.get("text", "")

    if not text.strip():
        return {"error": "No text provided"}

    result = analyze_input(text)

    save_to_history(text, result)

    return result


@app.post("/analyze-image")
async def analyze_image(file: UploadFile = File(...)):
    try:
        image_bytes = await file.read()
        image = Image.open(io.BytesIO(image_bytes))

        extracted_text = pytesseract.image_to_string(image)

        if not extracted_text.strip():
            return {
                "error": "No readable text found in image",
                "extracted_text": ""
            }

        result = analyze_input(extracted_text)

        result["mode"] = "IMAGE_ANALYSIS"
        result["extracted_text"] = extracted_text

        save_to_history("IMAGE_UPLOAD", result)

        return result

    except Exception as e:
        return {"error": str(e)}


@app.post("/analyze-qr")
async def analyze_qr(file: UploadFile = File(...)):
    try:
        image_bytes = await file.read()
        image = Image.open(io.BytesIO(image_bytes))

        qr_results = extract_qr_data(image)

        if not qr_results:
            return {
                "error": "No QR code detected in image",
                "qr_data": []
            }

        qr_text = qr_results[0]

        result = analyze_input(qr_text)

        result["mode"] = "QR_ANALYSIS"
        result["qr_data"] = qr_results

        save_to_history(qr_text, result)

        return result

    except Exception as e:
        return {"error": str(e)}