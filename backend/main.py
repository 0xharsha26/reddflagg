from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from analyzer import analyze_input
from qr_analyzer import extract_qr_data
import history_manager

from PIL import Image
import pytesseract
import io
import json
import os

app = FastAPI(title="REDDFLAGG API")
app.mount("/static", StaticFiles(directory="../frontend"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    return history_manager.load_history()


@app.delete("/history")
def clear_history():
    history_manager.clear_history_file()
    return {
        "message": "Scan history cleared",
        "history": []
    }


@app.get("/stats")
def get_stats():
    return history_manager.generate_stats()


@app.post("/analyze")
def analyze(payload: dict):
    text = payload.get("text", "")

    if not text.strip():
        return {"error": "No text provided"}

    result = analyze_input(text)
    history_manager.save_to_history(text, result)
    return result


@app.post("/analyze-image")
async def analyze_image(file: UploadFile = File(...)):
    try:
        image_bytes = await file.read()
        image = Image.open(io.BytesIO(image_bytes))

        try:
            extracted_text = pytesseract.image_to_string(image)
        except Exception as ocr_err:
            if "tesseract" in str(ocr_err).lower() or "not found" in str(ocr_err).lower():
                return {
                    "error": "Tesseract OCR engine is not installed or configured on the host system. Please install Tesseract-OCR.",
                    "extracted_text": ""
                }
            raise ocr_err

        if not extracted_text.strip():
            return {
                "error": "No readable text could be extracted from this image.",
                "extracted_text": ""
            }

        result = analyze_input(extracted_text)
        result["mode"] = "IMAGE_ANALYSIS"
        result["extracted_text"] = extracted_text

        history_manager.save_to_history("IMAGE_UPLOAD", result)
        return result

    except Exception as e:
        return {"error": f"Image analysis failed: {str(e)}"}


@app.post("/analyze-qr")
async def analyze_qr(file: UploadFile = File(...)):
    try:
        image_bytes = await file.read()
        image = Image.open(io.BytesIO(image_bytes))

        qr_results = extract_qr_data(image)

        if not qr_results or not qr_results.get("success"):
            return {
                "error": qr_results.get("message", "No QR code detected in image."),
                "qr_data": []
            }

        qr_text = qr_results.get("data", "")

        result = analyze_input(qr_text)
        result["mode"] = "QR_ANALYSIS"
        result["qr_data"] = [qr_text]

        history_manager.save_to_history(qr_text, result)
        return result

    except Exception as e:
        return {"error": f"QR analysis failed: {str(e)}"}