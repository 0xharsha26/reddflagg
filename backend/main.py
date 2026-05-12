from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from analyzer import analyze_input
from PIL import Image
import pytesseract
import io

app = FastAPI(title="REDDFLAGG API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {"message": "REDDFLAGG backend is running"}


@app.post("/analyze")
def analyze(payload: dict):
    text = payload.get("text", "")

    if not text.strip():
        return {"error": "No text provided"}

    result = analyze_input(text)
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

        return result

    except Exception as e:
        return {"error": str(e)}
