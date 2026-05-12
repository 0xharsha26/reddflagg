from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from analyzer import analyze_input

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
