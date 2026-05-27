# Use official lightweight Python image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=10000

# Set working directory
WORKDIR /app

# Install system dependencies (libzbar for QR, tesseract for OCR, MesaGL/Glib for OpenCV)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    tesseract-ocr \
    libgl1-mesa-glx \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy all source files
COPY backend /app/backend
COPY frontend /app/frontend

# Change working directory to backend to run FastAPI
WORKDIR /app/backend

# Expose port and run uvicorn server
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT}
