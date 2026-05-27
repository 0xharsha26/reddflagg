# Use official lightweight Python image
FROM python:3.12-slim

# Set environment variables (7860 is default for Hugging Face, Render overrides via env)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=7860

# Set working directory
WORKDIR /app

# Install system dependencies (libzbar for QR, tesseract for OCR, MesaGL/Glib for OpenCV)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    tesseract-ocr \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user (UID 1000 is required by Hugging Face Spaces)
RUN useradd -m -u 1000 user

# Copy requirements first to leverage Docker cache
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy all source files
COPY backend /app/backend
COPY frontend /app/frontend

# Set ownership of the app directory to the non-root user to avoid permission errors on history.json
RUN chown -R user:user /app

# Switch to the non-root user
USER user

# Change working directory to backend to run FastAPI
WORKDIR /app/backend

# Expose port and run uvicorn server
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT}
