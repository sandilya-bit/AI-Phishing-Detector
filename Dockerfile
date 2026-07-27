# Use an official lightweight Python base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# Set workspace directory
WORKDIR /app

# Install system dependencies needed for some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source directories
COPY backend/ /app/backend/
COPY model/ /app/model/
COPY utils/ /app/utils/

# Expose port
EXPOSE 8000

# Run FastAPI using uvicorn program
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
