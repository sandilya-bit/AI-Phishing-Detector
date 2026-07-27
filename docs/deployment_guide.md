# Deployment Guide

This guide details deployment options for containerizing and hosting PhishGuard AI in cloud environments.

## Docker Deployment (Docker Compose)

To spin up the complete multi-service stack:

```bash
# Clone repository
git clone https://github.com/your-portfolio/AI_Phishing_Email_Detector.git
cd AI_Phishing_Email_Detector

# Build and start services
docker-compose up --build -d
```

- **FastAPI Dashboard Portal**: `http://localhost:8000`
- **Streamlit Demo Portal**: `http://localhost:8501`

---

## Render Deployment (FastAPI Backend)

Render is suitable for running Web Services directly from GitHub.

1. Create a new **Web Service** on Render and link your fork.
2. Configure settings:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
3. Add environment variables:
   - `ADMIN_USERNAME`: admin
   - `ADMIN_PASSWORD`: secure_password

> [!NOTE]
> Since Render's free tier has memory constraints, PhishGuard AI is designed to run the Scikit-Learn fallback model when PyTorch is not fully loaded, avoiding system memory crashes.

---

## HuggingFace Spaces (Streamlit Demo UI)

HuggingFace Spaces is great for hosting model applications.

1. Create a new Space and select **Streamlit** as the SDK.
2. Push the files to the HuggingFace git repository.
3. Configure the Space entrypoint as `frontend/streamlit_app.py`.
4. Add environment variables:
   - `BACKEND_API_URL`: Point to your hosted FastAPI endpoint on Render.
