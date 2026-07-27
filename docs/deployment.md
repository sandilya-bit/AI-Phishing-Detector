# Deployment Guide

This document outlines deployment configurations for various hosting environments.

## Docker Deployment (Self-Hosted / VPS)

To build and run the multi-container configuration locally or on a virtual private server:

```bash
# Clone the repository
git clone https://github.com/your-portfolio/AI_Phishing_Email_Detector.git
cd AI_Phishing_Email_Detector

# Launch services via docker-compose
docker-compose up --build -d
```

- **FastAPI Dashboard**: Access at `http://localhost:8000`
- **Streamlit Demo**: Access at `http://localhost:8501`

---

## Render Deployment (Free Tier Cloud)

Render is ideal for hosting the FastAPI backend and static files as a Web Service.

1. **Create Web Service**: Connect your GitHub repository to Render.
2. **Environment**: Select `Python 3` or `Docker`.
3. **Build Command**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Start Command**:
   ```bash
   uvicorn backend.main:app --host 0.0.0.0 --port $PORT
   ```
5. **Environment Variables**:
   - `ADMIN_USERNAME`: Set admin identifier.
   - `ADMIN_PASSWORD`: Set admin password.

> [!NOTE]
> Since the Render free tier has memory limits (512MB RAM), the application will automatically fall back to the fast Scikit-Learn model, ensuring 100% uptime with minimal memory usage.

---

## HuggingFace Spaces (Model Showcase)

HuggingFace Spaces is great for hosting the Streamlit app.

1. Create a new Space on HuggingFace and select **Streamlit** as the SDK.
2. Commit the codebase to the space repository.
3. Define the Space entrypoint as `frontend/streamlit_app.py`.
4. Define Space environment variables:
   - `BACKEND_API_URL`: Point to your hosted FastAPI endpoint on Render.
