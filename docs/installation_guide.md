# Detailed Installation Guide

This guide describes how to configure the local development workspace environment step-by-step.

## Prerequisites

Ensure you have the following packages installed on your host system:
1. **Python (3.8 - 3.12+)**: Download from the official website.
2. **Git**: Required for cloning and version control.
3. **Docker (Optional)**: For running containers.

---

## Step 1: Clone the Project Repository

Clone the project to your local workspace:

```bash
git clone https://github.com/your-portfolio/AI_Phishing_Email_Detector.git
cd AI_Phishing_Email_Detector
```

---

## Step 2: Establish the Python Virtual Environment

Use a virtual environment to avoid conflicts with global libraries:

### On Windows
```powershell
py -m venv .venv
.venv\Scripts\activate
```

### On macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## Step 3: Install Required Dependencies

Install the packages listed in `requirements.txt` along with the testing utilities:

```bash
pip install -r requirements.txt
pip install pytest httpx
```

---

## Step 4: Run Training & Local Evaluation

Verify that the dataset generator and model training pipelines run successfully:

```bash
# 1. Compile the synthetic CSV corpus
py dataset/download_dataset.py

# 2. Train the Scikit-Learn TF-IDF classifier
py model/train.py

# 3. Create ROC curve coordinates
py model/evaluate.py
```

---

## Step 5: Start the FastAPI Server

Launch the backend FastAPI uvicorn daemon:

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser and visit `http://127.0.0.1:8000` to inspect the premium security dashboard UI.

---

## Step 6: Verify with Automated Tests

Run the full testing suite:

```bash
pytest tests/
```
All unit tests should pass.
