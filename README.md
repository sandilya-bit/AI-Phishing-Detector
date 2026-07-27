# PhishGuard AI - AI Phishing Email Detector

[![CI/CD Pipeline](https://github.com/your-portfolio/AI_Phishing_Email_Detector/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/your-portfolio/AI_Phishing_Email_Detector/actions/workflows/ci-cd.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](requirements.txt)

PhishGuard AI is a production-quality, enterprise-grade AI-powered Phishing Email Detector web application. Featuring a modern, premium **cybersecurity dark-red/black/white theme**, it uses custom NLP heuristic engines and fine-tuned Transformer models (DistilBERT) to analyze incoming emails, flag social engineering indicators, identify spoofed domains, and explain threat decisions.

---

## Technical Visual Interface

The interface features glassmorphic dashboard controls, live gauge dials, incident timeline analytics, keyword maps, and recommendation actions.

---

## Main Features

- **Multi-Format Input**: Support for dragging and dropping `.eml`, `.txt`, and Outlook `.msg` files, or pasting text directly.
- **Explainable Threat Dashboard**: Analyzes credential harvesting keywords, urgent language, and provides a threat score (0-100) mapped to safe, medium, high, and critical levels.
- **Cybersecurity Heuristics Parser**:
  - Checks domain typosquatting (e.g. `micros0ft.com`).
  - Detects IDN homograph punycode domain spoofing.
  - Flags shortened redirect links and direct IP addresses.
  - Identifies header anomalies (From and Reply-To domain mismatches, SPF failures).
- **Interactive Analytics**: Interactive charts powered by Chart.js representing weekly detection histories, threat category distributions, and ROC accuracy comparisons.
- **Historical Auditing**: Local SQLite logs for review and filtering, supporting dynamic downloads in CSV, JSON, and PDF report formats.
- **Administrator Console**: Secure dashboard displaying system resource metrics (database file sizes, memory allocation, model footprint) and record logs flush operations.

---

## Directory Organization

```text
AI_Phishing_Email_Detector/
├── backend/
│   ├── api/v1/endpoints.py       # REST endpoint controllers
│   ├── core/config.py            # App parameters and limits
│   ├── database/                 # SQLite storage maps
│   ├── services/                 # Email parsing, heuristics, ML inference
│   ├── static/                   # HTML, CSS, JS SPA dashboard
│   ├── templates/admin.html      # Administration panel view
│   └── main.py                   # FastAPI entrypoint
├── frontend/streamlit_app.py     # Streamlit wrapper UI
├── model/                        # Training and evaluation pipelines
├── dataset/                      # Synthetic data generator and EML templates
├── tests/                        # Pytest suite
└── docs/                         # Technical manuals
```

---

## Tech Stack

- **Backend Framework**: FastAPI (Asynchronous REST API)
- **Database**: SQLite (SQLAlchemy ORM)
- **Machine Learning**: PyTorch, HuggingFace Transformers (DistilBERT), Scikit-Learn, Pandas
- **Frontend SPA**: HTML5, Vanilla CSS3 (Custom Glassmorphic variables), JavaScript (ES6, Chart.js, FontAwesome)
- **Deployment & Infra**: Docker, Docker Compose, GitHub Actions CI/CD

---

## Quickstart Guide

### Running Locally

1. **Clone & Setup Virtual Environment**:
   ```bash
   git clone https://github.com/your-portfolio/AI_Phishing_Email_Detector.git
   cd AI_Phishing_Email_Detector
   py -m venv .venv
   source .venv/Scripts/activate # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Generate Dataset & Train Fallback Classifier**:
   ```bash
   py dataset/download_dataset.py
   py model/train.py
   py model/evaluate.py
   ```

3. **Start FastAPI Application**:
   ```bash
   uvicorn backend.main:app --reload
   ```
   Open `http://localhost:8000` to view the premium dashboard.

4. **Start Streamlit Dashboard (Optional)**:
   ```bash
   streamlit run frontend/streamlit_app.py
   ```
   Open `http://localhost:8501` to view the Streamlit interface.

---

## Documentation Manuals

Explore detailed guides inside the `docs/` folder:

- 📐 **[System Architecture](docs/architecture.md)**: Deep dive into the clean services-based design.
- ⚙️ **[Local & Cloud Deployment](docs/deployment.md)**: Hosting on Docker, Render, and HuggingFace.
- 🧠 **[Model Training Manual](docs/training.md)**: Pipeline configurations, fallback architecture, and custom datasets.
- 📖 **[API Documentation](docs/api_documentation.md)**: Endpoint requests, JSON structures, and query parameters.
- 🛠️ **[Installation Guide](docs/installation_guide.md)**: Comprehensive environment setups.
- 📊 **[Dataset Description](docs/dataset_description.md)**: Dataset schemas and phishing categories.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
