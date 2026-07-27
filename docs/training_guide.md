# Model Training Guide

This guide details the processes for compiling datasets, training standard fallback classifiers, and fine-tuning DistilBERT transformer models.

## Training Architecture

PhishGuard AI uses a dual-engine machine learning configuration:
- **Primary Model**: HuggingFace `distilbert-base-uncased` Sequence Classification transformer (for contextual threat parsing).
- **Fallback Model**: Scikit-Learn TF-IDF vectorizer + Logistic Regression classifier (for resource-limited deployments).

---

## 1. Preparing the Corpus
Run the downloader/generator script:
```bash
py dataset/download_dataset.py
```
This generates `dataset/email_dataset.csv` with a balanced distribution of phishing, spam, and legitimate templates.

## 2. Running the Training Pipeline
Trigger the training pipeline script:
```bash
py model/train.py
```
The script will:
- Train the fallback Logistic Regression model and serialize it to `model/save/fallback_model.pkl`.
- Attempt to fine-tune the DistilBERT model (if PyTorch and Transformers are installed) and save weights to `model/save/distilbert/`.

## 3. Running Model Evaluation
Compute confusion matrices and ROC coordinate data:
```bash
py model/evaluate.py
```
This updates the analytics files, enabling the frontend dashboard to render comparative ROC curves dynamically.
