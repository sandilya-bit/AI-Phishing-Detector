# Model Training Guide

PhishGuard AI uses a dual-engine architecture to ensure deep-learning accuracy when GPU/RAM resources are available, and fast CPU performance when running on constrained servers.

## Model Summary

- **Primary Model**: HuggingFace DistilBERT (`distilbert-base-uncased`) - Fine-tuned transformer for advanced contextual classification.
- **Fallback Model**: TF-IDF Vectorizer + Logistic Regression Classifier - Fast, resource-friendly, trained in seconds.

---

## Running the Training Pipeline

To run the training pipeline locally:

1. **Generate/Fetch Dataset**:
   This compiles a balanced dataset of phishing, spam, and legitimate emails and saves it as `dataset/email_dataset.csv`.
   ```bash
   py dataset/download_dataset.py
   ```

2. **Run Training**:
   This script trains the fallback model and fine-tunes the DistilBERT transformer (if PyTorch and transformers are installed).
   ```bash
   py model/train.py
   ```

3. **Generate Evaluation Metrics**:
   This runs model tests against hold-out sets, evaluates ROC curves, and writes coordinate matrices to `model/save/evaluation_curves.json`.
   ```bash
   py model/evaluate.py
   ```

---

## Fine-tuning with External Datasets

To fine-tune using larger public datasets (e.g. HuggingFace SMS Spam or Phishing datasets), update `dataset/download_dataset.py` to import datasets directly:

```python
from datasets import load_dataset

# Load SMS Spam classification dataset
dataset = load_dataset("ucirvine/sms_spam")
# Convert to pandas and map columns to 'text' and 'label'
```
The model training script will automatically adapt to any training corpus with 'text' and 'label' columns, making it extremely easy to extend.
