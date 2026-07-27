"""
Training pipeline for the AI Phishing Email Detector.
Trains a fast, reliable TF-IDF + Logistic Regression model as a fallback,
and attempts to fine-tune a HuggingFace DistilBERT classifier.
Saves model files and performance metrics for the admin dashboard.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

# Directories
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
SAVE_DIR = os.path.join(MODEL_DIR, "save")
DATASET_CSV = os.path.join(MODEL_DIR, "..", "dataset", "email_dataset.csv")

def train_sklearn_model(df):
    """Trains a TF-IDF + Logistic Regression model."""
    print("\n--- Training Fallback TF-IDF + Logistic Regression Model ---")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        df['text'], df['label'], test_size=0.2, random_state=42, stratify=df['label']
    )
    
    # Vectorize text
    vectorizer = TfidfVectorizer(max_features=5000, stop_words='english', ngram_range=(1, 2))
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    # Train Logistic Regression
    clf = LogisticRegression(class_weight='balanced', max_iter=1000)
    clf.fit(X_train_vec, y_train)
    
    # Evaluate
    y_pred = clf.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
    cm = confusion_matrix(y_test, y_pred)
    
    print(f"Logistic Regression Accuracy: {acc:.4f}")
    print(f"F1 Score (Weighted): {f1:.4f}")
    
    # Save model and vectorizer
    os.makedirs(SAVE_DIR, exist_ok=True)
    joblib.dump(clf, os.path.join(SAVE_DIR, "fallback_model.pkl"))
    joblib.dump(vectorizer, os.path.join(SAVE_DIR, "vectorizer.pkl"))
    print(f"Saved Sklearn model & vectorizer to: {SAVE_DIR}")
    
    # Label mapping
    classes = list(clf.classes_)
    
    metrics = {
        "model_name": "TF-IDF + Logistic Regression (Fallback)",
        "accuracy": float(acc),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "confusion_matrix": cm.tolist(),
        "classes": classes
    }
    
    with open(os.path.join(SAVE_DIR, "fallback_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=4)
        
    return metrics

def train_transformer_model(df):
    """Attempts to train a DistilBERT model using PyTorch and HuggingFace Transformers."""
    print("\n--- Training Transformer (DistilBERT) Model ---")
    try:
        import torch
        from torch.utils.data import Dataset, DataLoader
        from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification, AdamW
    except ImportError:
        print("WARNING: PyTorch or HuggingFace Transformers not installed.")
        print("Skipping DistilBERT training. Fallback model will be used in deployment.")
        return None

    # Set device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")

    # Prepare labels (phishing: 0, spam: 1, legitimate: 2)
    label_map = {"phishing": 0, "spam": 1, "legitimate": 2}
    df['label_idx'] = df['label'].map(label_map)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        df['text'].tolist(), df['label_idx'].tolist(), test_size=0.2, random_state=42, stratify=df['label_idx']
    )

    # Tokenizer
    try:
        tokenizer = DistilBertTokenizerFast.from_pretrained('distilbert-base-uncased')
    except Exception as e:
        print(f"Could not load pre-trained tokenizer: {e}. Skipping transformer training.")
        return None

    # Dataset helper class
    class EmailDataset(Dataset):
        def __init__(self, texts, labels, tokenizer, max_len=256):
            self.encodings = tokenizer(texts, truncation=True, padding=True, max_length=max_len, return_tensors="pt")
            self.labels = torch.tensor(labels)

        def __getitem__(self, idx):
            item = {key: val[idx] for key, val in self.encodings.items()}
            item['labels'] = self.labels[idx]
            return item

        def __len__(self):
            return len(self.labels)

    train_dataset = EmailDataset(X_train, y_train, tokenizer)
    test_dataset = EmailDataset(X_test, y_test, tokenizer)

    train_loader = DataLoader(train_dataset, batch_size=8, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=8, shuffle=False)

    # Load Model
    model = DistilBertForSequenceClassification.from_pretrained('distilbert-base-uncased', num_labels=3)
    model.to(device)

    # Optimizer
    optimizer = AdamW(model.parameters(), lr=5e-5)

    # Simple training loop (1 epoch for synthetic data speed)
    model.train()
    print("Fine-tuning DistilBERT model (1 epoch)...")
    for epoch in range(1):
        for batch in train_loader:
            optimizer.zero_grad()
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)
            
            outputs = model(input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss
            loss.backward()
            optimizer.step()
            
    # Evaluation
    model.eval()
    all_preds = []
    all_labels = []
    
    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)
            
            outputs = model(input_ids, attention_mask=attention_mask)
            preds = torch.argmax(outputs.logits, dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    # Compute metrics
    acc = accuracy_score(all_labels, all_preds)
    precision, recall, f1, _ = precision_recall_fscore_support(all_labels, all_preds, average='weighted')
    cm = confusion_matrix(all_labels, all_preds)
    
    print(f"DistilBERT Accuracy: {acc:.4f}")
    print(f"DistilBERT F1 Score: {f1:.4f}")
    
    # Save Model
    distilbert_save_path = os.path.join(SAVE_DIR, "distilbert")
    os.makedirs(distilbert_save_path, exist_ok=True)
    model.save_pretrained(distilbert_save_path)
    tokenizer.save_pretrained(distilbert_save_path)
    print(f"Saved DistilBERT model to: {distilbert_save_path}")

    # Metrics
    metrics = {
        "model_name": "DistilBERT (Transformer)",
        "accuracy": float(acc),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "confusion_matrix": cm.tolist(),
        "classes": ["phishing", "spam", "legitimate"]
    }
    
    with open(os.path.join(SAVE_DIR, "distilbert_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=4)

    return metrics

def main():
    if not os.path.exists(DATASET_CSV):
        print(f"Dataset not found at {DATASET_CSV}. Please run download_dataset.py first.")
        sys.exit(1)
        
    df = pd.read_csv(DATASET_CSV)
    
    # 1. Train Scikit-Learn fallback
    sklearn_metrics = train_sklearn_model(df)
    
    # 2. Try training transformer
    tf_metrics = train_transformer_model(df)
    
    # Save summary report for dashboard comparison
    summary = {
        "fallback": sklearn_metrics,
        "transformer": tf_metrics if tf_metrics else {"status": "Not trained (missing dependencies or environment limit)"}
    }
    
    with open(os.path.join(SAVE_DIR, "model_summary.json"), "w") as f:
        json.dump(summary, f, indent=4)
        
    print("\nTraining Pipeline Finished Successfully!")

if __name__ == "__main__":
    main()
