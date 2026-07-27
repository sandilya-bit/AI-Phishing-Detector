"""
Machine Learning Inference Service for PhishGuard AI.
Loads the fine-tuned DistilBERT model or falls back to the fast Scikit-Learn TF-IDF model.
Includes local prediction caching for high performance.
"""

import os
import time
import joblib
import numpy as np
from utils.helpers import logger
from backend.core.config import settings

class MLService:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.transformer_model = None
        self.transformer_tokenizer = None
        self.cache = {}
        
        # Load models
        self._load_fallback_model()
        self._load_transformer_model()
        
    def _load_fallback_model(self):
        """Loads the Scikit-Learn fallback model."""
        try:
            if os.path.exists(settings.FALLBACK_MODEL_PATH) and os.path.exists(settings.VECTORIZER_PATH):
                self.model = joblib.load(settings.FALLBACK_MODEL_PATH)
                self.vectorizer = joblib.load(settings.VECTORIZER_PATH)
                logger.info("Successfully loaded fallback Logistic Regression model and vectorizer.")
            else:
                logger.warning("Fallback model files not found. Inference will fall back to heuristics.")
        except Exception as e:
            logger.error(f"Error loading fallback model: {e}")

    def _load_transformer_model(self):
        """Attempts to load the DistilBERT model and tokenizer."""
        if not os.path.exists(settings.TRANSFORMER_MODEL_PATH):
            logger.info("DistilBERT model files not found. Using Logistic Regression for machine learning classification.")
            return

        try:
            import torch
            from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
            
            self.transformer_tokenizer = DistilBertTokenizerFast.from_pretrained(settings.TRANSFORMER_MODEL_PATH)
            self.transformer_model = DistilBertForSequenceClassification.from_pretrained(settings.TRANSFORMER_MODEL_PATH)
            
            # Use CPU by default, fall back if CUDA is configured
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            self.transformer_model.to(self.device)
            self.transformer_model.eval()
            logger.info(f"Successfully loaded DistilBERT model on device: {self.device}")
        except Exception as e:
            logger.warning(f"Could not load DistilBERT model: {e}. Fallback ML model will be utilized.")

    def predict(self, text: str) -> dict:
        """Classifies the email text and returns predictions, confidence, and model info."""
        if not text or not text.strip():
            return {
                "label": "legitimate",
                "confidence": 1.0,
                "probabilities": {"phishing": 0.0, "spam": 0.0, "legitimate": 1.0},
                "prediction_time_ms": 0.0,
                "model_used": "None"
            }

        # Check Cache
        text_hash = hash(text)
        if text_hash in self.cache:
            logger.info("Prediction retrieved from local cache.")
            return self.cache[text_hash]

        start_time = time.perf_counter()

        # 1. Attempt Transformer Inference
        if self.transformer_model and self.transformer_tokenizer:
            try:
                import torch
                
                inputs = self.transformer_tokenizer(
                    text, truncation=True, padding=True, max_length=512, return_tensors="pt"
                ).to(self.device)
                
                with torch.no_grad():
                    outputs = self.transformer_model(**inputs)
                    logits = outputs.logits.cpu().numpy()[0]
                    
                # Compute Softmax
                exp_logits = np.exp(logits - np.max(logits))
                probs = exp_logits / np.sum(exp_logits)
                
                classes = ["phishing", "spam", "legitimate"]
                probabilities = {classes[i]: float(probs[i]) for i in range(3)}
                pred_idx = int(np.argmax(probs))
                pred_label = classes[pred_idx]
                confidence = float(probs[pred_idx])
                
                end_time = time.perf_counter()
                prediction_time_ms = (end_time - start_time) * 1000
                
                result = {
                    "label": pred_label,
                    "confidence": confidence,
                    "probabilities": probabilities,
                    "prediction_time_ms": round(prediction_time_ms, 2),
                    "model_used": "DistilBERT (Transformer)"
                }
                
                self.cache[text_hash] = result
                return result
            except Exception as e:
                logger.error(f"DistilBERT inference error: {e}. Cascading to Sklearn model.")

        # 2. Fall back to Scikit-Learn Model
        if self.model and self.vectorizer:
            try:
                # Vectorize and predict
                vec_text = self.vectorizer.transform([text])
                probs = self.model.predict_proba(vec_text)[0]
                classes = list(self.model.classes_)
                
                probabilities = {classes[i]: float(probs[i]) for i in range(len(classes))}
                pred_label = str(self.model.predict(vec_text)[0])
                confidence = float(probabilities[pred_label])
                
                end_time = time.perf_counter()
                prediction_time_ms = (end_time - start_time) * 1000
                
                result = {
                    "label": pred_label,
                    "confidence": confidence,
                    "probabilities": probabilities,
                    "prediction_time_ms": round(prediction_time_ms, 2),
                    "model_used": "TF-IDF + Logistic Regression (Fallback)"
                }
                
                self.cache[text_hash] = result
                return result
            except Exception as e:
                logger.error(f"Fallback model inference error: {e}")

        # 3. Last Resort: Simple rule-based prediction if no models load
        logger.warning("No ML models available for prediction. Using basic heuristics classification.")
        # Simple heuristic classification
        phish_keywords = ["verify", "bank", "password", "suspended", "urgent", "invoice", "ebay", "paypal", "chase", "log in"]
        spam_keywords = ["buy", "discount", "viagra", "money", "win", "lottery", "replica", "weight loss"]
        
        text_lower = text.lower()
        phish_count = sum(1 for kw in phish_keywords if kw in text_lower)
        spam_count = sum(1 for kw in spam_keywords if kw in text_lower)
        
        if phish_count > spam_count and phish_count > 0:
            pred_label = "phishing"
            confidence = 0.65 + min(phish_count * 0.05, 0.3)
        elif spam_count > 0:
            pred_label = "spam"
            confidence = 0.60 + min(spam_count * 0.05, 0.3)
        else:
            pred_label = "legitimate"
            confidence = 0.85
            
        probs = {
            "phishing": confidence if pred_label == "phishing" else (1 - confidence) / 2,
            "spam": confidence if pred_label == "spam" else (1 - confidence) / 2,
            "legitimate": confidence if pred_label == "legitimate" else (1 - confidence) / 2
        }
        # Normalize
        total = sum(probs.values())
        probs = {k: v / total for k, v in probs.items()}
        
        end_time = time.perf_counter()
        prediction_time_ms = (end_time - start_time) * 1000
        
        result = {
            "label": pred_label,
            "confidence": confidence,
            "probabilities": probs,
            "prediction_time_ms": round(prediction_time_ms, 2),
            "model_used": "Heuristic Model (Last Resort)"
        }
        
        self.cache[text_hash] = result
        return result
