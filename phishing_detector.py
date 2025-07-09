from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import numpy as np
import re
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingDetector:
    def __init__(self):
        """Initialize the phishing detector with DistilBERT model"""
        try:
            # Load DistilBERT model and tokenizer from Hugging Face
            logger.info("Starting to load phishing detection model...")
            logger.info("Loading model from Hugging Face...")
            self.model = AutoModelForSequenceClassification.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.4.1")
            logger.info("Model loaded successfully")
            
            logger.info("Loading tokenizer from Hugging Face...")
            self.tokenizer = AutoTokenizer.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.4.1")
            logger.info("Tokenizer loaded successfully")
            
            logger.info("Phishing detector initialized successfully")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise

    def _clean_text(self, text):
        """Clean and preprocess text"""
        text = str(text).lower()
        text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    def _extract_features(self, text):
        """Extract features from text"""
        # Clean the input text
        text = self._clean_text(text)
        
        # Tokenize and encode
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=512
        )
        
        return inputs

    def predict(self, text):
        """Predict if text is phishing"""
        try:
            # Prepare input
            inputs = self._extract_features(text)
            
            # Get model prediction
            with torch.no_grad():
                outputs = self.model(**inputs)
                
            # Get probabilities
            probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
            probabilities = probabilities.numpy()[0]
            
            # Get prediction
            predicted_class = np.argmax(probabilities)
            confidence = float(probabilities[predicted_class])
            
            # Map class to label
            label = "Phishing" if predicted_class == 1 else "Not Phishing"
            
            return {
                'prediction': label,
                'confidence': confidence,
                'is_phishing': predicted_class == 1
            }
            
        except Exception as e:
            print(f"Error during prediction: {str(e)}")
            return {
                'prediction': 'Error',
                'confidence': 0.0,
                'is_phishing': False
            }
