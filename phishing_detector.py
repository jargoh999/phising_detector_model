from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import numpy as np
import re
import os
import logging
import time
import streamlit as st

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Cache the model loading with a custom cache key
@st.cache_resource(show_spinner="Loading phishing detection model...")
def load_model():
    try:
        start_time = time.time()
        logger.info("Starting model loading...")
        
        # Load tokenizer first (it's smaller)
        tokenizer = AutoTokenizer.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.4.1")
        logger.info(f"Tokenizer loaded in {time.time() - start_time:.2f} seconds")
        
        # Load model
        model = AutoModelForSequenceClassification.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.4.1")
        logger.info(f"Model loaded in {time.time() - start_time:.2f} seconds")
        
        return model, tokenizer
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        raise

class PhishingDetector:
    def __init__(self):
        """Initialize the phishing detector with DistilBERT model"""
        try:
            # Load model and tokenizer from cache
            self.model, self.tokenizer = load_model()
            logger.info("Phishing detector initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing detector: {str(e)}")
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
