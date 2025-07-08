from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import numpy as np
import re

class PhishingDetector:
    def __init__(self):
        """Initialize the phishing detector with BERT model"""
        try:
            # Load BERT model and tokenizer
            self.model = AutoModelForSequenceClassification.from_pretrained("ealvaradob/bert-finetuned-phishing")
            self.tokenizer = AutoTokenizer.from_pretrained("ealvaradob/bert-finetuned-phishing")
            print("Phishing detector model loaded successfully")
        except Exception as e:
            print(f"Error loading model: {str(e)}")
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
