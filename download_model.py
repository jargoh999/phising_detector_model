from transformers import AutoModelForSequenceClassification, AutoTokenizer
import os
import shutil

# Create models directory if it doesn't exist
if not os.path.exists('models'):
    os.makedirs('models')

# Download and save model and tokenizer
print("Downloading model...")
model = AutoModelForSequenceClassification.from_pretrained("ealvaradob/bert-finetuned-phishing")
model.save_pretrained('models/phishing_bert')

print("Downloading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained("ealvaradob/bert-finetuned-phishing")
tokenizer.save_pretrained('models/phishing_bert')

print("Model and tokenizer downloaded successfully!")
