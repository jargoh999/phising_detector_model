import streamlit as st
import torch
from transformers import RobertaTokenizerFast, RobertaForSequenceClassification
import validators
import re
from urllib.parse import urlparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set page config
st.set_page_config(page_title="Phishing Detector", layout="wide")

@st.cache_resource(show_spinner="Loading ScamLLM model...")
def load_model():
    """Load the ScamLLM phishing detection model."""
    try:
        model_name = "phishbot/ScamLLM"
        logger.info(f"Loading model: {model_name}")
        
        # Load tokenizer and model
        tokenizer = RobertaTokenizerFast.from_pretrained(model_name)
        model = RobertaForSequenceClassification.from_pretrained(model_name)
        
        logger.info("Model loaded successfully")
        return model, tokenizer
        
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        st.error(f"Failed to load model: {str(e)}")
        raise

def predict(text, model, tokenizer):
    """Predict whether text is phishing or safe."""
    try:
        logger.info(f"Analyzing text: {text[:50]}...")
        
        # Tokenize input
        inputs = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True
        )
        
        # Get prediction
        with torch.no_grad():
            outputs = model(**inputs)
            predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
        # Get probabilities for each class
        probs = predictions[0].tolist()
        
        # Since this model is trained on scam detection, we'll use the highest probability
        # and map it to phishing/safe based on the class
        max_prob = max(probs)
        max_idx = probs.index(max_prob)
        
        # ScamLLM is trained on scam detection, so we'll map it to phishing/safe
        if max_idx == 1:  # Assuming 1 is the scam/phishing class
            return "Phishing", max_prob
        else:
            return "Safe", max_prob
            
    except Exception as e:
        logger.error(f"Error during prediction: {str(e)}")
        st.error(f"Error analyzing text: {str(e)}")
        return None, 0.0

def predict(text, model, tokenizer):
    """Predict whether text is phishing or safe."""
    try:
        logger.info(f"Analyzing text: {text[:50]}...")
        
        # Tokenize input
        inputs = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True
        )
        
        # Get model predictions
        with torch.no_grad():
            outputs = model(**inputs)
            
        # Process outputs
        logits = outputs.logits
        probabilities = torch.nn.functional.softmax(logits, dim=1)
        predicted_class = torch.argmax(probabilities).item()
        confidence = torch.max(probabilities).item()
        
        logger.info(f"Prediction: {'Phishing' if predicted_class == 1 else 'Safe'} with confidence: {confidence:.2f}")
        return "Phishing" if predicted_class == 1 else "Safe", confidence
        
    except Exception as e:
        logger.error(f"Error during prediction: {str(e)}")
        st.error(f"Error analyzing text: {str(e)}")
        return None, 0.0
    logits = outputs.logits
    probabilities = torch.nn.functional.softmax(logits, dim=1)
    predicted_class = torch.argmax(probabilities).item()
    confidence = torch.max(probabilities).item()
    return "Phishing" if predicted_class == 1 else "Safe", confidence

def analyze_url(url):
    """Analyze URL for basic phishing indicators."""
    try:
        # Basic URL validation
        if not validators.url(url):
            return False, "Invalid URL format"
            
        # Extract domain
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Basic checks for phishing indicators
        if any(substr in domain.lower() for substr in ['login', 'verify', 'secure', 'update']):
            return True, "Suspicious domain name"
            
        # Check for IP addresses instead of domain names
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            return True, "Uses IP address instead of domain"
            
        return False, "No obvious phishing indicators"
        
    except Exception as e:
        return False, f"Error analyzing URL: {str(e)}"

def main():
    """Main application function."""
    st.title("🛡️ Phishing Detector")
    st.markdown("""
    This tool helps detect phishing attempts in URLs and text content using AI.
    Enter a URL or text below to analyze for potential phishing indicators.
    """)
    
    # Load model
    with st.spinner("Loading phishing detection model..."):
        model, tokenizer = load_model()
    
    # Create tabs
    tab1, tab2 = st.tabs(["URL Analysis", "Text Analysis"])
    
    with tab1:
        st.header("🔍 URL Analysis")
        
        # Example URLs
        example_urls = {
            "Safe Example": "https://www.paypal.com/myaccount/activity",
            "Phishing Example": "https://secure-paypal-login.com/update-account",
            "Suspicious Example": "http://192.168.1.100/paypal-login",
            "Common Phishing Pattern": "https://paypal-security-verification.com/verify-account"
        }
        
        # URL selection
        url_type = st.selectbox(
            "Select example URL or enter your own:",
            ["Enter custom URL"] + list(example_urls.keys())
        )
        
        # Set URL input based on selection
        if url_type != "Enter custom URL":
            url_input = st.text_input(
                "Enter URL to analyze:",
                value=example_urls[url_type],
                placeholder="https://example.com/login"
            )
        else:
            url_input = st.text_input(
                "Enter URL to analyze:",
                placeholder="https://example.com/login"
            )
        
        if st.button("Analyze URL"):
            if url_input.strip():
                with st.spinner("Analyzing URL..."):
                    # Basic URL analysis
                    url_result, url_message = analyze_url(url_input)
                    
                    # Phishing model prediction
                    prediction, confidence = predict(url_input, model, tokenizer)
                    
                    st.subheader("Analysis Results")
                    if url_result:
                        st.error(f"⚠️ {url_message}")
                    else:
                        st.success("✅ No obvious phishing indicators")
                    
                    if prediction == "Phishing":
                        st.error(f"⚠️ {prediction} (Confidence: {confidence:.1%})")
                        st.write("Potential risks:")
                        st.write("- May request sensitive information")
                        st.write("- Could contain malicious links")
                    else:
                        st.success(f"✅ {prediction} (Confidence: {confidence:.1%})")
                        st.write("No known phishing indicators detected")
                    
                    # Simple progress bar for confidence
                    st.progress(int(confidence * 100))
                    
            else:
                st.warning("Please enter a URL to analyze.")
    
    with tab2:
        st.header("📝 Text Analysis")
        
        # Example texts
        example_texts = {
            "Safe Example": "Dear customer, your account has been successfully updated. No further action is required.",
            "Phishing Example": "Dear customer, your account has been compromised! Please verify your identity by clicking the link below:\nhttps://secure-login.example.com/update-account\nFailure to verify within 24 hours will result in account suspension.",
            "Suspicious Example": "URGENT: Your password will expire in 24 hours. Click here to update immediately: https://192.168.1.1/change-password"
        }
        
        # Text selection
        text_type = st.selectbox(
            "Select example text or enter your own:",
            ["Enter custom text"] + list(example_texts.keys())
        )
        
        # Set text input based on selection
        if text_type != "Enter custom text":
            text_input = st.text_area(
                "Enter text to analyze:",
                value=example_texts[text_type],
                height=300,
                placeholder="Enter email content or text here..."
            )
        else:
            text_input = st.text_area(
                "Enter text to analyze:",
                height=300,
                placeholder="Enter email content or text here..."
            )
        
        if st.button("Analyze Text"):
            if text_input.strip():
                with st.spinner("Analyzing text..."):
                    prediction, confidence = predict(text_input, model, tokenizer)
                    
                    st.subheader("Analysis Results")
                    if prediction == "Phishing":
                        st.error(f"⚠️ {prediction} (Confidence: {confidence:.1%})")
                        st.write("Potential risks:")
                        st.write("- May request sensitive information")
                        st.write("- Could contain malicious links")
                        st.write("- May ask for personal data")
                        st.write("- May have suspicious attachments")
                    else:
                        st.success(f"✅ {prediction} (Confidence: {confidence:.1%})")
                        st.write("No known phishing indicators detected")
                    
                    # Progress bar for confidence
                    st.progress(int(confidence * 100))
                    
            else:
                st.warning("Please enter some text to analyze.")

if __name__ == "__main__":
    main()
