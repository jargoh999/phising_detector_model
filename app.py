import streamlit as st
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import validators
import re
from urllib.parse import urlparse
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set page config
st.set_page_config(
    page_title="Healthcare Cybersecurity Analyzer",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add custom CSS for better styling
st.markdown("""
    <style>
    .header {
        color: white;
        padding: 20px;
        border-radius: 10px;
    }
    .warning {
        padding: 15px;
        border-radius: 8px;
    }
    .success {
        padding: 15px;
        border-radius: 8px;
    }
    .threat-level {
        font-size: 20px;
        font-weight: bold;
        margin: 10px 0;
    }
    </style>
    """, unsafe_allow_html=True)

# Sidebar with healthcare cybersecurity information
with st.sidebar:
    st.markdown("""
    <div class="header">
        <h2>Healthcare Cybersecurity Dashboard</h2>
        <p>Powered by AI/ML Threat Detection</p>
    </div>
    
    <div class="warning">
        <h3>Healthcare Cybersecurity Challenges</h3>
        <ul>
            <li>Data quality and availability</li>
            <li>Model transparency</li>
            <li>Regulatory compliance (GDPR, HIPAA)</li>
            <li>Technical expertise limitations</li>
        </ul>
    </div>
    
    <div class="success">
        <h3>AI/ML Benefits</h3>
        <ul>
            <li>Real-time threat detection</li>
            <li>Pattern recognition</li>
            <li>Automated response capabilities</li>
            <li>Continuous learning</li>
        </ul>
    </div>
    
    <div class="info">
        <h3>Best Practices</h3>
        <ul>
            <li>Regular security audits</li>
            <li>Employee training</li>
            <li>Multi-factor authentication</li>
            <li>Regular updates</li>
        </ul>
    </div>
    
    <div class="footer">
        <p>Powered by AI/ML</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""
    <h4>Important Notice</h4>
    <p>This tool is designed to assist healthcare organizations in detecting potential cyber threats.
       It uses AI/ML models to analyze emails and URLs for phishing attempts.</p>
    </div>
    """, unsafe_allow_html=True)

@st.cache_resource(show_spinner="Loading AI Threat Detection Model...")
def load_model():
    """Load the AI threat detection model."""
    try:
        model_name = "phishbot/ScamLLM"
        logger.info(f"Loading model: {model_name}")
        
        # Load tokenizer and model
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        
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

# Main app
st.title("Healthcare Cybersecurity Analyzer")

# Add a banner with healthcare cybersecurity information
st.markdown("""
    <div style="background-color: #004d99; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
        <h2>Healthcare Cybersecurity Dashboard</h2>
        <p>Advanced AI/ML Threat Detection for Healthcare Organizations</p>
        <p>Real-time analysis of potential cyber threats in healthcare communications</p>
    </div>
    """, unsafe_allow_html=True)

# Main app
model, tokenizer = load_model()

# Create two columns layout
col1, col2 = st.columns(2)

with col1:
    st.header("Email Analysis")
    
    # Example emails
    example_emails = {
        "Safe Example": "Dear patient, your appointment is confirmed for tomorrow at 10 AM. Please arrive 15 minutes early.",
        "Phishing Example": "URGENT: Your medical records have been compromised! Click here to verify your identity: https://secure-medical-login.com/update-account",
        "Suspicious Example": "Dear user, we noticed suspicious activity on your account. Please verify your password at: http://192.168.1.1/account-security"
    }
    
    # Email selection
    email_type = st.selectbox(
        "Select example email or enter your own:",
        ["Enter custom email"] + list(example_emails.keys())
    )
    
    # Set email input based on selection
    if email_type != "Enter custom email":
        email_input = st.text_area(
            "Enter email content to analyze:",
            value=example_emails[email_type],
            height=200,
            placeholder="Enter email content here..."
        )
    else:
        email_input = st.text_area(
            "Enter email content to analyze:",
            height=200,
            placeholder="Enter email content here..."
        )
    
    if st.button("Analyze Email", key="email_button"):
        if email_input.strip():
            result, confidence = predict(email_input, model, tokenizer)
            st.write(f"Threat Level: {result}")
            st.progress(confidence)
            st.write(f"Confidence: {confidence:.2%}")
        else:
            st.warning("Please enter email content to analyze")

with col2:
    st.header("URL Analysis")
    
    # Example URLs
    example_urls = {
        "Safe Example": "https://www.mayoclinic.org/appointments",
        "Phishing Example": "https://secure-mayoclinic-login.com/update-account",
        "Suspicious Example": "http://192.168.1.100/medical-login",
        "Common Phishing Pattern": "https://medical-security-verification.com/verify-account"
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
    
    if st.button("Analyze URL", key="url_button"):
        if url_input.strip():
            result, confidence = predict(url_input, model, tokenizer)
            st.write(f"Threat Level: {result}")
            st.progress(confidence)
            st.write(f"Confidence: {confidence:.2%}")
            
            if result == "Phishing":
                st.error(f"⚠️ {result} (Confidence: {confidence:.1%})")
                st.write("Potential risks:")
                st.write("- May request sensitive information")
                st.write("- Could contain malicious links")
            else:
                st.success(f"✅ {result} (Confidence: {confidence:.1%})")
                st.write("No known phishing indicators detected")
            
            # Simple progress bar for confidence
            st.progress(int(confidence * 100))
            
        else:
            st.warning("Please enter a URL to analyze.")
        
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
