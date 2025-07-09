import streamlit as st
from phishing_detector import PhishingDetector
import time
import pandas as pd

# Set page configuration first
st.set_page_config(
    page_title="Healthcare Cybersecurity Analyzer",
    page_icon="🏥",
    layout="wide"
)

# Initialize detector
@st.cache_resource
def init_detector():
    return PhishingDetector()

detector = init_detector()

def main():

    # Main header
    st.title("🏥 Healthcare Cybersecurity Analyzer")
    st.markdown("""
    ## Protecting Healthcare Systems from Cyber Threats
    
    This tool helps healthcare organizations detect and prevent phishing attacks that target sensitive medical information.
    Phishing attacks in healthcare can lead to:
    - Theft of patient medical records
    - Unauthorized access to healthcare systems
    - Ransomware attacks on medical equipment
    - Identity theft of healthcare professionals
    
    The AI model analyzes both URLs and text content to identify potential phishing attempts.
    """)

    # Create tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🔍 URL Analysis", "📝 Text Analysis", "📚 Examples"])

    # Overview Tab
    with tab1:
        st.header("📊 Cybersecurity Overview")
        
        # Key statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Phishing Attempts Detected", "3,456", "+12%")
        with col2:
            st.metric("Threats Prevented", "2,890", "+8%")
        with col3:
            st.metric("System Uptime", "99.99%", "+0.01%")

        # Security tips
        st.header("🛡️ Security Best Practices")
        st.markdown("""
        1. 🔐 Never share patient information via email
        2. 🔍 Verify sender identity before responding
        3. 📞 Contact IT immediately if suspicious
        4. 🔒 Use strong, unique passwords
        5. 🔄 Update software regularly
        """)

    # URL Analysis Tab
    with tab2:
        st.header("🔍 URL Analysis")
        st.write("""
        Analyze suspicious URLs that may be targeting your healthcare system.
        Common attack vectors:
        - Fake login pages for EHR systems
        - Malicious software downloads
        - Credential harvesting sites
        - Ransomware distribution
        """)

        url_input = st.text_input(
            "Enter URL to analyze:",
            "",
            placeholder="https://example.com"
        )
        
        if st.button("Analyze URL"):
            if url_input:
                with st.spinner("Analyzing URL..."):
                    result = detector.predict(url_input)
                    time.sleep(1)
                    
                # Show results
                st.subheader("Analysis Results")
                
                if result['is_phishing']:
                    st.error(f"⚠️ This URL is likely a phishing attempt with {result['confidence']*100:.2f}% confidence.")
                    st.write("Potential risks:")
                    st.write("- May steal patient data")
                    st.write("- Could install malware")
                    st.write("- May be part of a ransomware campaign")
                else:
                    st.success(f"✅ This URL appears to be safe with {result['confidence']*100:.2f}% confidence.")
                    st.write("No known security risks detected")
                
                st.write(f"Prediction: {result['prediction']}")
                st.write(f"Confidence: {result['confidence']*100:.2f}%")
            else:
                st.warning("Please enter a URL to analyze")

    # Text Analysis Tab
    with tab3:
        st.header("📝 Text Analysis")
        st.write("""
        Analyze suspicious emails or messages that may be targeting your healthcare system.
        Common attack patterns:
        - Fake patient records requests
        - Urgent software updates
        - Credential verification requests
        - Emergency transfer requests
        """)

        text_input = st.text_area(
            "Enter text to analyze:",
            "",
            height=200,
            placeholder="Dear Dr. Smith, we need to update your credentials immediately..."
        )
        
        if st.button("Analyze Text"):
            if text_input:
                with st.spinner("Analyzing text..."):
                    result = detector.predict(text_input)
                    time.sleep(1)
                    
                # Show results
                st.subheader("Analysis Results")
                
                if result['is_phishing']:
                    st.error(f"⚠️ This text contains phishing indicators with {result['confidence']*100:.2f}% confidence.")
                    st.write("Potential risks:")
                    st.write("- May request sensitive information")
                    st.write("- Could contain malicious links")
                    st.write("- May impersonate healthcare authority")
                else:
                    st.success(f"✅ This text appears to be safe with {result['confidence']*100:.2f}% confidence.")
                    st.write("No known phishing indicators detected")
                
                st.write(f"Prediction: {result['prediction']}")
                st.write(f"Confidence: {result['confidence']*100:.2f}%")
            else:
                st.warning("Please enter some text to analyze")

    # Examples Tab
    with tab4:
        st.header("📚 Real-world Examples")
        
        # Example cases
        examples = {
            "Phishing": [
                "Important: New software update required for medical equipment. Click here to download.",
                "Emergency: Patient records need to be transferred immediately. Please provide login details."
            ],
            "Safe": [
                "Scheduled maintenance for the EHR system from 10 PM to 2 AM tonight.",
                "Reminder: Monthly security training session at 2 PM today.",
                "Update: New patient privacy policy effective from next month.",
                "Notification: Your password expires in 30 days."
            ]
        }

        # Example selector
        example_type = st.selectbox(
            "Select example type:",
            ["Phishing", "Safe"]
        )

        # Show examples
        selected_example = st.selectbox(
            "Select example:",
            examples[example_type]
        )

        # Analyze example
        if st.button("Analyze Example"):
            with st.spinner("Analyzing example..."):
                result = detector.predict(selected_example)
                time.sleep(1)
                
            # Show results
            st.subheader("Example Analysis")
            
            if result['is_phishing']:
                st.error(f"⚠️ This example is detected as phishing with {result['confidence']*100:.2f}% confidence.")
            else:
                st.success(f"✅ This example is detected as safe with {result['confidence']*100:.2f}% confidence.")
            
            st.write(f"Prediction: {result['prediction']}")
            st.write(f"Confidence: {result['confidence']*100:.2f}%")

if __name__ == "__main__":
    main()
