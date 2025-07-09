#!/bin/bash

# Install dependencies
pip install -r requirements.txt

# Download model
python download_model.py

# Set up environment
mkdir -p ~/.streamlit

echo "[server]\nport = $PORT\nheadless = true\nenableCORS = false\n\n[theme]\nprimaryColor = '#007bff'\nbackgroundColor = '#f8f9fa'\nsecondaryBackgroundColor = '#e9ecef'\ntextColor = '#333333'\nfont = 'sans serif'" > ~/.streamlit/config.toml
