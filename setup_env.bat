@echo off
echo Setting up environment for Phishing Detector...

pip install -r requirements.txt

if %errorlevel% neq 0 (
    echo Failed to install dependencies
    exit /b 1
)

echo Setup complete! You can now run the app with:
python app.py
