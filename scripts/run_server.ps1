# Add OpenSSL to PATH and run the Flask server
$env:PATH = "C:\Program Files\OpenSSL-Win64\bin;" + $env:PATH

# Run the Flask application
& "C:/Users/uzi/Downloads/projects/PKI/.venv/Scripts/python.exe" app.py
