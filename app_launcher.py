#!/usr/bin/env python3
"""
Launcher for UniFi Analyzer macOS app.
Starts the FastAPI server and opens the browser.
"""

import webbrowser
import time
import os
import sys
import threading
import uvicorn

# Get the directory where the executable is located
if getattr(sys, 'frozen', False):
    # Running in a bundle
    app_dir = os.path.dirname(sys.executable)
else:
    # Running in development
    app_dir = os.path.dirname(os.path.abspath(__file__))

# Change to the app directory
os.chdir(app_dir)

print(f"Starting UniFi Analyzer from {app_dir}")

# Import the FastAPI app
from main import app

def open_browser():
    """Open browser after server starts."""
    time.sleep(2)  # Wait for server to be ready
    print("Opening browser...")
    webbrowser.open('http://localhost:8080')

# Start browser opening in a separate thread
browser_thread = threading.Thread(target=open_browser)
browser_thread.daemon = True
browser_thread.start()

# Run the server directly
print("Starting server...")
uvicorn.run(app, host="0.0.0.0", port=8080)