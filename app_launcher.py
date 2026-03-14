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
import signal
import tkinter as tk
from tkinter import ttk, messagebox

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

class UniFiAnalyzerApp:
    def __init__(self):
        self.server_thread = None
        self.server_running = False

        # Create the main window
        self.root = tk.Tk()
        self.root.title("UniFi Analyzer")
        self.root.geometry("400x250")
        self.root.resizable(False, False)

        # Center the window on screen
        self.root.eval('tk::PlaceWindow . center')

        # Create the UI
        self.create_ui()

        # Handle window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Start the server
        self.start_server()

    def create_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Title
        title_label = ttk.Label(main_frame, text="UniFi Analyzer", font=("Helvetica", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))

        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))

        self.status_label = ttk.Label(status_frame, text="Starting server...")
        self.status_label.grid(row=0, column=0, sticky=tk.W)

        self.status_indicator = ttk.Label(status_frame, text="●", foreground="orange")
        self.status_indicator.grid(row=0, column=1, padx=(10, 0))

        # Info text
        info_text = "The UniFi Analyzer web interface has been opened in your browser.\n\nYou can close this window to stop the server."
        info_label = ttk.Label(main_frame, text=info_text, wraplength=360, justify=tk.LEFT)
        info_label.grid(row=2, column=0, columnspan=2, pady=(0, 15))

        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2)

        # Open Browser button
        self.open_browser_btn = ttk.Button(button_frame, text="Open Browser", command=self.open_browser)
        self.open_browser_btn.grid(row=0, column=0, padx=(0, 10))

        # Quit button
        self.quit_btn = ttk.Button(button_frame, text="Quit", command=self.on_closing)
        self.quit_btn.grid(row=0, column=1)

    def start_server(self):
        """Start the FastAPI server in a separate thread."""
        def run_server():
            try:
                self.server_running = True
                self.update_status("Server running", "green")
                uvicorn.run(app, host="0.0.0.0", port=8080)
            except Exception as e:
                self.update_status(f"Server error: {e}", "red")
                self.server_running = False

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        # Open browser after a short delay
        self.root.after(2000, self.open_browser)

    def open_browser(self):
        """Open the web interface in the default browser."""
        try:
            webbrowser.open('http://localhost:8080')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open browser: {e}")

    def update_status(self, text, color):
        """Update the status indicator."""
        def _update():
            self.status_label.config(text=text)
            self.status_indicator.config(foreground=color)
        self.root.after(0, _update)

    def on_closing(self):
        """Handle window close event."""
        if messagebox.askokcancel("Quit", "Stop the UniFi Analyzer server and quit?"):
            self.stop_server()
            self.root.quit()

    def stop_server(self):
        """Stop the server."""
        if self.server_running:
            self.update_status("Stopping server...", "orange")
            # Send SIGTERM to the current process to stop uvicorn
            os.kill(os.getpid(), signal.SIGTERM)
            self.server_running = False

    def run(self):
        """Start the GUI event loop."""
        self.root.mainloop()

def main():
    app = UniFiAnalyzerApp()
    app.run()

if __name__ == "__main__":
    main()