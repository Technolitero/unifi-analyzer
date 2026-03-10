#!/bin/bash
# Rebuild the Mac App with the new network icon

echo "Rebuilding UniFi Analyzer Mac App with network icon..."

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Setting up virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
source .venv/bin/activate

# Install/upgrade PyInstaller
pip install --upgrade pyinstaller

# Create foundry directory if it doesn't exist
mkdir -p foundry

# Clean previous build
rm -rf foundry/build foundry/dist

# Build the app
pyinstaller --distpath "foundry/dist" --workpath "foundry/build" "UniFi Analyzer.spec"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Mac App rebuilt successfully!"
    echo "📍 Location: $(pwd)/foundry/dist/UniFi Analyzer.app"
    echo "🎨 New network-themed icon applied"
    echo ""
    echo "To install:"
    echo "1. Copy 'foundry/dist/UniFi Analyzer.app' to /Applications/"
    echo "2. Launch the app from Applications folder"
else
    echo "❌ Build failed!"
    exit 1
fi