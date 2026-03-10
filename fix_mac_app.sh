#!/bin/bash
# Fix for UniFi Analyzer Mac App - removes reload mode that causes multiple browser tabs

APP_PATH="/Applications/UniFi Analyzer.app"
EXECUTABLE_PATH="$APP_PATH/Contents/MacOS/UniFi Analyzer"

if [ ! -f "$EXECUTABLE_PATH" ]; then
    echo "UniFi Analyzer app not found at $APP_PATH"
    echo "Please make sure the app is installed in /Applications/"
    exit 1
fi

echo "Fixing UniFi Analyzer app to prevent multiple browser tabs..."
echo "This will modify the app bundle to remove the --reload flag."

# Create a backup
cp "$EXECUTABLE_PATH" "$EXECUTABLE_PATH.backup"

# Use sed to replace the reload flag in the executable
# This is a binary file, so we need to be careful
# The --reload flag appears as a string in the binary

# Alternative approach: create a wrapper script
cat > "$EXECUTABLE_PATH.fixed" << 'EOF'
#!/bin/bash
# Fixed launcher for UniFi Analyzer that doesn't use --reload

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$DIR"

# Get the original executable name
ORIGINAL_EXE=$(basename "$0" .fixed)

# Start the server without --reload
"$DIR/$ORIGINAL_EXE" --host 0.0.0.0 --port 8080 &
SERVER_PID=$!

# Wait a bit for server to start
sleep 3

# Check if server is running
if kill -0 $SERVER_PID 2>/dev/null; then
    # Open browser
    open http://localhost:8080
    # Wait for server
    wait $SERVER_PID
else
    echo "Server failed to start"
    exit 1
fi
EOF

chmod +x "$EXECUTABLE_PATH.fixed"

echo "Fixed launcher created at: $EXECUTABLE_PATH.fixed"
echo ""
echo "To use the fixed version:"
echo "1. Backup the original: cp '$EXECUTABLE_PATH' '$EXECUTABLE_PATH.original'"
echo "2. Replace with fixed version: cp '$EXECUTABLE_PATH.fixed' '$EXECUTABLE_PATH'"
echo "3. Test the app"
echo ""
echo "Alternatively, use the Python source installation method instead."