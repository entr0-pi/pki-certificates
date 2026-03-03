#!/bin/bash
# Start the PKI Management Web Application
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || exit 1

echo "===================================="
echo "PKI Management Web Application"
echo "===================================="
echo ""
echo "Starting FastAPI server..."
echo "Access the application at: http://localhost:8000"
echo "Press Ctrl+C to stop the server"
echo ""

python backend/app.py
