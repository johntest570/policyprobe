#!/bin/bash
#
# PolicyProbe Development Server
#
# This script starts both the frontend and backend servers for development.
# Run from the project root: ./scripts/run_dev.sh
#
# Override Python version: PYTHON_PATH=/path/to/python ./scripts/run_dev.sh
#

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "  PolicyProbe Development Server"
echo "=========================================="
echo ""

# Find suitable Python interpreter (3.10+)
# Validate helper script exists and is a regular file before sourcing
PYTHON_HELPER="$PROJECT_ROOT/scripts/python_helper.sh"
if [ ! -f "$PYTHON_HELPER" ] || [ ! -r "$PYTHON_HELPER" ]; then
    echo "ERROR: python_helper.sh not found or not readable at $PYTHON_HELPER" >&2
    exit 1
fi
# shellcheck source=scripts/python_helper.sh
. "$PYTHON_HELPER"
echo ""

# Check for required environment variables
if [ -z "$OPENAI_API_KEY" ]; then
    echo "WARNING: OPENAI_API_KEY not set"
    echo "The LLM features will not work without it."
    echo "Set it with: export OPENAI_API_KEY=your_key_here"
    echo ""
fi

# Function to cleanup background processes on exit
cleanup() {
    echo ""
    echo "Shutting down servers..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start backend
echo "Starting Python backend..."
cd "$PROJECT_ROOT/backend"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    "$PYTHON_CMD" -m venv .venv
    echo "Installing Python dependencies..."
    .venv/bin/pip install --require-hashes -r requirements.txt
else
    # Verify venv integrity before use
    if [ ! -x ".venv/bin/python" ] || [ ! -x ".venv/bin/pip" ]; then
        echo "ERROR: Virtual environment appears corrupt. Remove .venv and retry." >&2
        exit 1
    fi
fi
# Use venv binaries directly instead of activating to avoid sourcing arbitrary scripts
PYTHON_VENV="$PROJECT_ROOT/backend/.venv/bin/python"
PIP_VENV="$PROJECT_ROOT/backend/.venv/bin/pip"
UVICORN_VENV="$PROJECT_ROOT/backend/.venv/bin/uvicorn"

# Start uvicorn in background using venv binary directly
"$UVICORN_VENV" main:app --reload --host 127.0.0.1 --port 5500 &
BACKEND_PID=$!
echo "Backend started (PID: $BACKEND_PID)"
echo "Backend URL: http://localhost:5500"
echo ""

# Wait for backend to be ready
echo "Waiting for backend to be ready..."
sleep 3

# Start frontend
echo "Starting Next.js frontend..."
cd "$PROJECT_ROOT/frontend"

# Check if node_modules exists and is valid
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
elif [ ! -f "node_modules/.bin/next" ]; then
    echo "⚠️  node_modules exists but is incomplete. Reinstalling..."
    # Remove only the specific node_modules directory (no wildcard or recursive glob)
    rm -rf -- "$PROJECT_ROOT/frontend/node_modules"
    npm install
fi

# Start Next.js in background on port 5001
npm run dev -- -p 5001 &
FRONTEND_PID=$!
echo "Frontend started (PID: $FRONTEND_PID)"
echo ""

# Wait for frontend to start and verify it's still running
echo "Waiting for frontend to initialize..."
sleep 3

if ! kill -0 $FRONTEND_PID 2>/dev/null; then
    echo "❌ ERROR: Frontend failed to start!"
    echo "   Check for errors above or try: cd frontend && npm install"
    kill $BACKEND_PID 2>/dev/null || true
    exit 1
fi

echo "=========================================="
echo "  Servers are running!"
echo "=========================================="
echo ""
echo "  Frontend: http://localhost:5001"
echo "  Backend:  http://localhost:5500"
echo "  API Docs: http://localhost:5500/docs"
echo ""
echo "  Press Ctrl+C to stop all servers"
echo "=========================================="
echo ""

# Wait for both processes
wait
