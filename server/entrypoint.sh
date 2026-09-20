#!/usr/bin/env bash
set -euo pipefail


# --- Start the server ---
echo "Starting server..."
exec gunicorn -b 0.0.0.0:5000 server:app

