#!/usr/bin/env bash

if [[ -z "${FLAG_2:-}" ]]; then
  echo "WARNING: FLAG_2 is not set"
fi

# --- Replace placeholder in /app/flag ---
if [[ -f "/app/flag" ]]; then
    if grep -q "REPLACE_THIS_STRING_WITH_SERVER_FLAG" "/app/flag"; then
        echo "Initializing /app/flag"

        python - <<'PY'
import os

flag_path = "/app/flag"
placeholder = "REPLACE_THIS_STRING_WITH_SERVER_FLAG"
flag_value = os.environ["FLAG_2"]

# Read the existing flag template.
with open(flag_path, "r") as f:
    content = f.read()

# Replace the placeholder.
content = content.replace(placeholder, flag_value)

# Write directly back to the existing file.
with open(flag_path, "w") as f:
    f.write(content)
PY

	chmod 400 /app/flag

  fi
else
  echo "WARNING: /app/flag not found, skipping"
fi

unset FLAG_2

# --- Start the server ---
echo "Starting server..."
exec gunicorn -b 0.0.0.0:5000 server:app

