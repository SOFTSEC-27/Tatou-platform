# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies
RUN pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY src /app/src
COPY flag /app/flag
COPY entrypoint.sh /app/entrypoint.sh
RUN pip install --no-cache-dir -e .

RUN groupadd --system appuser \
    && useradd --system --gid appuser --uid 10001 \
       --home-dir /app --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/storage \
    && chown -R appuser:appuser /app/src /app/storage \
    && chown appuser:appuser /app/flag /app/entrypoint.sh \
    && chmod 755 /app/entrypoint.sh \
    && chmod 600 /app/flag

USER appuser

EXPOSE 5000

# Default command runs the web server
CMD ["./entrypoint.sh"]

