FROM python:3.12-slim

# Set environment flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Install dependencies in cached layer
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create dedicated non-root application user and group
RUN groupadd -r cloudguard && \
    useradd -r -g cloudguard -u 10001 -d /app -s /sbin/nologin cloudguard

# Copy application source code
COPY . .

# Ensure proper non-root permissions
RUN chown -R cloudguard:cloudguard /app

# Switch to unprivileged user
USER cloudguard

EXPOSE 8000

# Native Python liveness probe (avoids external binaries in slim image)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).getcode() == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]