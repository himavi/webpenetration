# Backend image for the AI Penetration Tester API.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# --- Install the Nuclei scanner (pinned) and its templates ---
ARG NUCLEI_VERSION=3.9.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget unzip ca-certificates \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip \
    && apt-get purge -y --auto-remove wget unzip \
    && rm -rf /var/lib/apt/lists/*

# Pre-download nuclei templates so scans start fast and work offline.
# (Note: -disable-update-check must NOT be combined here or the update is skipped.)
RUN nuclei -update-templates

# Install Python dependencies (separate layer to leverage Docker layer caching).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY app ./app

# Where the SQLite database will live (mounted as a volume in compose).
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
