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

# --- Install sqlmap (pinned) for SQL-injection testing ---
ARG SQLMAP_VERSION=1.10.6
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget ca-certificates \
    && wget -q "https://github.com/sqlmapproject/sqlmap/archive/refs/tags/${SQLMAP_VERSION}.tar.gz" -O /tmp/sqlmap.tgz \
    && mkdir -p /opt/sqlmap \
    && tar -xzf /tmp/sqlmap.tgz -C /opt/sqlmap --strip-components=1 \
    && chmod +x /opt/sqlmap/sqlmap.py \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && rm -f /tmp/sqlmap.tgz \
    && apt-get purge -y --auto-remove wget \
    && rm -rf /var/lib/apt/lists/*

# --- Install Nikto web scanner ---
RUN apt-get update \
    && apt-get install -y --no-install-recommends nikto \
    && rm -rf /var/lib/apt/lists/*

# --- Install Semgrep for SAST ---
RUN pip install --no-cache-dir semgrep

# Install Python dependencies (separate layer to leverage Docker layer caching).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY app ./app

# Where the SQLite database will live (mounted as a volume in compose).
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
