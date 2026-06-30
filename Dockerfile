# All-in-one image for Hugging Face Spaces (Docker SDK) and any single-container
# host. Builds the React frontend, then serves it from the FastAPI backend on
# port 7860 alongside the API, with every scanning engine installed, in demo
# mode (scope-restricted + sample report seeded on first boot).
#
# HF Spaces uses this Dockerfile automatically (root + named "Dockerfile") and
# the app_port: 7860 declared in README.md frontmatter.
#
# Local build/run:
#   docker build -t ai-pentester .
#   docker run -p 7860:7860 ai-pentester   ->  open http://localhost:7860

# --- Stage 1: build the React frontend (same-origin API, so no base URL) ---
FROM node:24-alpine AS frontend
WORKDIR /web
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# --- Stage 2: backend + engines + bundled static frontend ---
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEMO_MODE=1 \
    DEMO_TARGET=http://localhost:7860 \
    STATIC_DIR=/app/static \
    NUCLEI_TIMEOUT=60 \
    NUCLEI_TAGS=misconfig,misconfiguration,exposure,exposures,tech,ssl \
    SQLMAP_TIMEOUT=60

WORKDIR /app

# --- Nuclei scanner (pinned) + templates ---
ARG NUCLEI_VERSION=3.9.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget unzip ca-certificates \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip \
    && apt-get purge -y --auto-remove wget unzip \
    && rm -rf /var/lib/apt/lists/*
RUN nuclei -update-templates

# --- sqlmap (pinned) ---
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

# --- WeasyPrint native libraries (PDF reports) ---
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# --- Nikto from source (Debian trixie dropped the package) ---
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git perl libnet-ssleay-perl libjson-perl libxml-writer-perl \
    && git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/*

# --- Semgrep (SAST) ---
RUN pip install --no-cache-dir semgrep

# --- Python deps ---
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# --- App code + built frontend ---
COPY backend/app ./app
COPY --from=frontend /web/dist ./static
# World-writable data dir so the SQLite DB works whether the host runs the
# container as root or a non-root user (e.g. Hugging Face Spaces).
RUN mkdir -p /app/data && chmod 777 /app/data

EXPOSE 7860

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860"]
