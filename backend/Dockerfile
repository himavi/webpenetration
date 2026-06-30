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

# --- WeasyPrint native libraries (for PDF report rendering) ---
# Pango pulls in harfbuzz, fontconfig, cairo, glib and libffi as dependencies,
# so the explicit list stays minimal and avoids the t64-renamed package names
# that are not present on the trixie-based slim image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# --- Install Nikto from source ---
# Debian trixie no longer packages nikto, so install it from the upstream repo
# and expose it on PATH via a small wrapper (running nikto.pl by its real path
# lets Perl's FindBin locate its config/plugins). perl, libnet-ssleay-perl (TLS)
# and the JSON / XML::Writer modules (output formats) remain as runtime deps.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git perl libnet-ssleay-perl libjson-perl libxml-writer-perl \
    && git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto \
    && apt-get purge -y --auto-remove git \
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
