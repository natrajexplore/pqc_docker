# PQC WireScope backend: FastAPI + the analyzer. tshark is needed for offline
# work (packet detail trees, pcap imports, TLS decryption with a lab key log).
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update && apt-get install -y --no-install-recommends \
        tshark python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml .
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir .
COPY app/ ./app/

# Unprivileged at run time. It needs read/write on /captures (shared volume),
# which Docker creates root-owned; the UID is pinned so you can chown the
# volume once if your platform needs it (see docs/IMPLEMENTATION_PLAN.md phase 1).
RUN useradd -r -u 10001 -d /app pqcw
USER 10001
ENV PATH=/opt/venv/bin:$PATH HOME=/tmp
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)" || exit 1
# --no-access-log: app.middleware writes the access log, with request ids and durations.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-access-log"]
