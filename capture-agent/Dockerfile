# Capture agent sidecar. Runs inside a lab node's network namespace
# (network_mode: service:<node>) and exposes a tiny HTTP/WebSocket API on the
# management leg only:
#   - dumpcap writes the authoritative pcapng to the shared captures volume
#   - tshark streams decoded packets (EK JSON) live to the backend
#
# Debian trixie for Wireshark 4.4.x, whose dissectors know X25519MLKEM768,
# IKE_INTERMEDIATE and the OpenSSH mlkem768x25519 KEX names.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update && apt-get install -y --no-install-recommends \
        tshark iproute2 python3 python3-venv ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/agent
COPY requirements.txt .
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt
COPY agent/ ./agent/

# Root inside the container, but with every capability dropped except
# NET_RAW/NET_ADMIN (set in compose). File capabilities on dumpcap would be
# ignored anyway under no-new-privileges.
ENV PATH=/opt/venv/bin:$PATH
EXPOSE 9100
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; a=open('/tmp/agent.addr').read().strip(); urllib.request.urlopen('http://'+a+'/health', timeout=2)" || exit 1
CMD ["python3", "-m", "agent.main"]
