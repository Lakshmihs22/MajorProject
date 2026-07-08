FROM python:3.11-slim

RUN for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do \
        [ -f "$f" ] && sed -i 's#http://deb.debian.org#https://deb.debian.org#g; s#http://security.debian.org#https://security.debian.org#g' "$f"; \
    done; \
    echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/99-retries && \
    apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    hydra \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build context is the repo root (see docker-compose.yml), so paths below
# are relative to the repo root, not this Dockerfile's folder.
COPY person-a-sensor-ml/attacker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY person-a-sensor-ml/attacker/src/ ./src/

CMD ["python", "src/attack_agent.py"]
