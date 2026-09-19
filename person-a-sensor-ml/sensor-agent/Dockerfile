FROM python:3.11-slim

RUN for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do \
        [ -f "$f" ] && sed -i 's#http://deb.debian.org#https://deb.debian.org#g; s#http://security.debian.org#https://security.debian.org#g' "$f"; \
    done; \
    echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/99-retries && \
    apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY person-a-sensor-ml/sensor-agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY person-a-sensor-ml/sensor-agent/src/ ./src/

CMD ["python", "-u", "src/sensor_agent.py"]
