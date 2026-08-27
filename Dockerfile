FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    jq \
    bc \
    netcat-openbsd \
    dnsutils \
    iproute2 \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# IPQuality is stored in the repository instead of being downloaded
# during the Docker build.
RUN mkdir -p /opt/ipquality

COPY ipquality/ip.sh /opt/ipquality/ip.sh
RUN chmod 755 /opt/ipquality/ip.sh

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10000

CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 4 --timeout 180"]