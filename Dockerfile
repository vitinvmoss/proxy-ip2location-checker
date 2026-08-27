FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash curl jq bc netcat-openbsd dnsutils iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN curl -fsSL https://raw.githubusercontent.com/xykt/IPQuality/main/ip.sh -o /opt/ipquality/ip.sh && chmod +x /opt/ipquality/ip.sh
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
CMD gunicorn app:app --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 4 --timeout 180
