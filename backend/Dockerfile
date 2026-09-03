FROM crowdsecurity/crowdsec:latest-debian AS crowdsec-cli

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=crowdsec-cli /usr/local/bin/cscli /usr/local/bin/cscli

RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables suricata suricata-update \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/data

EXPOSE 8000
