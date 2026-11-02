# Plain Debian Python image: aioesphomeapi/cryptography/noise ship manylinux wheels for it
# (Alpine/musl would compile them on the HA box). The Supervisor's BUILD_FROM is not used.
FROM python:3.13-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY netwatch /app/netwatch
WORKDIR /app
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "netwatch"]
