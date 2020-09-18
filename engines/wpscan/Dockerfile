FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Wpscan\ \(Patrowl engine\)" Version="1.0.0"

# Install dependencies
RUN apk add --update --no-cache \
    python3 \
    python3-dev \
    py3-pip \
    git \
    gcc \
    musl-dev \
    libc-dev \
    linux-headers \
  && rm -rf /var/cache/apk/*

RUN mkdir -p /opt/patrowl-engines/wpscan
RUN mkdir -p /opt/patrowl-engines/wpscan/results

WORKDIR /opt/patrowl-engines/wpscan

COPY __init__.py .
COPY engine-wpscan.py .
COPY wpscan.json.sample wpscan.json
COPY requirements.txt .
COPY README.md .

RUN pip3 install --no-cache-dir -U pip wheel setuptools
RUN pip3 install --no-cache-dir -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5023

# Run the application when the container launches
CMD ["gunicorn", "engine-wpscan:app", "-b", "0.0.0.0:5023", "--timeout", "120", "--graceful-timeout", "60", "--access-logfile", "-"]
