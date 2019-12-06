FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="PastebinMonitor\ \(Patrowl engine\)" Version="0.0.1"

# Install dependencies
RUN apk add --update \
    python3 \
    python3-dev \
    py3-pip \
    git \
  && rm -rf /var/cache/apk/*

RUN mkdir -p /opt/patrowl-engines/pastebin_monitor
RUN mkdir -p /opt/patrowl-engines/pastebin_monitor/results

WORKDIR /opt/patrowl-engines/pastebin_monitor

COPY __init__.py .
COPY engine-pastebin_monitor.py .
COPY pastebin_monitor.json.sample pastebin_monitor.json
COPY proxies.txt .
COPY README.md .
COPY requirements.txt .
COPY useragents.txt .

RUN pip3 install --no-cache-dir -U pip
RUN pip3 install --no-cache-dir -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5030

# Run the application when the container launches
CMD ["python3", "engine-pastebin_monitor.py"]