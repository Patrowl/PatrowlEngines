FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"

LABEL Name="PastebinMonitor\ \(Patrowl engine\)" Version="1.4.26"

# Install dependencies
RUN apk add --update --no-cache \
    python3 python3-dev py3-pip \
    git \
  && rm -rf /var/cache/apk/*

RUN mkdir -p /opt/patrowl-engines/pastebin_monitor
RUN mkdir -p /opt/patrowl-engines/pastebin_monitor/results

WORKDIR /opt/patrowl-engines/pastebin_monitor

COPY . .
COPY pastebin_monitor.json.sample pastebin_monitor.json

RUN pip3 install --no-cache-dir --upgrade pip
RUN pip3 install --no-cache-dir --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5020

# Run the application when the container launches
CMD ["gunicorn", "engine-pastebin_monitor:app", "-b", "0.0.0.0:5020", "--timeout", "120", "--graceful-timeout", "60"]
