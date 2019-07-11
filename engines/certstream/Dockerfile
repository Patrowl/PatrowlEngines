FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="CertStream\ \(Patrowl engine\)" Version="1.1.1"

# Install dependencies
RUN apk add --update \
    python3 \
    python3-dev \
    py3-pip \
    git \
  && rm -rf /var/cache/apk/*

RUN mkdir -p /opt/patrowl-engines/certstream
RUN mkdir -p /opt/patrowl-engines/certstream/results

WORKDIR /opt/patrowl-engines/certstream

COPY . .
COPY certstream.json.sample certstream.json
COPY whitelist.txt.sample whitelist.txt

RUN pip3 install --no-cache-dir -U pip
RUN pip3 install --no-cache-dir -r requirements.txt

RUN git clone https://github.com/AssuranceMaladieSec/CertStreamMonitor.git

COPY tests/CertStreamMonitor_empty.sqlite3 CertStreamMonitor/db/CertStreamMonitor.sqlite3

# TCP port exposed by the container (NAT)
EXPOSE 5017

# Run the application when the container launches
CMD ["gunicorn", "engine-certstream:app", "-b", "0.0.0.0:5017", "--timeout", "120", "--graceful-timeout", "60", "--access-logfile", "-"]
