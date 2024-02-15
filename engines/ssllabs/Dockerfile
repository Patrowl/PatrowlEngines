FROM alpine:3.16.3
LABEL Name="SSL-Labs\ \(Patrowl engine\)" Version="1.4.31"

# Install dependencies
RUN apk add --update --no-cache \
    python3 python3-dev py3-pip \
    git \
  && rm -rf /var/cache/apk/*

RUN mkdir -p /opt/patrowl-engines/ssllabs
RUN mkdir -p /opt/patrowl-engines/ssllabs/results

WORKDIR /opt/patrowl-engines/ssllabs

COPY . .
COPY ssllabs.json.sample ssllabs.json


RUN pip3 install --no-cache-dir --upgrade pip
RUN pip3 install --no-cache-dir --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5004

# Run the application when the container launches
CMD ["gunicorn", "engine-ssllabs:app", "-b", "0.0.0.0:5004", "--timeout", "600", "--graceful-timeout", "60","--access-logfile", "-", "--log-file", "/opt/patrowl-engines/ssllabs/patrowlengine.ssllabs.log", "--log-level", "$LOGLEVEL", "--capture-output", "--log-syslog"]
