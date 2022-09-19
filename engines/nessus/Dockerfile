FROM alpine:latest
LABEL Name="Nessus\ \(Patrowl engine\)" Version="1.4.28"

ENV LOGLEVEL info

# Set the working directory
RUN mkdir -p /opt/patrowl-engines/nessus
RUN mkdir -p /opt/patrowl-engines/nessus/logs
RUN mkdir -p /opt/patrowl-engines/nessus/results
RUN mkdir -p /opt/patrowl-engines/nessus/reports
RUN mkdir -p /opt/patrowl-engines/nessus/external-libs
WORKDIR /opt/patrowl-engines/nessus

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-nessus.py .
COPY parser.py .
COPY nessus.json.sample nessus.json
COPY requirements.txt .
COPY README.md .
COPY VERSION .
COPY etc/ ./etc/

RUN apk add --update \
    python3 python3-dev py3-pip \
    git \
  && rm -rf /var/cache/apk/*
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

WORKDIR /opt/patrowl-engines/nessus/external-libs
RUN git clone https://github.com/tenable/nessrest
RUN cd nessrest && git reset --hard af28834d6253db0d00e3ab46ab259dd5bc903063
WORKDIR /opt/patrowl-engines/nessus/external-libs/nessrest/
RUN git apply /opt/patrowl-engines/nessus/etc/ness6rest.patch
RUN pip3 install --trusted-host pypi.python.org -e /opt/patrowl-engines/nessus/external-libs/nessrest/
WORKDIR /opt/patrowl-engines/nessus/

# TCP port exposed by the container (NAT)
EXPOSE 5002

# Run app.py when the container launches
CMD ["gunicorn", "engine-nessus:app", "-b", "0.0.0.0:5002", "--preload", "--timeout", "300", "--access-logfile", "-", "--log-file", "/opt/patrowl-engines/nessus/logs/patrowlengine.nessus.log", "--log-level", "$LOGLEVEL", "--capture-output", "--log-syslog"]
