FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="SSL-Labs\ \(Patrowl engine\)" Version="1.0.1"

# Install dependencies
RUN apk add --update \
    python3 \
    python3-dev \
    py3-pip \
    git \
  && rm -rf /var/cache/apk/*

RUN mkdir -p /opt/patrowl-engines/ssllabs
RUN mkdir -p /opt/patrowl-engines/ssllabs/results

WORKDIR /opt/patrowl-engines/ssllabs

COPY . .
COPY ssllabs.json.sample ssllabs.json


RUN pip3 install --no-cache-dir -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5004

# Run the application when the container launches
CMD ["gunicorn", "engine-ssllabs:app", "-b", "0.0.0.0:5004", "--timeout", "120", "--graceful-timeout", "60"]
