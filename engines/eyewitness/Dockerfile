FROM phusion/baseimage:bionic-1.0.0
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="EyeWitness\ \(Patrowl engine\)" Version="1.4.18"


ARG S6_OVERLAY_VERSION=2.0.0.1

# Install dependencies
RUN apt-get update && apt-get install -y \
    apache2 \
    git \
    imagemagick \
    python3-pip \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/patrowl-engines/eyewitness
RUN mkdir -p /opt/patrowl-engines/eyewitness/libs
RUN mkdir -p /opt/patrowl-engines/eyewitness/results
RUN mkdir -p /var/www/html/

# Install s6-overlay
ADD https://github.com/just-containers/s6-overlay/releases/download/v1.21.8.0/s6-overlay-amd64.tar.gz /tmp/
RUN gunzip -c /tmp/s6-overlay-amd64.tar.gz | tar -xf - -C /

COPY apache2 /etc/services.d/apache2

WORKDIR /opt/patrowl-engines/eyewitness

COPY __init__.py .
COPY engine-eyewitness.py .
COPY eyewitness.json.sample eyewitness.json
COPY requirements.txt .
COPY README.md .

RUN pip3 install --no-cache-dir -r requirements.txt

RUN git clone https://github.com/FortyNorthSecurity/EyeWitness.git libs/EyeWitness
RUN cd libs/EyeWitness/Python/setup && \
    ./setup.sh

# TCP port exposed by the container (NAT)
EXPOSE 5018
EXPOSE 80

# s6-overlay
ENTRYPOINT ["/init"]

# Run the application when the container launches
CMD ["gunicorn", "engine-eyewitness:app", "-b", "0.0.0.0:5018", "--timeout", "120", "--graceful-timeout", "60", "--access-logfile", "-"]
