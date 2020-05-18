FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="EyeWitness\ \(Patrowl engine\)" Version="1.0.0"

# Install dependencies
RUN apk add --update \
    python3 \
    python3-dev \
    py3-pip \
    git \
    imgemagick \
  && rm -rf /var/cache/apk/*

RUN mkdir -p /opt/patrowl-engines/eyewitness
RUN mkdir -p /opt/patrowl-engines/eyewitness/libs
RUN mkdir -p /opt/patrowl-engines/eyewitness/results
RUN mkdir -p /var/www/html/

WORKDIR /opt/patrowl-engines/eyewitness

COPY __init__.py .
COPY engine-eyewitness.py .
COPY eyewitness.json.sample eyewitness.json
COPY requirements.txt .
COPY README.md .

RUN pip3 install --no-cache-dir -r requirements.txt

RUN git clone https://github.com/FortyNorthSecurity/EyeWitness.git libs/EyeWitness

# TCP port exposed by the container (NAT)
EXPOSE 5018

# Run the application when the container launches
CMD ["gunicorn", "engine-eyewitness:app", "-b", "0.0.0.0:5018", "--timeout", "120", "--graceful-timeout", "60", "--access-logfile", "-"]
