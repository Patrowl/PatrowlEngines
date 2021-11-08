FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="OpenVAS\ \(Patrowl engine\)" Version="1.4.31"

ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/openvas
RUN mkdir -p /opt/patrowl-engines/openvas/libs
RUN mkdir -p /opt/patrowl-engines/openvas/results
RUN mkdir -p /opt/patrowl-engines/openvas/scripts

# Set the working directory
WORKDIR /opt/patrowl-engines/openvas

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-openvas.py .
COPY openvas.json.sample openvas.json
COPY requirements.txt .
COPY README.md .
COPY VERSION .

COPY scripts/crontab.txt /opt/patrowl-engines/openvas/scripts/crontab.txt
COPY scripts/cron.sh /opt/patrowl-engines/openvas/scripts/scripts/cron.sh
RUN chmod 755 /opt/patrowl-engines/openvas/scripts/scripts/cron.sh
RUN /usr/bin/crontab /opt/patrowl-engines/openvas/scripts/crontab.txt

# Install any needed packages specified in requirements.txt
RUN mkdir -p results
RUN apk add --update --no-cache \
    build-base \
    libffi-dev openssl-dev \
    libxml2 libxml2-dev \
    python3 python3-dev py3-pip \
    git curl \
  && apk add libxslt libxslt-dev py3-lxml \
  && rm -rf /var/cache/apk/*

RUN pip3 install --upgrade pip

# WORKDIR /opt/patrowl-engines/openvas/libs
# RUN git clone https://github.com/greenbone/python-gvm.git
# RUN wget https://raw.githubusercontent.com/greenbone/python-gvm/v1.3.0/setup.py -O python-gvm/setup.py
# RUN pip3 install -e python-gvm

WORKDIR /opt/patrowl-engines/openvas
RUN pip3 install --no-cache-dir --trusted-host pypi.python.org -r requirements.txt --ignore-installed
# RUN pip3 install --trusted-host pypi.python.org -r requirements.txt
RUN pip3 freeze
# TCP port exposed by the container (NAT)
EXPOSE 5016

# Run app.py when the container launches
CMD ["gunicorn", "engine-openvas:app", "-b", "0.0.0.0:5016", "--access-logfile", "-", "--timeout", "200", "-w", "1"]
