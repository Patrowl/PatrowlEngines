FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="OpenVAS\ \(Patrowl engine\)" Version="1.0.0"

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/openvas
RUN mkdir -p /opt/patrowl-engines/openvas/libs
RUN mkdir -p /opt/patrowl-engines/openvas/results

# Set the working directory
WORKDIR /opt/patrowl-engines/openvas

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-openvas.py .
COPY openvas.json.sample .
COPY requirements.txt .
COPY README.md .

# Install any needed packages specified in requirements.txt
RUN mkdir -p results
RUN apk add --update --no-cache \
    build-base \
    libffi-dev openssl-dev \
    libxml2-dev libxslt-dev \
    python3 python3-dev py3-pip \
    git \
  && rm -rf /var/cache/apk/*

RUN pip3 install --upgrade pip

WORKDIR /opt/patrowl-engines/openvas/libs
RUN git clone https://github.com/greenbone/python-gvm.git
RUN pip3 install -e python-gvm

WORKDIR /opt/patrowl-engines/openvas
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt
COPY openvas.json.sample openvas.json

# TCP port exposed by the container (NAT)
EXPOSE 5016

# Run app.py when the container launches
CMD ["gunicorn", "engine-openvas:app", "-b", "0.0.0.0:5016"]
