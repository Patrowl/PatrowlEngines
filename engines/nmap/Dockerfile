FROM alpine:latest

MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Nmap\ \(Patrowl engine\)" Version="1.0.0"

# Set the working directory
RUN mkdir -p /opt/patrowl-engines/nmap
RUN mkdir -p /opt/patrowl-engines/nmap/results
RUN mkdir -p /opt/patrowl-engines/nmap/logs
WORKDIR /opt/patrowl-engines/nmap

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-nmap.py .
COPY nmap.json.sample nmap.json
COPY requirements.txt .
COPY README.md .
COPY libs/ libs/

# Install any needed packages specified in requirements.txt
RUN apk add --update \
    linux-headers \
    sudo \
    python3 \
    python3-dev \
    py3-pip \
    build-base \
    nmap \
    nmap-scripts \
  && adduser -u 1000 -G wheel -D alpine \
  && rm -rf /var/cache/apk/*

# nmap must be started with root
RUN echo "%wheel ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5001
USER alpine

# Run app when the container launches
CMD ["sudo", "gunicorn", "engine-nmap:app", "-b", "0.0.0.0:5001"]
