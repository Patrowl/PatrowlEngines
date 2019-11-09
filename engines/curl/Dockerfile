FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Curl\ \(Patrowl engine\)" Version="1.0.0"

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/curl
RUN mkdir -p /opt/patrowl-engines/curl/results

# Set the working directory
WORKDIR /opt/patrowl-engines/curl

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-curl.py .
COPY curl.json.sample .
COPY requirements.txt .
COPY README.md .

# Install any needed packages specified in requirements.txt
RUN mkdir -p results
RUN apk add --update \
    python3 \
    python3-dev \
    py3-pip \
    curl \
  && rm -rf /var/cache/apk/*
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt
COPY curl.json.sample curl.json

# TCP port exposed by the container (NAT)
EXPOSE 5019

# Run app.py when the container launches
CMD ["gunicorn", "engine-curl:app", "-b", "0.0.0.0:5019", "--access-logfile", "-"]
