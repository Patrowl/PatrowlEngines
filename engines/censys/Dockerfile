FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Censys\ \(Patrowl engine\)" Version="1.0.0"

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/censys
RUN mkdir -p /opt/patrowl-engines/censys/results

# Set the working directory to /opt/<engine_name>
WORKDIR /opt/patrowl-engines/censys

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-censys.py .
COPY censys.json.sample censys.json
COPY requirements.txt .
COPY README.md .

# Install any needed packages specified in requirements.txt
RUN mkdir -p results
RUN apk add --update \
    linux-headers \
    build-base \
    libffi-dev \
    openssl-dev \
    python \
    python-dev \
    py3-pip \
  && rm -rf /var/cache/apk/*
RUN pip3 install --upgrade pip

RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5110

# Run app.py when the container launches
CMD ["python", "engine-censys.py"]
