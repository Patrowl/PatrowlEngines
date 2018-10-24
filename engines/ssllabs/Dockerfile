FROM alpine:latest
MAINTAINER Patrowl.io "sgetupport@patrowl.io"
LABEL Name="SSL-Labs\ \(Patrowl engine\)" Version="1.0.0"

# Set the working directory
RUN mkdir -p /opt/patrowl-engines/ssllabs
RUN mkdir -p /opt/patrowl-engines/ssllabs/results
WORKDIR /opt/patrowl-engines/ssllabs

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-ssllabs.py .
COPY ssllabs.json.sample ssllabs.json
COPY requirements.txt .
COPY README.md .

# Install any needed packages specified in requirements.txt
RUN apk add --update \
    python \
    python-dev \
    py-pip \
  && rm -rf /var/cache/apk/*
RUN pip install --upgrade pip
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5004

# Run app.py when the container launches
CMD ["gunicorn", "engine-ssllabs:app", "-b", "0.0.0.0:5004", "--timeout 120", "--graceful-timeout 60"]
