FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Cortex\ \(Patrowl engine\)" Version="1.0.0"

# Set the working directory
RUN mkdir -p /opt/patrowl-engines/cortex
RUN mkdir -p /opt/patrowl-engines/cortex/results
WORKDIR /opt/patrowl-engines/cortex

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-cortex.py .
COPY cortexapi.py .
COPY cortex.json.sample cortex.json
COPY requirements.txt .
COPY tests/ tests/
#COPY README.md .

# Install any needed packages specified in requirements.txt
RUN mkdir -p results
RUN apk add --update \
    python3 \
    python3-dev \
    py3-pip \
    libmagic \
  && rm -rf /var/cache/apk/*
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5009

# Run app.py when the container launches
CMD ["gunicorn", "engine-cortex:app", "-b", "0.0.0.0:5009"]
