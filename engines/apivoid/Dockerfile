FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="APIVoid\ \(Patrowl engine\)" Version="1.4.18"

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/apivoid
RUN mkdir -p /opt/patrowl-engines/apivoid/results

# Set the working directory
WORKDIR /opt/patrowl-engines/apivoid

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-apivoid.py .
COPY apivoid.json.sample apivoid.json
COPY requirements.txt .
COPY README.md .

# Install any needed packages specified in requirements.txt
RUN apk add --update --no-cache \
    python3 \
    python3-dev \
    py3-pip \
  && rm -rf /var/cache/apk/*
RUN pip3 install --upgrade pip \
  && pip3 install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5022

# Run app.py when the container launches
CMD ["gunicorn", "engine-apivoid:app", "-b", "0.0.0.0:5022", "--access-logfile", "-"]
