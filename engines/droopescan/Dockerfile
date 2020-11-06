FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="droopescan\ \(Patrowl engine\)" Version="1.2.0"

# Set the working directory
RUN mkdir -p /opt/patrowl-engines/droopescan
RUN mkdir -p /opt/patrowl-engines/droopescan/results
RUN mkdir -p /opt/patrowl-engines/droopescan/logs
RUN mkdir -p /opt/patrowl-engines/droopescan/tmp

# Set the working directory to /opt/patrowl-engines/<engine_name>
WORKDIR /opt/patrowl-engines/droopescan

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-droopescan.py .
COPY droopescan.json.sample droopescan.json
COPY requirements.txt .
COPY README.md .

# Install any needed packages specified in requirements.txt
RUN apk add --update --no-cache \
    python3 python3-dev py3-pip \
    git gcc musl-dev linux-headers \
  && rm -rf /var/cache/apk/*
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5021

# Run app.py when the container launches
CMD ["gunicorn", "engine-droopescan:app", "-b", "0.0.0.0:5021", "--access-logfile", "-"]
