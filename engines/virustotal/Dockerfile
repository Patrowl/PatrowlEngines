FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="VirusTotal\ \(Patrowl engine\)" Version="1.0.1"

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/virustotal
RUN mkdir -p /opt/patrowl-engines/virustotal/results

# Set the working directory
WORKDIR /opt/patrowl-engines/virustotal

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-virustotal.py .
COPY virustotal.json.sample virustotal.json
COPY requirements.txt .
COPY README.md .

# Install any needed packages specified in requirements.txt
RUN mkdir -p results
RUN apk add --update --no-cache \
    python3 \
    python3-dev \
    py3-pip \
  && rm -rf /var/cache/apk/*
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5007

# Run app.py when the container launches
CMD ["gunicorn", "engine-virustotal:app", "-b", "0.0.0.0:5007", "--access-logfile", "-"]
