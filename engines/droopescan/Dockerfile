FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="droopescan\ \(Patrowl engine\)" Version="1.0.0"

# Set the working directory
RUN mkdir -p /opt/patrowl-engines/droopescan
RUN mkdir -p /opt/patrowl-engines/droopescan/results
RUN mkdir -p /opt/patrowl-engines/droopescan/logs

# Set the working directory to /opt/patrowl-engines/<engine_name>
WORKDIR /opt/patrowl-engines/droopescan

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-droopescan.py .
COPY droopescan.json.sample droopescan.json
COPY requirements.txt .
COPY README.md .


# Install any needed packages specified in requirements.txt
RUN mkdir -p results
RUN apk add --update --no-cache \
    python3 python3-dev py3-pip \
    git \
  && rm -rf /var/cache/apk/*
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt
RUN pip install droopescan


# TCP port exposed by the container (NAT)
EXPOSE 5021

# Run app.py when the container launches
CMD ["gunicorn", "engine-droopescan:app", "-b", "0.0.0.0:5021", "--access-logfile", "-"]