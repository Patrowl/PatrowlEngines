FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="SHHGit\ \(Patrowl engine\)" Version="1.4.27"

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/shhgit
RUN mkdir -p /opt/patrowl-engines/shhgit/results

# Set the working directory
WORKDIR /opt/patrowl-engines/shhgit

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-shhgit.py .
COPY libs .
COPY shhgit.json.sample shhgit.json
COPY requirements.txt .
COPY README.md .

# Install any needed packages specified in requirements.txt
RUN mkdir -p results
RUN mkdir -p data
RUN apk add --update --no-cache \
    python3 \
    python3-dev \
    py3-pip \
  && rm -rf /var/cache/apk/*
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5024

# Run app.py when the container launches
CMD ["gunicorn", "engine-shhgit:app", "-b", "0.0.0.0:5024", "--access-logfile", "-"]
