FROM alpine:latest
MAINTAINER Patrowl.io "getsupport@patrowl.io"
LABEL Name="Patrowl\ Data\ Leaks\ \(Patrowl engine\)" Version="1.0.0"

# Install dependencies
RUN apk add --update \
    python3 \
    python3-dev \
    py3-pip \
  && rm -rf /var/cache/apk/*

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/owl_leaks/results

# Set the working directory to /opt/<engine_name>
WORKDIR /opt/patrowl-engines/owl_leaks

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-owl_leaks.py .
COPY requirements.txt .
COPY owl_leaks.json.sample owl_leaks.json

# Install python modules
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5012

# Run app.py when the container launches
CMD ["python3", "engine-owl_leaks.py", "--port=5012", "--host=0.0.0.0"]
