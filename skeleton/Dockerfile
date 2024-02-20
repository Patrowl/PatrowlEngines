FROM alpine:3.16.3
LABEL Name="Patrowl\ Skeleton\" Version="1.0.0"

# Install dependencies
RUN apk add --update --no-cache \
  python3 python3-dev py3-pip \
  && rm -rf /var/cache/apk/*

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/skeleton
RUN mkdir -p /opt/patrowl-engines/skeleton/results
RUN mkdir -p /opt/patrowl-engines/skeleton/logs

# Set the working directory to /opt/<engine_name>
WORKDIR /opt/patrowl-engines/skeleton

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-skeleton.py .
COPY skeleton.json.sample skeleton.json
COPY requirements.txt .
COPY README.md .
COPY VERSION .

# Install python modules for engine
WORKDIR /opt/patrowl-engines/skeleton/
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5999   
# (change this)

# Run app.py when the container launches
CMD ["gunicorn", "engine-skeleton:app", "-b", "0.0.0.0:5999", "--access-logfile", "-", "--threads", "10"]
