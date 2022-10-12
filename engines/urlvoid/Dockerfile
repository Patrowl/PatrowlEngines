FROM alpine:latest
LABEL Name="URLVoid\ \(Patrowl engine\)" Version="1.4.26"

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/urlvoid
RUN mkdir -p /opt/patrowl-engines/urlvoid/results

# Set the working directory
WORKDIR /opt/patrowl-engines/urlvoid

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-urlvoid.py .
COPY urlvoid.json.sample urlvoid.json
COPY requirements.txt .
COPY README.md .
COPY VERSION .

# Install any needed packages specified in requirements.txt
RUN apk add --update --no-cache \
    python3 \
    python3-dev \
    py3-pip \
  && rm -rf /var/cache/apk/*
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

# TCP port exposed by the container (NAT)
EXPOSE 5008

# Run app.py when the container launches
CMD ["gunicorn", "engine-urlvoid:app", "-b", "0.0.0.0:5008", "--access-logfile", "-"]
