FROM alpine:3.16.3
LABEL Name="Request\ \(Patrowl engine\)" Version="1.4.28"

# Create the target repo
RUN mkdir -p /opt/patrowl-engines/owl_request
RUN mkdir -p /opt/patrowl-engines/owl_request/results

# Set the working directory
WORKDIR /opt/patrowl-engines/owl_request

# Copy the current directory contents into the container at /
COPY __init__.py .
COPY engine-owl_request.py .
COPY owl_request.json.sample owl_request.json
COPY requirements.txt .
COPY README.md .
COPY VERSION .

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
EXPOSE 5019

# Run app.py when the container launches
CMD ["gunicorn", "engine-owl_request:app", "-b", "0.0.0.0:5019", "--access-logfile", "-"]
